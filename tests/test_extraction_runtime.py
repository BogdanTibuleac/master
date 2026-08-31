"""Fail-closed tests for the disposable hostile-content extraction boundary."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from malware_robustness.domain.analysis import EMBER_V2_FEATURE_COUNT
from malware_robustness.domain.extraction import (
    EXTRACTION_PROTOCOL_VERSION,
    ExtractionContractError,
    ExtractionFailureCode,
    ExtractionOutcomeStatus,
    ExtractionRuntimeIdentity,
    ExtractorRunnerRequest,
    ExtractorRunnerResult,
    RunnerFailureCode,
    RunnerProtocolError,
    RunnerSchemaError,
    SealedObjectRead,
)
from malware_robustness.domain.scan_jobs import ScanTask
from malware_robustness.services.extraction_runtime import (
    ContainerExtractorRunner,
    ExtractionTaskHandler,
    decode_runner_request,
    decode_runner_result,
    encode_runner_request,
    encode_runner_result,
)

_RELEASE_DIGEST = "sha256:" + "a" * 64
_EXTRACTOR_DIGEST = "sha256:" + "b" * 64
_WORKER_DIGEST = "sha256:" + "c" * 64
_SCHEMA_DIGEST = "sha256:" + "d" * 64
_OBJECT_KEY = "e" * 32
_GENERATION = "f" * 32
_NONCE = "nonce_1234567890abcdef"


class FakeSealedReader:
    def __init__(self, sealed: SealedObjectRead) -> None:
        self.sealed = sealed
        self.calls: list[tuple[str, str]] = []

    def read_exact(self, object_key: str, object_generation: str) -> SealedObjectRead:
        self.calls.append((object_key, object_generation))
        return self.sealed


class FailingSealedReader:
    def read_exact(self, object_key: str, object_generation: str) -> SealedObjectRead:
        raise OSError("storage detail must not escape the boundary")


class FakeRunner:
    def __init__(self, result: object) -> None:
        self.result = result
        self.requests: list[ExtractorRunnerRequest] = []

    def run(self, request: ExtractorRunnerRequest) -> ExtractorRunnerResult:
        self.requests.append(request)
        return self.result  # type: ignore[return-value]


def _content() -> bytes:
    return b"MZ" + b"\0" * 126 + b"PE\0\0" + b"bounded hostile sample"


def _task(content: bytes | None = None) -> ScanTask:
    value = _content() if content is None else content
    return ScanTask(
        scan_id="scan-123",
        tenant_id="tenant-123",
        object_key=_OBJECT_KEY,
        object_generation=_GENERATION,
        sample_sha256=hashlib.sha256(value).hexdigest(),
        analysis_release_id=_RELEASE_DIGEST,
        attempt=0,
        job_nonce=_NONCE,
    )


def _identity() -> ExtractionRuntimeIdentity:
    return ExtractionRuntimeIdentity(
        extractor_image_digest=_EXTRACTOR_DIGEST,
        worker_image_digest=_WORKER_DIGEST,
        feature_schema_id="ember-v2/2381",
        feature_schema_digest=_SCHEMA_DIGEST,
    )


def _sealed(
    content: bytes | None = None,
    *,
    sample_sha256: str | None = None,
    generation: str = _GENERATION,
    size_bytes: int | None = None,
) -> SealedObjectRead:
    value = _content() if content is None else content
    return SealedObjectRead(
        object_key=_OBJECT_KEY,
        object_generation=generation,
        sample_sha256=sample_sha256 or hashlib.sha256(value).hexdigest(),
        size_bytes=len(value) if size_bytes is None else size_bytes,
        chunks=(value[:7], memoryview(value[7:91]), bytearray(value[91:])),
    )


def _envelope_payload(request: ExtractorRunnerRequest) -> dict[str, object]:
    return {
        "sample_digest": request.sample_digest,
        "job_nonce": request.job_nonce,
        "extractor_image_digest": request.extractor_image_digest,
        "worker_image_digest": request.worker_image_digest,
        "feature_schema_id": request.feature_schema_id,
        "feature_schema_digest": request.feature_schema_digest,
        "analysis_release_id": request.analysis_release_id,
        "extraction_completeness": "complete",
        "warnings": [],
        "evidence": [
            {
                "indicator_id": "pe.static.test",
                "family": "sections",
                "severity": "medium",
                "summary": "A bounded deterministic observation.",
            }
        ],
        "features": [0.0] * EMBER_V2_FEATURE_COUNT,
    }


class SuccessfulFakeRunner:
    def __init__(self) -> None:
        self.requests: list[ExtractorRunnerRequest] = []

    def run(self, request: ExtractorRunnerRequest) -> ExtractorRunnerResult:
        self.requests.append(request)
        return ExtractorRunnerResult.complete(_envelope_payload(request))


def test_handler_reads_exact_generation_verifies_bytes_and_emits_envelope() -> None:
    content = _content()
    reader = FakeSealedReader(_sealed(content))
    runner = SuccessfulFakeRunner()
    handler = ExtractionTaskHandler(reader, runner, _identity())

    outcome = handler(_task(content))

    assert outcome.status is ExtractionOutcomeStatus.COMPLETE
    assert outcome.envelope is not None
    assert outcome.envelope.sample_digest == "sha256:" + hashlib.sha256(content).hexdigest()
    assert outcome.envelope.job_nonce == _NONCE
    assert outcome.envelope.analysis_release_id == _RELEASE_DIGEST
    assert len(outcome.envelope.features) == EMBER_V2_FEATURE_COUNT
    assert reader.calls == [(_OBJECT_KEY, _GENERATION)]
    assert len(runner.requests) == 1
    assert runner.requests[0].content == content
    assert content not in repr(runner.requests[0]).encode()
    assert "features" not in repr(outcome)


def test_reported_digest_mismatch_prevents_stream_and_runner_invocation() -> None:
    task = _task()

    def should_not_be_read():
        raise AssertionError("mismatched sealed metadata must fail before reading")
        yield b"unreachable"

    reader = FakeSealedReader(
        SealedObjectRead(
            object_key=_OBJECT_KEY,
            object_generation=_GENERATION,
            sample_sha256="0" * 64,
            size_bytes=1,
            chunks=should_not_be_read(),
        )
    )
    runner = FakeRunner(ExtractorRunnerResult.inconclusive(RunnerFailureCode.CRASH))

    outcome = ExtractionTaskHandler(reader, runner, _identity())(task)

    assert outcome.status is ExtractionOutcomeStatus.INCONCLUSIVE
    assert outcome.failure_code is ExtractionFailureCode.SEALED_DIGEST_MISMATCH
    assert outcome.retryable is False
    assert runner.requests == []


def test_rehashed_content_mismatch_prevents_runner_invocation() -> None:
    original = _content()
    task = _task(original)
    tampered = original + b"tampered"
    reader = FakeSealedReader(_sealed(tampered, sample_sha256=task.sample_sha256))
    runner = SuccessfulFakeRunner()

    outcome = ExtractionTaskHandler(reader, runner, _identity())(task)

    assert outcome.failure_code is ExtractionFailureCode.SEALED_DIGEST_MISMATCH
    assert runner.requests == []


def test_generation_mismatch_prevents_runner_invocation() -> None:
    reader = FakeSealedReader(_sealed(generation="1" * 32))
    runner = SuccessfulFakeRunner()

    outcome = ExtractionTaskHandler(reader, runner, _identity())(_task())

    assert outcome.failure_code is ExtractionFailureCode.SEALED_IDENTITY_MISMATCH
    assert runner.requests == []


def test_size_and_maximum_limits_fail_before_runner() -> None:
    content = _content()
    short_reader = FakeSealedReader(_sealed(content, size_bytes=len(content) + 1))
    runner = SuccessfulFakeRunner()

    short = ExtractionTaskHandler(short_reader, runner, _identity())(_task(content))
    oversized = ExtractionTaskHandler(
        FakeSealedReader(_sealed(content)),
        runner,
        _identity(),
        maximum_sample_bytes=len(content) - 1,
    )(_task(content))

    assert short.failure_code is ExtractionFailureCode.SEALED_SIZE_MISMATCH
    assert oversized.failure_code is ExtractionFailureCode.SAMPLE_TOO_LARGE
    assert runner.requests == []


def test_reader_failure_is_typed_without_exposing_storage_exception() -> None:
    runner = SuccessfulFakeRunner()

    outcome = ExtractionTaskHandler(FailingSealedReader(), runner, _identity())(_task())

    assert outcome.failure_code is ExtractionFailureCode.SEALED_OBJECT_UNAVAILABLE
    assert outcome.retryable is True
    assert runner.requests == []
    assert "storage detail" not in repr(outcome)


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (RunnerFailureCode.TIMEOUT, ExtractionFailureCode.RUNNER_TIMEOUT),
        (RunnerFailureCode.OUTPUT_LIMIT, ExtractionFailureCode.RUNNER_OUTPUT_LIMIT),
        (RunnerFailureCode.RESOURCE_LIMIT, ExtractionFailureCode.RUNNER_RESOURCE_LIMIT),
        (RunnerFailureCode.CRASH, ExtractionFailureCode.RUNNER_CRASH),
        (RunnerFailureCode.PROTOCOL, ExtractionFailureCode.RUNNER_PROTOCOL_INVALID),
        (RunnerFailureCode.SCHEMA, ExtractionFailureCode.RUNNER_SCHEMA_INVALID),
        (RunnerFailureCode.EXTRACTOR_REJECTED, ExtractionFailureCode.EXTRACTOR_REJECTED),
    ],
)
def test_runner_failures_are_typed_inconclusive_and_non_retryable(
    failure: RunnerFailureCode, expected: ExtractionFailureCode
) -> None:
    runner = FakeRunner(ExtractorRunnerResult.inconclusive(failure))

    outcome = ExtractionTaskHandler(FakeSealedReader(_sealed()), runner, _identity())(_task())

    assert outcome.status is ExtractionOutcomeStatus.INCONCLUSIVE
    assert outcome.failure_code is expected
    assert outcome.retryable is False


@pytest.mark.parametrize(
    "mutation",
    [
        lambda payload: payload.__setitem__("features", [0.0] * 2380),
        lambda payload: payload.__setitem__("sample_digest", "sha256:" + "0" * 64),
        lambda payload: payload.__setitem__("feature_schema_id", "unknown"),
        lambda payload: payload.__setitem__("unexpected", "field"),
    ],
)
def test_malformed_or_mismatched_runner_output_fails_closed(mutation) -> None:
    request = ExtractorRunnerRequest(
        sample_digest=_task().sample_sha256,
        job_nonce=_NONCE,
        analysis_release_id=_RELEASE_DIGEST,
        extractor_image_digest=_EXTRACTOR_DIGEST,
        worker_image_digest=_WORKER_DIGEST,
        feature_schema_id="ember-v2/2381",
        feature_schema_digest=_SCHEMA_DIGEST,
        content=_content(),
    )
    payload = _envelope_payload(request)
    mutation(payload)
    runner = FakeRunner(ExtractorRunnerResult.complete(payload))

    outcome = ExtractionTaskHandler(FakeSealedReader(_sealed()), runner, _identity())(_task())

    assert outcome.status is ExtractionOutcomeStatus.INCONCLUSIVE
    assert outcome.failure_code is ExtractionFailureCode.RUNNER_SCHEMA_INVALID
    assert outcome.envelope is None
    assert outcome.retryable is False


def test_non_contract_fake_runner_output_fails_closed() -> None:
    runner = FakeRunner({"status": "complete", "features": [0.0] * 2381})

    outcome = ExtractionTaskHandler(FakeSealedReader(_sealed()), runner, _identity())(_task())

    assert outcome.failure_code is ExtractionFailureCode.RUNNER_SCHEMA_INVALID


def test_request_binary_frame_is_bounded_exact_and_path_free() -> None:
    content = _content()
    request = ExtractorRunnerRequest(
        sample_digest=hashlib.sha256(content).hexdigest(),
        job_nonce=_NONCE,
        analysis_release_id=_RELEASE_DIGEST,
        extractor_image_digest=_EXTRACTOR_DIGEST,
        worker_image_digest=_WORKER_DIGEST,
        feature_schema_id="ember-v2/2381",
        feature_schema_digest=_SCHEMA_DIGEST,
        content=content,
    )

    frame = encode_runner_request(request)
    decoded = decode_runner_request(frame)

    assert decoded == request
    assert decoded.metadata()["protocol_version"] == EXTRACTION_PROTOCOL_VERSION
    assert set(decoded.metadata()) == {
        "protocol_version",
        "sample_size_bytes",
        "sample_digest",
        "job_nonce",
        "analysis_release_id",
        "extractor_image_digest",
        "worker_image_digest",
        "feature_schema_id",
        "feature_schema_digest",
    }
    assert not any(
        token in frame
        for token in (b"filename", b"object_key", b"tenant_id", b"file://", b"http://")
    )
    with pytest.raises(RunnerProtocolError, match="trailing"):
        decode_runner_request(frame + b"x")


def test_result_json_frame_rejects_unknown_duplicate_and_non_finite_fields() -> None:
    result = ExtractorRunnerResult.inconclusive(RunnerFailureCode.TIMEOUT)
    assert decode_runner_result(encode_runner_result(result)) == result

    unknown = {
        "protocol_version": EXTRACTION_PROTOCOL_VERSION,
        "status": "inconclusive",
        "envelope": None,
        "failure_code": "runner_timeout",
        "extra": True,
    }
    body = json.dumps(unknown, separators=(",", ":")).encode()
    frame = len(body).to_bytes(4, "big") + body
    with pytest.raises(RunnerSchemaError, match="unknown"):
        decode_runner_result(frame)

    duplicate = (
        b'{"protocol_version":1,"protocol_version":1,"status":"inconclusive",'
        b'"envelope":null,"failure_code":"runner_timeout"}'
    )
    frame = len(duplicate).to_bytes(4, "big") + duplicate
    with pytest.raises(RunnerProtocolError, match="strict"):
        decode_runner_result(frame)


def test_digest_pinned_container_configuration_rejects_latest_and_host_paths() -> None:
    with pytest.raises(ValueError, match="pinned"):
        ContainerExtractorRunner("registry.example/extractor:latest")
    with pytest.raises(ValueError, match="PATH-resolved"):
        ContainerExtractorRunner(
            "registry.example/extractor@" + _EXTRACTOR_DIGEST,
            docker_binary=str(Path("/host/bin/docker")),
        )


def test_contracts_reject_latest_identities_and_raw_byte_iterables() -> None:
    with pytest.raises(ExtractionContractError, match="concrete"):
        replace(_identity(), feature_schema_id="latest")
    with pytest.raises(ExtractionContractError, match="iterable"):
        SealedObjectRead(
            object_key=_OBJECT_KEY,
            object_generation=_GENERATION,
            sample_sha256="0" * 64,
            size_bytes=1,
            chunks=b"x",
        )
