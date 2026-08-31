"""Focused tests for immutable result storage and the trusted runtime."""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from malware_robustness.domain.analysis import (
    EMBER_V2_FEATURE_COUNT,
    AnalysisRelease,
    PolicyThresholds,
)
from malware_robustness.repositories.results import (
    AzureBlobResultRepository,
    LocalResultRepository,
    ResultConflictError,
    ResultIntegrityError,
    ResultTooLargeError,
)
from malware_robustness.services.decision import DecisionService
from malware_robustness.services.decision_runtime import DecisionRuntime

_SAMPLE_DIGEST = "sha256:" + "a" * 64
_EXTRACTOR_DIGEST = "sha256:" + "b" * 64
_WORKER_DIGEST = "sha256:" + "c" * 64
_SCHEMA_DIGEST = "sha256:" + "d" * 64
_RELEASE_DIGEST = "sha256:" + "e" * 64


class FixedModel:
    model_id = "ember-v2-lightgbm/17"

    def predict_margin(self, features: tuple[float, ...]) -> float:
        assert len(features) == EMBER_V2_FEATURE_COUNT
        return 0.7


class FixedCalibrator:
    calibrator_id = "platt/9"

    def calibrate(self, raw_margin: float) -> float:
        assert raw_margin == 0.7
        return 0.82


def _decision_service() -> DecisionService:
    release = AnalysisRelease(
        analysis_release_id=_RELEASE_DIGEST,
        extractor_image_digest=_EXTRACTOR_DIGEST,
        worker_image_digest=_WORKER_DIGEST,
        feature_schema_id="ember-v2/2381",
        feature_schema_digest=_SCHEMA_DIGEST,
        model_id=FixedModel.model_id,
        calibrator_id=FixedCalibrator.calibrator_id,
    )
    thresholds = PolicyThresholds(
        policy_id="static-pe-policy/17",
        t_b=0.2,
        t_m=0.6,
        t_h=0.9,
    )
    return DecisionService(FixedModel(), FixedCalibrator(), release, thresholds)


def _envelope(*, job_nonce: str = "job_nonce_0123456789") -> dict[str, object]:
    return {
        "sample_digest": _SAMPLE_DIGEST,
        "job_nonce": job_nonce,
        "extractor_image_digest": _EXTRACTOR_DIGEST,
        "worker_image_digest": _WORKER_DIGEST,
        "feature_schema_id": "ember-v2/2381",
        "feature_schema_digest": _SCHEMA_DIGEST,
        "analysis_release_id": _RELEASE_DIGEST,
        "extraction_completeness": "complete",
        "warnings": [],
        "evidence": [],
        "features": [0.0] * EMBER_V2_FEATURE_COUNT,
    }


def _runtime(repository) -> DecisionRuntime:
    return DecisionRuntime(_decision_service(), repository)


def test_runtime_persists_only_a_canonical_public_manifest(tmp_path: Path) -> None:
    repository = LocalResultRepository(tmp_path)

    result = _runtime(repository).process(
        scan_id="scan-001",
        extraction_envelope=_envelope(),
    )

    object_path = tmp_path.joinpath(*result.reference.object_key.split("/"))
    stored_bytes = object_path.read_bytes()
    stored = repository.read(result.reference)
    assert hashlib.sha256(stored_bytes).hexdigest() == result.reference.sha256
    assert result.reference.object_key.endswith(f"/{result.reference.sha256}.json")
    assert stored == result.public_manifest.model_dump(mode="json")
    assert stored["release"]["analysis_release_id"] == _RELEASE_DIGEST
    assert stored["release"]["model_id"] == FixedModel.model_id
    assert stored["release"]["calibrator_id"] == FixedCalibrator.calibrator_id
    assert stored["limitations"]
    assert stored["executed"] is False
    assert b'"features"' not in stored_bytes
    assert b"MZ" not in stored_bytes


def test_invalid_untrusted_envelope_is_persisted_as_inconclusive_without_features(
    tmp_path: Path,
) -> None:
    repository = LocalResultRepository(tmp_path)
    envelope = _envelope()
    envelope["features"] = [0.0]

    result = _runtime(repository).process(
        scan_id="scan-invalid",
        extraction_envelope=envelope,
    )

    stored = repository.read(result.reference)
    assert stored["analysis_status"] == "inconclusive"
    assert stored["decision"]["reason_codes"] == ["invalid_feature_count"]
    assert "Untrusted extraction envelope rejected" in stored["limitations"][-1]
    assert "features" not in stored


def test_duplicate_processing_is_idempotent_only_for_identical_bytes(tmp_path: Path) -> None:
    repository = LocalResultRepository(tmp_path)
    runtime = _runtime(repository)

    first = runtime.process(scan_id="scan-idempotent", extraction_envelope=_envelope())
    duplicate = runtime.process(scan_id="scan-idempotent", extraction_envelope=_envelope())

    assert duplicate.reference == first.reference
    assert duplicate.public_manifest == first.public_manifest
    with pytest.raises(ResultConflictError):
        runtime.process(
            scan_id="scan-idempotent",
            extraction_envelope=_envelope(job_nonce="different_nonce_123456"),
        )
    assert repository.read(first.reference) == first.public_manifest.model_dump(mode="json")


def test_local_repository_detects_manifest_tampering_and_refuses_reuse(tmp_path: Path) -> None:
    repository = LocalResultRepository(tmp_path)
    runtime = _runtime(repository)
    result = runtime.process(scan_id="scan-tamper", extraction_envelope=_envelope())
    object_path = tmp_path.joinpath(*result.reference.object_key.split("/"))
    original = object_path.read_bytes()
    object_path.write_bytes(original[:-1] + b" ")

    with pytest.raises(ResultIntegrityError):
        repository.read(result.reference)
    with pytest.raises(ResultIntegrityError):
        runtime.process(scan_id="scan-tamper", extraction_envelope=_envelope())


def test_repository_rejects_a_manifest_changed_after_its_digest_was_created(
    tmp_path: Path,
) -> None:
    repository = LocalResultRepository(tmp_path)
    manifest = _decision_service().decide(_envelope()).to_dict()
    manifest["limitations"].append("Injected after signing.")

    with pytest.raises(ResultIntegrityError):
        repository.persist(
            scan_id="scan-invalid-manifest",
            analysis_release_id=_RELEASE_DIGEST,
            manifest=manifest,
        )


def test_conflicting_overwrite_race_has_one_winner_and_never_replaces_it(
    tmp_path: Path,
) -> None:
    repository = LocalResultRepository(tmp_path)
    barrier = Barrier(2)

    def publish(job_nonce: str):
        barrier.wait(timeout=5)
        return _runtime(repository).process(
            scan_id="scan-race",
            extraction_envelope=_envelope(job_nonce=job_nonce),
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(publish, "race_nonce_first_123"),
            pool.submit(publish, "race_nonce_second_456"),
        ]
    successes = []
    conflicts = []
    for future in futures:
        try:
            successes.append(future.result())
        except ResultConflictError as error:
            conflicts.append(error)

    assert len(successes) == 1
    assert len(conflicts) == 1
    winner = successes[0]
    assert repository.read(winner.reference) == winner.public_manifest.model_dump(mode="json")


def test_identical_concurrent_writers_share_one_immutable_reference(tmp_path: Path) -> None:
    repository = LocalResultRepository(tmp_path)
    barrier = Barrier(4)

    def publish():
        barrier.wait(timeout=5)
        return (
            _runtime(repository)
            .process(
                scan_id="scan-same-race",
                extraction_envelope=_envelope(),
            )
            .reference
        )

    with ThreadPoolExecutor(max_workers=4) as pool:
        references = list(pool.map(lambda _: publish(), range(4)))

    assert references == [references[0]] * 4
    repository.read(references[0])


def test_oversized_canonical_manifest_is_rejected_before_publication(tmp_path: Path) -> None:
    repository = LocalResultRepository(tmp_path, maximum_manifest_bytes=128)

    with pytest.raises(ResultTooLargeError):
        _runtime(repository).process(
            scan_id="scan-oversized",
            extraction_envelope=_envelope(),
        )

    assert not list(tmp_path.rglob("*.json"))


class FakeAzureError(RuntimeError):
    def __init__(self, status_code: int, error_code: str) -> None:
        super().__init__(error_code)
        self.status_code = status_code
        self.error_code = error_code


class FakeDownloader:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def readall(self) -> bytes:
        return self._data


class FakeBlobClient:
    def __init__(self, container: FakeContainerClient, key: str) -> None:
        self._container = container
        self._key = key

    def upload_blob(self, data: bytes, **kwargs) -> None:
        self._container.upload_calls.append((self._key, dict(kwargs)))
        if self._key in self._container.blobs:
            raise FakeAzureError(409, "BlobAlreadyExists")
        self._container.blobs[self._key] = bytes(data)

    def download_blob(self, *, offset: int, length: int) -> FakeDownloader:
        if self._key not in self._container.blobs:
            raise FakeAzureError(404, "BlobNotFound")
        return FakeDownloader(self._container.blobs[self._key][offset : offset + length])


class FakeContainerClient:
    def __init__(self) -> None:
        self.blobs: dict[str, bytes] = {}
        self.upload_calls: list[tuple[str, dict[str, object]]] = []

    def get_blob_client(self, blob: str) -> FakeBlobClient:
        return FakeBlobClient(self, blob)


def test_azure_adapter_uses_create_only_uploads_and_idempotent_claims() -> None:
    client = FakeContainerClient()
    repository = AzureBlobResultRepository(client)
    runtime = _runtime(repository)

    first = runtime.process(scan_id="scan-azure", extraction_envelope=_envelope())
    duplicate = runtime.process(scan_id="scan-azure", extraction_envelope=_envelope())

    assert duplicate.reference == first.reference
    assert len(client.upload_calls) == 2  # one manifest object and one identity claim
    for _, options in client.upload_calls:
        assert options["overwrite"] is False
        assert options["if_none_match"] == "*"
        assert options["length"] > 0
        assert options["metadata"]["immutable"] == "true"
    assert repository.read(first.reference) == first.public_manifest.model_dump(mode="json")

    uploads_before_conflict = len(client.upload_calls)
    with pytest.raises(ResultConflictError):
        runtime.process(
            scan_id="scan-azure",
            extraction_envelope=_envelope(job_nonce="azure_conflict_nonce_123"),
        )
    assert len(client.upload_calls) == uploads_before_conflict
    assert repository.read(first.reference) == first.public_manifest.model_dump(mode="json")
