"""Integration tests for fenced extraction-to-decision workflow execution."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from itertools import count
from types import SimpleNamespace

import pytest

from malware_robustness.domain.analysis import (
    EMBER_V2_FEATURE_COUNT,
    ExtractionCompleteness,
    ExtractionEnvelope,
)
from malware_robustness.domain.extraction import (
    ExtractionFailureCode,
    ExtractionOutcome,
)
from malware_robustness.domain.scan_jobs import ScanTask, ScanTaskRejectedError
from malware_robustness.domain.workflows import ContentHashedResultReference, WorkflowState
from malware_robustness.repositories.results import ResultStorageError
from malware_robustness.repositories.workflows import InMemoryWorkflowRepository
from malware_robustness.services.analysis_runtime import (
    AnalysisRetryableError,
    AnalysisTaskRuntime,
)
from malware_robustness.services.workflows import WorkflowService

NOW = datetime(2026, 8, 31, 19, 0, tzinfo=UTC)
RELEASE = "sha256:" + "1" * 64
EXTRACTOR = "sha256:" + "2" * 64
WORKER = "sha256:" + "3" * 64
SCHEMA_DIGEST = "sha256:" + "4" * 64
RESULT = ContentHashedResultReference("results/objects/result.json", "5" * 64)


class SequenceExtractor:
    def __init__(self, outcomes: list[ExtractionOutcome]) -> None:
        self.outcomes = outcomes
        self.tasks: list[ScanTask] = []

    def __call__(self, task: ScanTask) -> ExtractionOutcome:
        self.tasks.append(task)
        return self.outcomes.pop(0)


class FakeDecisionRuntime:
    def __init__(self, failures: int = 0) -> None:
        self.failures = failures
        self.envelopes: list[ExtractionEnvelope] = []

    def process(self, *, scan_id: str, extraction_envelope: ExtractionEnvelope):
        del scan_id
        self.envelopes.append(extraction_envelope)
        if self.failures:
            self.failures -= 1
            raise ResultStorageError("storage unavailable")
        return SimpleNamespace(reference=RESULT)


def _system():
    identifiers = count(1)
    repository = InMemoryWorkflowRepository()
    workflows = WorkflowService(
        repository,
        clock=lambda: NOW,
        id_factory=lambda: f"{next(identifiers):032x}",
    )
    created = workflows.create(
        tenant_id="tenant-a",
        idempotency_key="request-a",
        analysis_release_id=RELEASE,
        policy_snapshot_id="policy-a",
        sample_sha256="a" * 64,
        object_key="b" * 32,
        object_generation="c" * 32,
    ).workflow
    workflows.transition("tenant-a", created.scan_id, WorkflowState.VALIDATING)
    queued = workflows.transition("tenant-a", created.scan_id, WorkflowState.QUEUED)
    task = ScanTask(
        scan_id=queued.scan_id,
        tenant_id=queued.tenant_id,
        object_key=queued.object_key,
        object_generation=queued.object_generation,
        sample_sha256=queued.sample_sha256,
        analysis_release_id=queued.analysis_release_id,
        attempt=0,
        job_nonce="runtime_nonce_123",
    )
    return workflows, repository, task


def _envelope(task: ScanTask) -> ExtractionEnvelope:
    return ExtractionEnvelope(
        sample_digest=task.sample_sha256,
        job_nonce=task.job_nonce,
        extractor_image_digest=EXTRACTOR,
        worker_image_digest=WORKER,
        feature_schema_id="ember-v2",
        feature_schema_digest=SCHEMA_DIGEST,
        analysis_release_id=task.analysis_release_id,
        extraction_completeness=ExtractionCompleteness.COMPLETE,
        warnings=(),
        evidence=(),
        features=(0.0,) * EMBER_V2_FEATURE_COUNT,
    )


def test_runtime_advances_every_stage_and_completes_with_immutable_reference() -> None:
    workflows, repository, task = _system()
    extractor = SequenceExtractor([ExtractionOutcome.complete(_envelope(task))])
    decision = FakeDecisionRuntime()

    report = AnalysisTaskRuntime(
        workflows,
        extractor,
        decision,
        owner="analysis-1",
    )(task)

    assert report.state is WorkflowState.COMPLETE
    assert report.result_reference == RESULT
    stored = workflows.get(task.tenant_id, task.scan_id)
    assert stored.result_reference == RESULT
    assert stored.lease_owner is None
    states = [event.to_state for event in repository.history(task.tenant_id, task.scan_id)]
    assert states[-6:] == [
        WorkflowState.EXTRACTING,
        WorkflowState.VALIDATING_FEATURES,
        WorkflowState.SCORING,
        WorkflowState.APPLYING_POLICY,
        WorkflowState.PUBLISHING,
        WorkflowState.COMPLETE,
    ]


def test_retryable_extraction_releases_fence_then_replays_idempotently() -> None:
    workflows, _, task = _system()
    extractor = SequenceExtractor(
        [
            ExtractionOutcome.inconclusive(
                ExtractionFailureCode.SEALED_OBJECT_UNAVAILABLE,
                retryable=True,
            ),
            ExtractionOutcome.complete(_envelope(task)),
        ]
    )
    runtime = AnalysisTaskRuntime(
        workflows,
        extractor,
        FakeDecisionRuntime(),
        owner="analysis-1",
        lease_duration=timedelta(minutes=1),
    )

    with pytest.raises(AnalysisRetryableError, match="sealed_object_unavailable"):
        runtime(task)
    released = workflows.get(task.tenant_id, task.scan_id)
    assert released.state is WorkflowState.EXTRACTING
    assert released.lease_owner is None

    assert runtime(task).state is WorkflowState.COMPLETE
    assert workflows.get(task.tenant_id, task.scan_id).attempt_count == 2


def test_nonretryable_extraction_is_terminal_and_does_not_invoke_decision() -> None:
    workflows, _, task = _system()
    decision = FakeDecisionRuntime()
    runtime = AnalysisTaskRuntime(
        workflows,
        SequenceExtractor(
            [ExtractionOutcome.inconclusive(ExtractionFailureCode.SEALED_DIGEST_MISMATCH)]
        ),
        decision,
        owner="analysis-1",
    )

    report = runtime(task)

    assert report.state is WorkflowState.INCONCLUSIVE
    assert report.failure_reason == "extraction:sealed_digest_mismatch"
    assert decision.envelopes == []


def test_mismatched_task_identity_is_rejected_before_a_lease_is_acquired() -> None:
    workflows, _, task = _system()
    poisoned = ScanTask(
        scan_id=task.scan_id,
        tenant_id=task.tenant_id,
        object_key=task.object_key,
        object_generation=task.object_generation,
        sample_sha256="f" * 64,
        analysis_release_id=task.analysis_release_id,
        attempt=task.attempt,
        job_nonce=task.job_nonce,
    )

    with pytest.raises(ScanTaskRejectedError, match="identity"):
        AnalysisTaskRuntime(
            workflows,
            SequenceExtractor([]),
            FakeDecisionRuntime(),
            owner="analysis-1",
        )(poisoned)

    stored = workflows.get(task.tenant_id, task.scan_id)
    assert stored.state is WorkflowState.QUEUED
    assert stored.attempt_count == 0


def test_result_storage_outage_releases_lease_and_retry_completes() -> None:
    workflows, _, task = _system()
    extractor = SequenceExtractor(
        [
            ExtractionOutcome.complete(_envelope(task)),
            ExtractionOutcome.complete(_envelope(task)),
        ]
    )
    decision = FakeDecisionRuntime(failures=1)
    runtime = AnalysisTaskRuntime(
        workflows,
        extractor,
        decision,
        owner="analysis-1",
    )

    with pytest.raises(AnalysisRetryableError, match="storage"):
        runtime(task)
    assert workflows.get(task.tenant_id, task.scan_id).lease_owner is None

    assert runtime(task).state is WorkflowState.COMPLETE
    assert len(decision.envelopes) == 2


def test_duplicate_delivery_after_completion_is_a_noop() -> None:
    workflows, _, task = _system()
    extractor = SequenceExtractor([ExtractionOutcome.complete(_envelope(task))])
    decision = FakeDecisionRuntime()
    runtime = AnalysisTaskRuntime(
        workflows,
        extractor,
        decision,
        owner="analysis-1",
    )

    first = runtime(task)
    duplicate = runtime(task)

    assert duplicate == first
    assert len(extractor.tasks) == 1
    assert len(decision.envelopes) == 1
