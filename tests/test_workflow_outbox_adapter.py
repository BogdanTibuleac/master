"""Integration tests joining workflow persistence to the outbox dispatcher."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import count

from malware_robustness.domain.outbox_delivery import SCAN_QUEUED_OUTBOX_TOPIC
from malware_robustness.domain.scan_jobs import ScanTask
from malware_robustness.domain.workflows import OutboxMessage, WorkflowState
from malware_robustness.repositories.outbox_delivery import WorkflowOutboxDeliveryStore
from malware_robustness.repositories.workflows import InMemoryWorkflowRepository
from malware_robustness.services.outbox import OutboxDispatcher
from malware_robustness.services.workflows import WorkflowService

TENANT = "tenant-runtime"
NOW = datetime(2026, 8, 31, 18, 0, tzinfo=UTC)


@dataclass
class MutableClock:
    value: datetime = NOW

    def __call__(self) -> datetime:
        return self.value


class RecordingPublisher:
    def __init__(self, failures: int = 0) -> None:
        self.failures = failures
        self.tasks: list[ScanTask] = []

    def publish(self, task: ScanTask) -> None:
        self.tasks.append(task)
        if self.failures:
            self.failures -= 1
            raise RuntimeError("broker unavailable")


def _queued_repository(clock: MutableClock):
    identifiers = count(1)
    repository = InMemoryWorkflowRepository()
    service = WorkflowService(
        repository,
        clock=clock,
        id_factory=lambda: f"{next(identifiers):032x}",
    )
    workflow = service.create(
        tenant_id=TENANT,
        idempotency_key="request-1",
        analysis_release_id="release-immutable-1",
        policy_snapshot_id="policy-1",
        sample_sha256="a" * 64,
        object_key="b" * 32,
        object_generation="c" * 32,
    ).workflow
    service.transition(TENANT, workflow.scan_id, WorkflowState.VALIDATING)
    queued = service.transition(
        TENANT,
        workflow.scan_id,
        WorkflowState.QUEUED,
        outbox=OutboxMessage(
            SCAN_QUEUED_OUTBOX_TOPIC,
            {
                "object_key": "b" * 32,
                "object_generation": "c" * 32,
                "sample_sha256": "a" * 64,
                "analysis_release_id": "release-immutable-1",
            },
        ),
    )
    return repository, queued


def test_workflow_outbox_dispatches_exact_metadata_and_marks_publication() -> None:
    clock = MutableClock()
    repository, queued = _queued_repository(clock)
    publisher = RecordingPublisher()
    store = WorkflowOutboxDeliveryStore(repository, clock=clock)

    report = OutboxDispatcher(
        store,
        publisher,
        owner="dispatcher-1",
        clock=clock,
    ).dispatch_once()

    assert report.published == 1
    assert repository.pending_outbox() == []
    assert publisher.tasks == [
        ScanTask(
            scan_id=queued.scan_id,
            tenant_id=TENANT,
            object_key="b" * 32,
            object_generation="c" * 32,
            sample_sha256="a" * 64,
            analysis_release_id="release-immutable-1",
            attempt=0,
            job_nonce=repository._outbox[0].intent_id,
        )
    ]


def test_first_failed_publication_is_retried_without_off_by_one_exhaustion() -> None:
    clock = MutableClock()
    repository, _ = _queued_repository(clock)
    publisher = RecordingPublisher(failures=1)
    store = WorkflowOutboxDeliveryStore(repository, max_attempts=2, clock=clock)
    dispatcher = OutboxDispatcher(
        store,
        publisher,
        owner="dispatcher-1",
        max_attempts=2,
        retry_backoff=lambda _: timedelta(seconds=1),
        clock=clock,
    )

    first = dispatcher.dispatch_once()
    clock.value += timedelta(seconds=1)
    second = dispatcher.dispatch_once()

    assert first.retry_scheduled == 1
    assert second.published == 1
    assert publisher.tasks[0] == publisher.tasks[1]
    assert repository.pending_outbox() == []
