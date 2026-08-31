"""Tests for the durable hostile-content workflow domain boundary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import count
from pathlib import Path

import pytest
from pydantic import ValidationError

from malware_robustness.domain.workflows import (
    AnalysisIdentityConflictError,
    ConcurrentWorkflowUpdateError,
    ContentHashedResultReference,
    IdempotencyConflictError,
    IllegalTransitionError,
    LeaseConflictError,
    OutboxMessage,
    StaleFenceError,
    TerminalWorkflowError,
    WorkflowInvariantError,
    WorkflowState,
)
from malware_robustness.repositories.workflows import InMemoryWorkflowRepository
from malware_robustness.schemas.workflows import (
    WorkflowCompletionRequest,
    WorkflowCreateRequest,
    WorkflowResponse,
    WorkflowTerminationRequest,
)
from malware_robustness.services.workflows import WorkflowService

TENANT = "tenant-a"
SHA256 = "a" * 64
OTHER_SHA256 = "b" * 64
RESULT_SHA256 = "c" * 64


@dataclass
class MutableClock:
    current: datetime

    def __call__(self) -> datetime:
        return self.current

    def advance(self, **kwargs: int) -> None:
        self.current += timedelta(**kwargs)


def sequential_ids():
    values = count(1)
    return lambda: f"{next(values):032x}"


@pytest.fixture
def workflow_system() -> tuple[WorkflowService, InMemoryWorkflowRepository, MutableClock]:
    clock = MutableClock(datetime(2026, 8, 31, 9, 0, tzinfo=UTC))
    repository = InMemoryWorkflowRepository()
    service = WorkflowService(repository, clock=clock, id_factory=sequential_ids())
    return service, repository, clock


def create_awaiting(service: WorkflowService, *, key: str = "request-1"):
    return service.create(
        tenant_id=TENANT,
        idempotency_key=key,
        analysis_release_id="ember-2026-08",
        policy_snapshot_id="policy-17",
        object_key=f"quarantine/{TENANT}/{key}",
    ).workflow


def create_received(service: WorkflowService, *, key: str = "request-1"):
    return service.create(
        tenant_id=TENANT,
        idempotency_key=key,
        analysis_release_id="ember-2026-08",
        policy_snapshot_id="policy-17",
        sample_sha256=SHA256,
        object_key=f"quarantine/{TENANT}/sample",
        object_generation="7",
    ).workflow


def advance_to_queued(service: WorkflowService, scan_id: str):
    service.transition(TENANT, scan_id, WorkflowState.VALIDATING)
    return service.transition(TENANT, scan_id, WorkflowState.QUEUED)


def test_state_model_contains_every_required_active_and_terminal_state() -> None:
    assert {state.value for state in WorkflowState} == {
        "AWAITING_UPLOAD",
        "UPLOAD_RECEIVED",
        "VALIDATING",
        "QUEUED",
        "EXTRACTING",
        "VALIDATING_FEATURES",
        "SCORING",
        "APPLYING_POLICY",
        "PUBLISHING",
        "COMPLETE",
        "REJECTED",
        "INCONCLUSIVE",
        "FAILED",
        "CANCELLED",
        "EXPIRED",
    }


def test_happy_path_preserves_identity_and_completes_with_hashed_result(
    workflow_system,
) -> None:
    service, repository, _ = workflow_system
    created = create_awaiting(service)
    received = service.transition(
        TENANT,
        created.scan_id,
        WorkflowState.UPLOAD_RECEIVED,
        sample_sha256=SHA256,
        object_key=created.object_key,
        object_generation="7",
    )
    assert received.analysis_identity == (TENANT, SHA256, "7", "ember-2026-08")

    service.transition(TENANT, created.scan_id, WorkflowState.VALIDATING)
    queued = service.transition(TENANT, created.scan_id, WorkflowState.QUEUED)
    leased = service.acquire_lease(
        TENANT,
        created.scan_id,
        owner="extractor-1",
        duration=timedelta(minutes=5),
    )
    assert leased.attempt_count == 1
    assert leased.fencing_token == 1

    for target in (
        WorkflowState.EXTRACTING,
        WorkflowState.VALIDATING_FEATURES,
        WorkflowState.SCORING,
        WorkflowState.APPLYING_POLICY,
        WorkflowState.PUBLISHING,
    ):
        queued = service.transition(
            TENANT,
            created.scan_id,
            target,
            fencing_token=leased.fencing_token,
        )
    completed = service.complete(
        TENANT,
        created.scan_id,
        result_object_key="results/tenant-a/result.json",
        result_sha256=RESULT_SHA256,
        fencing_token=leased.fencing_token,
        outbox=OutboxMessage("scan.completed", {"verdict": "needs_review"}),
    )

    assert queued.state == WorkflowState.PUBLISHING
    assert completed.state == WorkflowState.COMPLETE
    assert completed.result_reference == ContentHashedResultReference(
        "results/tenant-a/result.json", RESULT_SHA256
    )
    assert completed.lease_owner is None
    assert completed.terminal_at == completed.updated_at
    assert [event.sequence for event in repository.events(TENANT, created.scan_id)] == list(
        range(completed.version + 1)
    )
    assert repository.pending_outbox()[0].payload["state"] == "COMPLETE"


def test_illegal_transition_cannot_skip_processing_stages(workflow_system) -> None:
    service, _, _ = workflow_system
    workflow = create_received(service)

    with pytest.raises(IllegalTransitionError, match="UPLOAD_RECEIVED.*SCORING"):
        service.transition(TENANT, workflow.scan_id, WorkflowState.SCORING)

    assert service.get(TENANT, workflow.scan_id).version == 0


@pytest.mark.parametrize(
    ("start_state", "terminal_state"),
    [
        (WorkflowState.AWAITING_UPLOAD, WorkflowState.REJECTED),
        (WorkflowState.VALIDATING, WorkflowState.INCONCLUSIVE),
        (WorkflowState.QUEUED, WorkflowState.FAILED),
        (WorkflowState.QUEUED, WorkflowState.CANCELLED),
    ],
)
def test_supported_unsuccessful_terminal_paths(
    workflow_system, start_state: WorkflowState, terminal_state: WorkflowState
) -> None:
    service, _, _ = workflow_system
    if start_state == WorkflowState.AWAITING_UPLOAD:
        workflow = create_awaiting(service)
    else:
        workflow = create_received(service)
        service.transition(TENANT, workflow.scan_id, WorkflowState.VALIDATING)
        if start_state == WorkflowState.QUEUED:
            service.transition(TENANT, workflow.scan_id, WorkflowState.QUEUED)

    terminal = service.terminate(
        TENANT,
        workflow.scan_id,
        terminal_state,
        reason="bounded public reason",
    )

    assert terminal.state == terminal_state
    assert terminal.failure_reason == "bounded public reason"
    assert terminal.result_reference is None


def test_expiry_is_not_allowed_before_configured_time(workflow_system) -> None:
    service, _, clock = workflow_system
    expires_at = clock.current + timedelta(minutes=10)
    workflow = service.create(
        tenant_id=TENANT,
        idempotency_key="expiring",
        analysis_release_id="release",
        policy_snapshot_id="policy",
        expires_at=expires_at,
    ).workflow

    with pytest.raises(IllegalTransitionError, match="before its configured expiry"):
        service.terminate(
            TENANT, workflow.scan_id, WorkflowState.EXPIRED, reason="upload grant expired"
        )

    clock.advance(minutes=10)
    expired = service.terminate(
        TENANT, workflow.scan_id, WorkflowState.EXPIRED, reason="upload grant expired"
    )
    assert expired.state == WorkflowState.EXPIRED


def test_terminal_state_is_idempotently_replayable_but_immutable(workflow_system) -> None:
    service, repository, _ = workflow_system
    workflow = create_awaiting(service)
    rejected = service.terminate(
        TENANT, workflow.scan_id, WorkflowState.REJECTED, reason="policy rejected intake"
    )
    replayed = service.terminate(
        TENANT, workflow.scan_id, WorkflowState.REJECTED, reason="policy rejected intake"
    )

    assert replayed is rejected
    assert len(repository.events(TENANT, workflow.scan_id)) == 2
    with pytest.raises(TerminalWorkflowError, match="immutable"):
        service.terminate(
            TENANT, workflow.scan_id, WorkflowState.REJECTED, reason="different reason"
        )
    with pytest.raises(TerminalWorkflowError, match="terminal"):
        service.transition(TENANT, workflow.scan_id, WorkflowState.FAILED)


def test_unsuccessful_completion_requires_reason_and_success_requires_hash(
    workflow_system,
) -> None:
    service, _, _ = workflow_system
    workflow = create_received(service)
    advance_to_queued(service, workflow.scan_id)

    with pytest.raises(WorkflowInvariantError, match="require a reason"):
        service.transition(TENANT, workflow.scan_id, WorkflowState.FAILED)
    with pytest.raises(WorkflowInvariantError, match="lowercase hexadecimal"):
        ContentHashedResultReference("results/result.json", "not-a-hash")


def test_creation_is_idempotent_per_tenant_and_conflicting_reuse_is_rejected(
    workflow_system,
) -> None:
    service, repository, clock = workflow_system
    first = create_awaiting(service)
    clock.advance(seconds=30)
    replay = create_awaiting(service)

    assert replay is first
    assert len(repository.events(TENANT, first.scan_id)) == 1
    with pytest.raises(IdempotencyConflictError, match="different workflow request"):
        service.create(
            tenant_id=TENANT,
            idempotency_key="request-1",
            analysis_release_id="different-release",
            policy_snapshot_id="policy-17",
            object_key=first.object_key,
        )


def test_analysis_identity_deduplicates_requests_but_remains_tenant_scoped(
    workflow_system,
) -> None:
    service, repository, _ = workflow_system
    first = create_received(service, key="first")
    duplicate = create_received(service, key="second")
    other_tenant = service.create(
        tenant_id="tenant-b",
        idempotency_key="first",
        analysis_release_id="ember-2026-08",
        policy_snapshot_id="policy-17",
        sample_sha256=SHA256,
        object_key="quarantine/tenant-b/sample",
        object_generation="7",
    ).workflow

    assert duplicate is first
    assert other_tenant.scan_id != first.scan_id
    assert repository.get_by_analysis_identity(TENANT, SHA256, "7", "ember-2026-08") is first


def test_sealing_rejects_an_analysis_identity_owned_by_another_workflow(
    workflow_system,
) -> None:
    service, _, _ = workflow_system
    first = create_awaiting(service, key="first")
    second = create_awaiting(service, key="second")
    service.transition(
        TENANT,
        first.scan_id,
        WorkflowState.UPLOAD_RECEIVED,
        sample_sha256=SHA256,
        object_generation="7",
    )

    with pytest.raises(AnalysisIdentityConflictError, match="another workflow"):
        service.transition(
            TENANT,
            second.scan_id,
            WorkflowState.UPLOAD_RECEIVED,
            sample_sha256=SHA256,
            object_generation="7",
        )

    assert service.get(TENANT, second.scan_id).state == WorkflowState.AWAITING_UPLOAD
    assert service.get(TENANT, second.scan_id).version == 0


def test_active_lease_blocks_takeover_and_expired_lease_issues_a_new_fence(
    workflow_system,
) -> None:
    service, _, clock = workflow_system
    workflow = create_received(service)
    advance_to_queued(service, workflow.scan_id)
    first = service.acquire_lease(
        TENANT, workflow.scan_id, owner="worker-1", duration=timedelta(seconds=30)
    )

    with pytest.raises(LeaseConflictError, match="worker-1"):
        service.acquire_lease(
            TENANT, workflow.scan_id, owner="worker-2", duration=timedelta(seconds=30)
        )

    clock.advance(seconds=31)
    second = service.acquire_lease(
        TENANT, workflow.scan_id, owner="worker-2", duration=timedelta(seconds=30)
    )
    assert (second.attempt_count, second.fencing_token) == (2, 2)
    with pytest.raises(StaleFenceError):
        service.transition(
            TENANT, workflow.scan_id, WorkflowState.EXTRACTING, fencing_token=first.fencing_token
        )
    extracted = service.transition(
        TENANT, workflow.scan_id, WorkflowState.EXTRACTING, fencing_token=second.fencing_token
    )
    assert extracted.state == WorkflowState.EXTRACTING


def test_coordinator_can_fail_workflow_after_worker_lease_expires(workflow_system) -> None:
    service, _, clock = workflow_system
    workflow = create_received(service)
    advance_to_queued(service, workflow.scan_id)
    leased = service.acquire_lease(
        TENANT, workflow.scan_id, owner="lost-worker", duration=timedelta(seconds=10)
    )
    clock.advance(seconds=11)

    failed = service.terminate(
        TENANT,
        workflow.scan_id,
        WorkflowState.FAILED,
        reason="worker lease expired",
    )

    assert leased.lease_owner == "lost-worker"
    assert failed.lease_owner is None
    assert failed.state == WorkflowState.FAILED


def test_lease_can_be_renewed_checked_and_released(workflow_system) -> None:
    service, _, clock = workflow_system
    workflow = create_received(service)
    advance_to_queued(service, workflow.scan_id)
    leased = service.acquire_lease(
        TENANT, workflow.scan_id, owner="worker", duration=timedelta(seconds=30)
    )
    clock.advance(seconds=10)
    renewed = service.renew_lease(
        TENANT,
        workflow.scan_id,
        owner="worker",
        fencing_token=leased.fencing_token,
        duration=timedelta(minutes=1),
    )

    assert renewed.attempt_count == 1
    assert (
        service.assert_fence(
            TENANT, workflow.scan_id, owner="worker", fencing_token=leased.fencing_token
        )
        is renewed
    )
    released = service.release_lease(
        TENANT,
        workflow.scan_id,
        owner="worker",
        fencing_token=leased.fencing_token,
    )
    assert released.lease_owner is None
    with pytest.raises(StaleFenceError):
        service.assert_fence(
            TENANT, workflow.scan_id, owner="worker", fencing_token=leased.fencing_token
        )


def test_expected_version_prevents_lost_updates(workflow_system) -> None:
    service, _, _ = workflow_system
    workflow = create_received(service)
    service.transition(
        TENANT,
        workflow.scan_id,
        WorkflowState.VALIDATING,
        expected_version=workflow.version,
    )

    with pytest.raises(ConcurrentWorkflowUpdateError, match="Expected version 0, found 1"):
        service.transition(
            TENANT,
            workflow.scan_id,
            WorkflowState.QUEUED,
            expected_version=workflow.version,
        )


def test_outbox_conflict_rolls_back_workflow_and_event_mutation(workflow_system) -> None:
    service, repository, _ = workflow_system
    created = service.create(
        tenant_id=TENANT,
        idempotency_key="outbox",
        analysis_release_id="release",
        policy_snapshot_id="policy",
        sample_sha256=SHA256,
        object_key="quarantine/sample",
        object_generation="1",
        outbox=OutboxMessage("scan.created", {"kind": "created"}, deduplication_key="same-key"),
    ).workflow
    transitioned = service.transition(
        TENANT,
        created.scan_id,
        WorkflowState.VALIDATING,
        outbox=OutboxMessage("scan.validating", {"kind": "validating"}),
    )
    event_count = len(repository.events(TENANT, created.scan_id))

    with pytest.raises(IdempotencyConflictError, match="different content"):
        service.transition(
            TENANT,
            created.scan_id,
            WorkflowState.QUEUED,
            outbox=OutboxMessage("scan.queued", {"kind": "queued"}, deduplication_key="same-key"),
        )

    persisted = service.get(TENANT, created.scan_id)
    assert persisted is transitioned
    assert persisted.state == WorkflowState.VALIDATING
    assert len(repository.events(TENANT, created.scan_id)) == event_count
    assert len(repository.pending_outbox()) == 2


def test_outbox_payload_reserves_workflow_identity_fields(workflow_system) -> None:
    service, repository, _ = workflow_system
    created = service.create(
        tenant_id=TENANT,
        idempotency_key="reserved",
        analysis_release_id="release",
        policy_snapshot_id="policy",
        outbox=OutboxMessage(
            "scan.awaiting-upload",
            {"tenant_id": "attacker", "scan_id": "attacker", "state": "COMPLETE"},
        ),
    ).workflow

    payload = repository.pending_outbox()[0].payload
    assert payload["tenant_id"] == TENANT
    assert payload["scan_id"] == created.scan_id
    assert payload["state"] == "AWAITING_UPLOAD"
    assert payload["workflow_version"] == 0


def test_workflow_schemas_validate_hashes_and_serialize_domain(workflow_system) -> None:
    service, _, _ = workflow_system
    request = WorkflowCreateRequest(
        tenant_id=TENANT,
        idempotency_key="schema",
        analysis_release_id="release",
        policy_snapshot_id="policy",
        sample_sha256=SHA256,
        object_key="quarantine/sample",
        object_generation="1",
    )
    workflow = service.create(**request.model_dump(exclude={"outbox"})).workflow
    response = WorkflowResponse.from_domain(workflow).model_dump(mode="json")

    assert response["state"] == "UPLOAD_RECEIVED"
    assert response["sample_sha256"] == SHA256
    WorkflowCompletionRequest(result_object_key="results/result.json", result_sha256=RESULT_SHA256)
    with pytest.raises(ValidationError):
        WorkflowCompletionRequest(result_object_key="results/result.json", result_sha256="ABC")
    with pytest.raises(ValidationError):
        WorkflowTerminationRequest(terminal_state=WorkflowState.SCORING, reason="not terminal")
    with pytest.raises(ValidationError):
        WorkflowCreateRequest(
            tenant_id=TENANT,
            idempotency_key="partial-identity",
            analysis_release_id="release",
            policy_snapshot_id="policy",
            sample_sha256=SHA256,
        )
    with pytest.raises(ValidationError):
        WorkflowCreateRequest(
            tenant_id=TENANT,
            idempotency_key="schema",
            analysis_release_id="release",
            policy_snapshot_id="policy",
            unexpected=True,
        )


def test_postgresql_migration_defines_constraints_events_and_outbox() -> None:
    migration = (
        Path(__file__).parents[1] / "db" / "migrations" / "001_scan_workflows.sql"
    ).read_text(encoding="utf-8")

    assert "UNIQUE (tenant_id, idempotency_key)" in migration
    assert "scan_workflows_analysis_identity_uq" in migration
    assert "scan_workflow_transitions" in migration
    assert "scan_workflow_events" in migration
    assert "scan_workflow_outbox" in migration
    assert "terminal scan workflow" in migration
    assert "fencing_token" in migration
    assert "result_sha256" in migration
    assert "jsonb_typeof(payload) = 'object'" in migration
