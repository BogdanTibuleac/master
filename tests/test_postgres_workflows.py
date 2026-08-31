"""Deterministic contract tests for the PostgreSQL workflow adapter."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from malware_robustness.domain.workflows import (
    AnalysisIdentityConflictError,
    ConcurrentWorkflowUpdateError,
    IdempotencyConflictError,
    IllegalTransitionError,
    OutboxIntent,
    ScanWorkflow,
    StaleFenceError,
    WorkflowEvent,
    WorkflowInvariantError,
    WorkflowState,
)
from malware_robustness.repositories.postgres_workflows import PostgresWorkflowRepository

NOW = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)
TENANT = "tenant-a"
SCAN_ID = "1" * 32
EVENT_ID = "2" * 32
INTENT_ID = "3" * 32
SHA256 = "a" * 64


@dataclass(slots=True)
class Step:
    """One expected cursor execution and its deterministic result."""

    contains: tuple[str, ...]
    rows: Sequence[dict[str, Any]] = ()
    error: Exception | None = None
    inspect: Callable[[Sequence[Any]], None] | None = None


class ScriptedCursor:
    description = None

    def __init__(self, steps: list[Step]) -> None:
        self.steps = steps
        self.rows: list[dict[str, Any]] = []
        self.executions: list[tuple[str, Sequence[Any]]] = []
        self.closed = False

    def execute(self, operation: str, parameters: Sequence[Any] = ()) -> None:
        assert self.steps, f"Unexpected SQL: {operation}"
        step = self.steps.pop(0)
        normalized = " ".join(operation.split()).lower()
        for fragment in step.contains:
            assert fragment.lower() in normalized
        self.executions.append((normalized, parameters))
        if step.inspect is not None:
            step.inspect(parameters)
        if step.error is not None:
            raise step.error
        self.rows = [dict(row) for row in step.rows]

    def fetchone(self) -> dict[str, Any] | None:
        return self.rows.pop(0) if self.rows else None

    def fetchall(self) -> list[dict[str, Any]]:
        rows, self.rows = self.rows, []
        return rows

    def close(self) -> None:
        self.closed = True


class ScriptedConnection:
    def __init__(self, steps: list[Step]) -> None:
        self.cursor_instance = ScriptedCursor(steps)
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def cursor(self) -> ScriptedCursor:
        return self.cursor_instance

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closed = True


class ScriptedFactory:
    def __init__(self, *scripts: Sequence[Step]) -> None:
        self.scripts = [list(script) for script in scripts]
        self.connections: list[ScriptedConnection] = []

    def __call__(self) -> ScriptedConnection:
        assert self.scripts, "Unexpected database connection"
        connection = ScriptedConnection(self.scripts.pop(0))
        self.connections.append(connection)
        return connection

    def assert_consumed(self) -> None:
        assert not self.scripts
        assert all(not connection.cursor_instance.steps for connection in self.connections)


def workflow(
    *,
    scan_id: str = SCAN_ID,
    idempotency_key: str = "request-1",
    state: WorkflowState = WorkflowState.AWAITING_UPLOAD,
    version: int = 0,
    updated_at: datetime = NOW,
) -> ScanWorkflow:
    sealed = state != WorkflowState.AWAITING_UPLOAD
    return ScanWorkflow(
        tenant_id=TENANT,
        scan_id=scan_id,
        idempotency_key=idempotency_key,
        state=state,
        analysis_release_id="ember-2026-08",
        policy_snapshot_id="policy-17",
        created_at=NOW,
        updated_at=updated_at,
        state_changed_at=updated_at,
        sample_sha256=SHA256 if sealed else None,
        object_key="quarantine/tenant-a/object",
        object_generation="7" if sealed else None,
        version=version,
    )


def event_for(
    aggregate: ScanWorkflow,
    *,
    event_id: str = EVENT_ID,
    from_state: WorkflowState | None = None,
) -> WorkflowEvent:
    return WorkflowEvent(
        event_id=event_id,
        tenant_id=aggregate.tenant_id,
        scan_id=aggregate.scan_id,
        sequence=aggregate.version,
        event_type="workflow.created" if from_state is None else "workflow.transitioned",
        from_state=from_state,
        to_state=aggregate.state,
        occurred_at=aggregate.updated_at,
        payload={"version": aggregate.version},
    )


def intent_for(aggregate: ScanWorkflow, *, payload: dict[str, Any] | None = None) -> OutboxIntent:
    return OutboxIntent(
        intent_id=INTENT_ID,
        tenant_id=aggregate.tenant_id,
        scan_id=aggregate.scan_id,
        workflow_version=aggregate.version,
        topic="scan.created",
        deduplication_key=f"{aggregate.scan_id}:{aggregate.version}:scan.created",
        payload=payload or {"scan_id": aggregate.scan_id, "state": aggregate.state.value},
        created_at=aggregate.updated_at,
    )


def workflow_row(aggregate: ScanWorkflow) -> dict[str, Any]:
    result = aggregate.result_reference
    return {
        "tenant_id": aggregate.tenant_id,
        "scan_id": aggregate.scan_id,
        "idempotency_key": aggregate.idempotency_key,
        "state": aggregate.state.value,
        "sample_sha256": aggregate.sample_sha256,
        "object_key": aggregate.object_key,
        "object_generation": aggregate.object_generation,
        "analysis_release_id": aggregate.analysis_release_id,
        "policy_snapshot_id": aggregate.policy_snapshot_id,
        "created_at": aggregate.created_at,
        "updated_at": aggregate.updated_at,
        "state_changed_at": aggregate.state_changed_at,
        "expires_at": aggregate.expires_at,
        "terminal_at": aggregate.terminal_at,
        "attempt_count": aggregate.attempt_count,
        "lease_owner": aggregate.lease_owner,
        "lease_expires_at": aggregate.lease_expires_at,
        "fencing_token": aggregate.fencing_token,
        "failure_reason": aggregate.failure_reason,
        "result_object_key": result.object_key if result else None,
        "result_sha256": result.sha256 if result else None,
        "version": aggregate.version,
    }


def event_row(value: WorkflowEvent) -> dict[str, Any]:
    return {
        "event_id": value.event_id,
        "tenant_id": value.tenant_id,
        "scan_id": value.scan_id,
        "sequence": value.sequence,
        "event_type": value.event_type,
        "from_state": value.from_state.value if value.from_state else None,
        "to_state": value.to_state.value,
        "occurred_at": value.occurred_at,
        "payload": dict(value.payload),
    }


def outbox_row(value: OutboxIntent) -> dict[str, Any]:
    return {
        "intent_id": value.intent_id,
        "tenant_id": value.tenant_id,
        "scan_id": value.scan_id,
        "workflow_version": value.workflow_version,
        "topic": value.topic,
        "deduplication_key": value.deduplication_key,
        "payload": dict(value.payload),
        "created_at": value.created_at,
    }


def test_create_commits_workflow_event_and_outbox_in_one_transaction() -> None:
    aggregate = workflow()
    event = event_for(aggregate)
    intent = intent_for(aggregate)

    def inspect_outbox(parameters: Sequence[Any]) -> None:
        assert parameters[1] == TENANT
        assert parameters[2] == "11111111-1111-1111-1111-111111111111"
        assert parameters[6] == (
            '{"scan_id":"11111111111111111111111111111111","state":"AWAITING_UPLOAD"}'
        )

    factory = ScriptedFactory(
        [
            Step(
                ("insert into scan_workflows", "on conflict do nothing"),
                [workflow_row(aggregate)],
            ),
            Step(("insert into scan_workflow_events",), [{"event_id": EVENT_ID}]),
            Step(
                ("insert into scan_workflow_outbox",),
                [{"intent_id": INTENT_ID}],
                inspect=inspect_outbox,
            ),
        ]
    )

    created = PostgresWorkflowRepository(factory).create(
        aggregate,
        event=event,
        outbox_intents=(intent,),
    )

    assert created.created is True
    assert created.workflow == aggregate
    assert factory.connections[0].commits == 1
    assert factory.connections[0].rollbacks == 0
    assert factory.connections[0].closed is True
    factory.assert_consumed()


def test_create_idempotency_replay_returns_existing_without_duplicate_side_effects() -> None:
    aggregate = workflow()
    factory = ScriptedFactory(
        [
            Step(("insert into scan_workflows",), []),
            Step(("idempotency_key = %s", "for update"), [workflow_row(aggregate)]),
        ]
    )

    result = PostgresWorkflowRepository(factory).create(aggregate, event=event_for(aggregate))

    assert result == result.__class__(aggregate, created=False)
    assert factory.connections[0].commits == 1
    factory.assert_consumed()


def test_create_conflicting_idempotency_key_rolls_back() -> None:
    existing = workflow()
    candidate = ScanWorkflow(
        **{
            **{field: getattr(existing, field) for field in existing.__dataclass_fields__},
            "analysis_release_id": "different-release",
        }
    )
    factory = ScriptedFactory(
        [
            Step(("insert into scan_workflows",), []),
            Step(("idempotency_key = %s",), [workflow_row(existing)]),
        ]
    )

    with pytest.raises(IdempotencyConflictError, match="different workflow request"):
        PostgresWorkflowRepository(factory).create(candidate, event=event_for(candidate))

    assert factory.connections[0].commits == 0
    assert factory.connections[0].rollbacks == 1
    factory.assert_consumed()


def test_create_analysis_identity_reuse_is_tenant_scoped() -> None:
    candidate = workflow(state=WorkflowState.UPLOAD_RECEIVED)
    existing = workflow(
        scan_id="4" * 32,
        idempotency_key="other-request",
        state=WorkflowState.UPLOAD_RECEIVED,
    )

    def inspect_identity(parameters: Sequence[Any]) -> None:
        assert parameters == (TENANT, SHA256, "7", "ember-2026-08")

    factory = ScriptedFactory(
        [
            Step(("insert into scan_workflows",), []),
            Step(("idempotency_key = %s",), []),
            Step(
                ("sample_sha256 = %s", "analysis_release_id = %s", "for update"),
                [workflow_row(existing)],
                inspect=inspect_identity,
            ),
        ]
    )

    result = PostgresWorkflowRepository(factory).create(candidate, event=event_for(candidate))

    assert result.created is False
    assert result.workflow.scan_id == existing.scan_id
    factory.assert_consumed()


def test_commit_uses_locked_version_check_and_rolls_back_all_side_effects() -> None:
    current = workflow(state=WorkflowState.UPLOAD_RECEIVED)
    updated_at = NOW + timedelta(seconds=1)
    updated = current.transition(WorkflowState.VALIDATING, at=updated_at)
    event = event_for(updated, from_state=current.state)
    intent = intent_for(updated)
    factory = ScriptedFactory(
        [
            Step(("select", "from scan_workflows", "for update"), [workflow_row(current)]),
            Step(("select scan_id", "scan_id <> %s", "for update"), []),
            Step(("update scan_workflows", "version = %s", "returning"), [workflow_row(updated)]),
            Step(("insert into scan_workflow_events",), [{"event_id": EVENT_ID}]),
            Step(("insert into scan_workflow_outbox",), error=RuntimeError("storage failure")),
        ]
    )

    with pytest.raises(RuntimeError, match="storage failure"):
        PostgresWorkflowRepository(factory).commit(
            updated,
            expected_version=0,
            event=event,
            outbox_intents=(intent,),
        )

    assert factory.connections[0].commits == 0
    assert factory.connections[0].rollbacks == 1
    factory.assert_consumed()


def test_commit_rejects_stale_optimistic_version_before_update() -> None:
    current = workflow(state=WorkflowState.UPLOAD_RECEIVED, version=1)
    candidate = workflow(
        state=WorkflowState.VALIDATING,
        version=1,
        updated_at=NOW + timedelta(seconds=1),
    )
    factory = ScriptedFactory(
        [Step(("from scan_workflows", "for update"), [workflow_row(current)])]
    )

    with pytest.raises(ConcurrentWorkflowUpdateError, match="Expected version 0, found 1"):
        PostgresWorkflowRepository(factory).commit(
            candidate,
            expected_version=0,
            event=event_for(candidate, from_state=WorkflowState.UPLOAD_RECEIVED),
        )

    assert factory.connections[0].rollbacks == 1
    factory.assert_consumed()


def test_commit_rejects_an_illegal_serialized_transition_before_update() -> None:
    current = workflow()
    changed_at = NOW + timedelta(seconds=1)
    candidate = replace(
        current,
        state=WorkflowState.SCORING,
        sample_sha256=SHA256,
        object_generation="7",
        updated_at=changed_at,
        state_changed_at=changed_at,
        version=1,
    )
    factory = ScriptedFactory(
        [Step(("from scan_workflows", "for update"), [workflow_row(current)])]
    )

    with pytest.raises(IllegalTransitionError, match="AWAITING_UPLOAD.*SCORING"):
        PostgresWorkflowRepository(factory).commit(
            candidate,
            expected_version=0,
            event=event_for(candidate, from_state=current.state),
        )

    assert factory.connections[0].rollbacks == 1
    factory.assert_consumed()


def test_commit_rejects_analysis_identity_owned_by_another_workflow() -> None:
    current = workflow()
    changed_at = NOW + timedelta(seconds=1)
    candidate = replace(
        current,
        state=WorkflowState.UPLOAD_RECEIVED,
        sample_sha256=SHA256,
        object_generation="7",
        updated_at=changed_at,
        state_changed_at=changed_at,
        version=1,
    )
    factory = ScriptedFactory(
        [
            Step(("from scan_workflows", "for update"), [workflow_row(current)]),
            Step(("select scan_id", "scan_id <> %s"), [{"scan_id": "4" * 32}]),
        ]
    )

    with pytest.raises(AnalysisIdentityConflictError, match="another workflow"):
        PostgresWorkflowRepository(factory).commit(
            candidate,
            expected_version=0,
            event=event_for(candidate, from_state=current.state),
        )

    assert factory.connections[0].rollbacks == 1
    factory.assert_consumed()


def test_repository_rejects_unknown_serialized_state() -> None:
    corrupted = workflow_row(workflow())
    corrupted["state"] = "EXECUTING_UNTRUSTED_FILE"
    factory = ScriptedFactory([Step(("where tenant_id = %s and scan_id = %s",), [corrupted])])

    with pytest.raises(WorkflowInvariantError, match="Unknown serialized workflow state"):
        PostgresWorkflowRepository(factory).get(TENANT, SCAN_ID)

    assert factory.connections[0].rollbacks == 1
    factory.assert_consumed()


def test_list_and_history_are_tenant_scoped_and_stably_ordered() -> None:
    aggregate = workflow()
    event = event_for(aggregate)

    def inspect_list(parameters: Sequence[Any]) -> None:
        assert parameters == (TENANT, 25, 5)

    def inspect_history(parameters: Sequence[Any]) -> None:
        assert parameters == (TENANT, "11111111-1111-1111-1111-111111111111")

    factory = ScriptedFactory(
        [
            Step(
                ("where tenant_id = %s", "order by created_at desc", "limit %s offset %s"),
                [workflow_row(aggregate)],
                inspect=inspect_list,
            )
        ],
        [
            Step(
                ("from scan_workflow_events", "order by sequence asc"),
                [event_row(event)],
                inspect=inspect_history,
            )
        ],
    )
    repository = PostgresWorkflowRepository(factory)

    assert repository.list(TENANT, limit=25, offset=5) == [aggregate]
    assert repository.history(TENANT, SCAN_ID) == [event]
    assert all(connection.commits == 1 for connection in factory.connections)
    factory.assert_consumed()


def test_claim_pending_outbox_uses_skip_locked_and_returns_fenced_claim() -> None:
    aggregate = workflow()
    intent = intent_for(aggregate)
    lease_expires_at = NOW + timedelta(seconds=30)
    claimed_row = {
        **outbox_row(intent),
        "publish_attempts": 2,
        "locked_by": "publisher-1",
        "locked_until": lease_expires_at,
        "delivery_fencing_token": 7,
        "last_error": "broker unavailable",
    }

    def inspect_claim(parameters: Sequence[Any]) -> None:
        assert parameters == (NOW, NOW, 10, "publisher-1", lease_expires_at)

    factory = ScriptedFactory(
        [
            Step(
                ("for update skip locked", "delivery_fencing_token", "publish_attempts"),
                [claimed_row],
                inspect=inspect_claim,
            )
        ]
    )

    claims = PostgresWorkflowRepository(factory).claim_pending_outbox(
        owner="publisher-1",
        now=NOW,
        lease_duration=timedelta(seconds=30),
        limit=10,
    )

    assert len(claims) == 1
    assert claims[0].intent == intent
    assert claims[0].fencing_token == 7
    assert claims[0].publish_attempts == 2
    assert claims[0].last_error == "broker unavailable"
    factory.assert_consumed()


def test_mark_published_is_tenant_and_fence_scoped() -> None:
    factory = ScriptedFactory(
        [
            Step(
                ("update scan_workflow_outbox", "delivery_fencing_token = %s"),
                [{"intent_id": INTENT_ID}],
                inspect=lambda parameters: (
                    (
                        parameters[1] == TENANT
                        and parameters[4] == 4
                        and parameters[3] == "publisher-1"
                    )
                    or pytest.fail("publish update was not scoped by tenant, owner, and fence")
                ),
            )
        ]
    )

    PostgresWorkflowRepository(factory).mark_outbox_published(
        TENANT,
        INTENT_ID,
        owner="publisher-1",
        fencing_token=4,
        published_at=NOW,
    )

    assert factory.connections[0].commits == 1
    factory.assert_consumed()


def test_mark_published_rejects_a_stale_fence() -> None:
    factory = ScriptedFactory(
        [
            Step(("update scan_workflow_outbox",), []),
            Step(
                ("select published_at", "for update"),
                [
                    {
                        "published_at": None,
                        "failed_at": None,
                        "locked_by": "publisher-2",
                        "locked_until": NOW + timedelta(minutes=1),
                        "delivery_fencing_token": 5,
                    }
                ],
            ),
        ]
    )

    with pytest.raises(StaleFenceError, match="stale"):
        PostgresWorkflowRepository(factory).mark_outbox_published(
            TENANT,
            INTENT_ID,
            owner="publisher-1",
            fencing_token=4,
            published_at=NOW,
        )

    assert factory.connections[0].rollbacks == 1
    factory.assert_consumed()


@pytest.mark.parametrize(
    ("publish_attempts", "stored_failed_at", "expected_retry"),
    [(2, None, True), (3, NOW, False)],
)
def test_release_outbox_retries_or_exhausts_with_bounded_error(
    publish_attempts: int,
    stored_failed_at: datetime | None,
    expected_retry: bool,
) -> None:
    long_error = "x" * 3000
    retry_at = NOW + timedelta(minutes=1)

    def inspect_release(parameters: Sequence[Any]) -> None:
        assert len(parameters[0]) == 2048
        assert parameters[1] == parameters[3] == 3
        assert parameters[5] == TENANT
        assert parameters[7] == "publisher-1"
        assert parameters[8] == 9

    factory = ScriptedFactory(
        [
            Step(
                ("set last_error = %s", "failed_at = case", "available_at = case"),
                [{"publish_attempts": publish_attempts, "failed_at": stored_failed_at}],
                inspect=inspect_release,
            )
        ]
    )

    retry = PostgresWorkflowRepository(factory).release_outbox(
        TENANT,
        INTENT_ID,
        owner="publisher-1",
        fencing_token=9,
        failed_at=NOW,
        retry_at=retry_at,
        error=long_error,
        max_attempts=3,
    )

    assert retry is expected_retry
    factory.assert_consumed()


@pytest.mark.parametrize(
    "payload",
    [
        {"raw_file": "base64-encoded-malware"},
        {"nested": {"extracted_strings": ["powershell.exe"]}},
        {"opaque": b"MZ"},
    ],
)
def test_raw_content_and_extracted_strings_are_rejected_before_database_access(
    payload: dict[str, Any],
) -> None:
    aggregate = workflow()
    factory = ScriptedFactory()

    with pytest.raises(WorkflowInvariantError, match="raw|extracted strings"):
        PostgresWorkflowRepository(factory).create(
            aggregate,
            event=event_for(aggregate),
            outbox_intents=(intent_for(aggregate, payload=payload),),
        )

    assert factory.connections == []


def test_migration_adds_fenced_delivery_without_rewriting_migration_001() -> None:
    root = Path(__file__).parents[1]
    original = (root / "db" / "migrations" / "001_scan_workflows.sql").read_text(encoding="utf-8")
    upgrade = (root / "db" / "migrations" / "002_workflow_delivery.sql").read_text(encoding="utf-8")

    assert "delivery_fencing_token" not in original
    assert "delivery_fencing_token" in upgrade
    assert "scan_workflows_enforce_content_identity" in upgrade
    assert "failed_at" in upgrade
    assert "last_error_bounded" in upgrade
    assert "published_at IS NULL AND failed_at IS NULL" in upgrade
    assert "scan_workflows_tenant_history_idx" in upgrade
