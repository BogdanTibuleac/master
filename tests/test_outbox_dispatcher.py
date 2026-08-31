"""Deterministic tests for fenced transactional-outbox dispatch."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import MappingProxyType

import pytest

from malware_robustness.domain.outbox_delivery import (
    SCAN_QUEUED_OUTBOX_TOPIC,
    ClaimedOutboxDelivery,
    OutboxLeaseLostError,
    OutboxPoisonMessageError,
    OutboxReleaseDisposition,
    OutboxRetryMetadata,
    OutboxStoreContractError,
)
from malware_robustness.domain.scan_jobs import (
    ScanQueueUnavailableError,
    ScanTask,
    ScanTaskFormatError,
)
from malware_robustness.services.outbox import OutboxDispatcher, scan_task_from_outbox

NOW = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)
OWNER = "dispatcher-a"


def _payload(*, suffix: str = "a") -> dict[str, object]:
    return {
        "tenant_id": "tenant_acme",
        "scan_id": f"scan_01K4DXQ20YQY7J1N7G8E5X3V2{suffix}",
        "workflow_version": 3,
        "state": "QUEUED",
        "object_key": suffix * 32,
        "object_generation": (suffix.upper() if suffix != "a" else "f") * 32,
        "sample_sha256": suffix * 64,
        "analysis_release_id": "ember-v2.2026-08-31",
    }


def _delivery(
    *,
    suffix: str = "a",
    topic: str = SCAN_QUEUED_OUTBOX_TOPIC,
    payload: dict[str, object] | None = None,
    publish_attempts: int = 0,
    owner: str = OWNER,
    lease_expires_at: datetime = NOW + timedelta(seconds=30),
    fencing_token: int = 7,
) -> ClaimedOutboxDelivery:
    event = payload or _payload(suffix=suffix)
    return ClaimedOutboxDelivery(
        intent_id=f"intent_01K4DXQ20YQY7J1N7G8E5X3V2{suffix}",
        tenant_id="tenant_acme",
        scan_id=f"scan_01K4DXQ20YQY7J1N7G8E5X3V2{suffix}",
        workflow_version=3,
        topic=topic,
        payload=event,
        publish_attempts=publish_attempts,
        owner=owner,
        lease_expires_at=lease_expires_at,
        fencing_token=fencing_token,
    )


class FakeStore:
    def __init__(self, batch: list[ClaimedOutboxDelivery], trace: list[str] | None = None) -> None:
        self.batch = batch
        self.trace = trace if trace is not None else []
        self.claims: list[dict[str, object]] = []
        self.published: list[tuple[str, str, int, datetime]] = []
        self.released: list[tuple[str, str, int, OutboxRetryMetadata]] = []
        self.mark_error: Exception | None = None
        self.release_error: Exception | None = None

    def claim_batch(self, **kwargs):
        self.claims.append(kwargs)
        return list(self.batch)

    def mark_published(
        self,
        intent_id: str,
        *,
        owner: str,
        fencing_token: int,
        published_at: datetime,
    ) -> None:
        self.trace.append("mark")
        if self.mark_error is not None:
            raise self.mark_error
        self.published.append((intent_id, owner, fencing_token, published_at))

    def release(
        self,
        intent_id: str,
        *,
        owner: str,
        fencing_token: int,
        retry: OutboxRetryMetadata,
    ) -> None:
        self.trace.append("release")
        if self.release_error is not None:
            raise self.release_error
        self.released.append((intent_id, owner, fencing_token, retry))


class FakePublisher:
    def __init__(
        self,
        actions: list[Exception | None] | None = None,
        trace: list[str] | None = None,
    ) -> None:
        self.actions = list(actions or [])
        self.trace = trace if trace is not None else []
        self.tasks: list[ScanTask] = []

    def publish(self, task: ScanTask) -> None:
        self.trace.append("publish")
        self.tasks.append(task)
        if self.actions:
            action = self.actions.pop(0)
            if action is not None:
                raise action


def _dispatcher(
    store: FakeStore,
    publisher: FakePublisher,
    **kwargs,
) -> OutboxDispatcher:
    return OutboxDispatcher(store, publisher, owner=OWNER, clock=lambda: NOW, **kwargs)


def test_confirmed_publication_is_marked_after_publish_with_current_fence() -> None:
    trace: list[str] = []
    store = FakeStore([_delivery()], trace)
    publisher = FakePublisher(trace=trace)

    report = _dispatcher(store, publisher, batch_size=4).dispatch_once()

    assert report.claimed == report.published == 1
    assert report.retry_scheduled == report.poisoned == report.exhausted == 0
    assert report.lease_lost == report.uncertain == 0
    assert trace == ["publish", "mark"]
    assert store.published == [(_delivery().intent_id, OWNER, _delivery().fencing_token, NOW)]
    assert store.claims == [
        {
            "owner": OWNER,
            "now": NOW,
            "lease_duration": timedelta(seconds=30),
            "limit": 4,
        }
    ]


def test_mapper_builds_only_a_fresh_id_only_scan_task() -> None:
    delivery = _delivery()

    task = scan_task_from_outbox(delivery)

    assert task == ScanTask(
        scan_id=delivery.scan_id,
        tenant_id=delivery.tenant_id,
        object_key="a" * 32,
        object_generation="f" * 32,
        sample_sha256="a" * 64,
        analysis_release_id="ember-v2.2026-08-31",
        attempt=0,
        job_nonce=delivery.intent_id,
    )
    assert isinstance(delivery.payload, MappingProxyType)


@pytest.mark.parametrize(
    ("topic", "mutation"),
    [
        ("scan.completed", {}),
        (SCAN_QUEUED_OUTBOX_TOPIC, {"__remove__": "object_generation"}),
        (SCAN_QUEUED_OUTBOX_TOPIC, {"raw_bytes": b"MZ hostile bytes"}),
        (SCAN_QUEUED_OUTBOX_TOPIC, {"filename": "invoice.exe"}),
        (SCAN_QUEUED_OUTBOX_TOPIC, {"url": "https://storage.invalid/sample"}),
        (SCAN_QUEUED_OUTBOX_TOPIC, {"upload_grant": "sig=classified"}),
        (SCAN_QUEUED_OUTBOX_TOPIC, {"feature_vector": [0.0, 1.0]}),
        (SCAN_QUEUED_OUTBOX_TOPIC, {"context": {"arbitrary": "nested"}}),
        (SCAN_QUEUED_OUTBOX_TOPIC, {"secret": "do-not-log-this-value"}),
    ],
)
def test_unknown_or_sensitive_events_are_terminal_poison(
    topic: str,
    mutation: dict[str, object],
    caplog: pytest.LogCaptureFixture,
) -> None:
    payload = _payload()
    changes = dict(mutation)
    removed = changes.pop("__remove__", None)
    if removed is not None:
        payload.pop(str(removed))
    payload.update(changes)
    store = FakeStore([_delivery(topic=topic, payload=payload)])
    publisher = FakePublisher()

    report = _dispatcher(store, publisher).dispatch_once()

    assert report.poisoned == 1
    assert publisher.tasks == []
    retry = store.released[0][3]
    assert retry == OutboxRetryMetadata(
        attempt=1,
        disposition=OutboxReleaseDisposition.POISON,
        error_code="invalid_scan_queued_event",
        available_at=None,
    )
    assert "do-not-log-this-value" not in caplog.text


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("object_key", "https://storage.invalid/file?sig=classified"),
        ("object_generation", "sig=classified"),
        ("object_key", b"MZ"),
        ("sample_sha256", ["a" * 64]),
        ("analysis_release_id", {"secret": "classified"}),
    ],
)
def test_sensitive_values_cannot_hide_inside_allow_listed_fields(field: str, value: object) -> None:
    payload = _payload()
    payload[field] = value

    with pytest.raises(OutboxPoisonMessageError):
        scan_task_from_outbox(_delivery(payload=payload))


@pytest.mark.parametrize(
    "mutation",
    [
        {"tenant_id": "tenant_other"},
        {"scan_id": "scan_other"},
        {"workflow_version": 4},
        {"workflow_version": True},
        {"state": "VALIDATING"},
    ],
)
def test_event_identity_and_queued_state_must_match_the_envelope(
    mutation: dict[str, object],
) -> None:
    payload = {**_payload(), **mutation}

    with pytest.raises(OutboxPoisonMessageError):
        scan_task_from_outbox(_delivery(payload=payload))


def test_publisher_outage_releases_with_bounded_non_sensitive_retry_metadata() -> None:
    store = FakeStore([_delivery(publish_attempts=1)])
    publisher = FakePublisher([ScanQueueUnavailableError("amqp://user:secret@broker")])
    dispatcher = _dispatcher(
        store,
        publisher,
        max_attempts=4,
        retry_backoff=lambda attempt: timedelta(seconds=attempt * 10),
    )

    report = dispatcher.dispatch_once()

    assert report.retry_scheduled == 1
    assert store.published == []
    retry = store.released[0][3]
    assert retry == OutboxRetryMetadata(
        attempt=2,
        disposition=OutboxReleaseDisposition.RETRY,
        error_code="publisher_unavailable",
        available_at=NOW + timedelta(seconds=20),
    )
    assert "secret" not in retry.error_code


def test_final_failed_attempt_is_exhausted_and_never_retried() -> None:
    store = FakeStore([_delivery(publish_attempts=2)])
    publisher = FakePublisher([RuntimeError("offline")])

    report = _dispatcher(store, publisher, max_attempts=3).dispatch_once()

    assert report.exhausted == 1
    retry = store.released[0][3]
    assert retry.disposition is OutboxReleaseDisposition.EXHAUSTED
    assert retry.attempt == 3
    assert retry.available_at is None


def test_already_exhausted_claim_is_not_published_again() -> None:
    store = FakeStore([_delivery(publish_attempts=3)])
    publisher = FakePublisher()

    report = _dispatcher(store, publisher, max_attempts=3).dispatch_once()

    assert report.exhausted == 1
    assert publisher.tasks == []
    assert store.released[0][3].attempt == 3


def test_partial_batch_continues_after_one_publisher_outage() -> None:
    first = _delivery(suffix="a")
    second = _delivery(suffix="b")
    store = FakeStore([first, second])
    publisher = FakePublisher([ScanQueueUnavailableError("offline"), None])

    report = _dispatcher(store, publisher, batch_size=2).dispatch_once()

    assert report.claimed == 2
    assert report.retry_scheduled == 1
    assert report.published == 1
    assert [item[0] for item in store.released] == [first.intent_id]
    assert [item[0] for item in store.published] == [second.intent_id]


@pytest.mark.parametrize(
    "delivery",
    [
        _delivery(owner="another-dispatcher"),
        _delivery(lease_expires_at=NOW),
        _delivery(lease_expires_at=NOW - timedelta(microseconds=1)),
    ],
)
def test_stale_or_foreign_claims_are_never_published(delivery: ClaimedOutboxDelivery) -> None:
    store = FakeStore([delivery])
    publisher = FakePublisher()

    report = _dispatcher(store, publisher).dispatch_once()

    assert report.lease_lost == 1
    assert publisher.tasks == []
    assert store.published == store.released == []


def test_stale_fence_after_confirmation_is_not_marked_or_released() -> None:
    store = FakeStore([_delivery()])
    store.mark_error = OutboxLeaseLostError("stale fence")
    publisher = FakePublisher()

    report = _dispatcher(store, publisher).dispatch_once()

    assert report.lease_lost == 1
    assert len(publisher.tasks) == 1
    assert store.released == []


def test_stale_fence_during_release_does_not_overwrite_newer_retry_state() -> None:
    store = FakeStore([_delivery()])
    store.release_error = OutboxLeaseLostError("stale fence")
    publisher = FakePublisher([ScanQueueUnavailableError("offline")])

    report = _dispatcher(store, publisher).dispatch_once()

    assert report.lease_lost == 1
    assert store.released == []


def test_confirmed_but_unmarked_publication_replays_with_identical_task() -> None:
    delivery = _delivery()
    store = FakeStore([delivery])
    store.mark_error = RuntimeError("database unavailable after broker confirmation")
    publisher = FakePublisher()

    first = _dispatcher(store, publisher).dispatch_once()

    assert first.uncertain == 1
    assert store.released == []
    store.mark_error = None
    store.batch = [
        replace(
            delivery,
            owner=OWNER,
            lease_expires_at=NOW + timedelta(minutes=1),
            fencing_token=delivery.fencing_token + 1,
        )
    ]

    replay = _dispatcher(store, publisher).dispatch_once()

    assert replay.published == 1
    assert len(publisher.tasks) == 2
    assert publisher.tasks[0] == publisher.tasks[1]
    assert publisher.tasks[0].job_nonce == delivery.intent_id


def test_publisher_contract_rejection_is_terminal_poison() -> None:
    store = FakeStore([_delivery()])
    publisher = FakePublisher([ScanTaskFormatError("policy rejected")])

    report = _dispatcher(store, publisher).dispatch_once()

    assert report.poisoned == 1
    assert store.released[0][3].disposition is OutboxReleaseDisposition.POISON


def test_store_release_failure_is_uncertain_and_does_not_acknowledge() -> None:
    store = FakeStore([_delivery()])
    store.release_error = RuntimeError("database unavailable")
    publisher = FakePublisher([ScanQueueUnavailableError("offline")])

    report = _dispatcher(store, publisher).dispatch_once()

    assert report.uncertain == 1
    assert store.published == store.released == []


def test_store_cannot_exceed_or_duplicate_the_claim_bound() -> None:
    store = FakeStore([_delivery(suffix="a"), _delivery(suffix="b")])
    publisher = FakePublisher()
    with pytest.raises(OutboxStoreContractError, match="more than"):
        _dispatcher(store, publisher, batch_size=1).dispatch_once()

    duplicate = _delivery()
    store.batch = [duplicate, duplicate]
    with pytest.raises(OutboxStoreContractError, match="duplicate"):
        _dispatcher(store, publisher, batch_size=2).dispatch_once()

    assert publisher.tasks == []


@pytest.mark.parametrize(
    "kwargs",
    [
        {"batch_size": 0},
        {"batch_size": 101},
        {"lease_duration": timedelta(0)},
        {"lease_duration": timedelta(hours=1)},
        {"max_attempts": 0},
        {"max_attempts": 11},
    ],
)
def test_dispatcher_configuration_is_bounded(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        _dispatcher(FakeStore([]), FakePublisher(), **kwargs)
