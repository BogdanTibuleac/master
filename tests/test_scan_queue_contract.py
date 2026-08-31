"""Contract tests for ID-only scan tasks and durable RabbitMQ handling."""

from __future__ import annotations

import json
from dataclasses import asdict
from types import SimpleNamespace

import pika
import pytest

from malware_robustness.domain.scan_jobs import (
    MAX_SCAN_TASK_MESSAGE_BYTES,
    ScanQueueUnavailableError,
    ScanTask,
    ScanTaskFormatError,
    ScanTaskRejectedError,
)
from malware_robustness.queues.rabbitmq import (
    RabbitMQScanQueue,
    decode_scan_task,
    encode_scan_task,
)
from malware_robustness.worker import run_worker


def _task(*, attempt: int = 0) -> ScanTask:
    return ScanTask(
        scan_id="scan_01K4DXQ20YQY7J1N7G8E5X3V2Z",
        tenant_id="tenant_acme",
        object_key="quarantine/tenant_acme/scan_01K4DXQ20YQY7J1N7G8E5X3V2Z",
        object_generation="2026-08-31T10:15:30.0000000Z",
        sample_sha256="a" * 64,
        analysis_release_id="ember-v2.2026-08-31",
        attempt=attempt,
        job_nonce="nonce_01K4DXQ2Y2F4B0PZA0T32H7S9R",
    )


def test_scan_task_round_trip_contains_only_allow_listed_metadata() -> None:
    task = _task()

    body = encode_scan_task(task)
    payload = json.loads(body)

    assert decode_scan_task(body) == task
    assert set(payload) == {
        "schema_version",
        "scan_id",
        "tenant_id",
        "object_key",
        "object_generation",
        "sample_sha256",
        "analysis_release_id",
        "attempt",
        "job_nonce",
    }
    assert len(body) <= MAX_SCAN_TASK_MESSAGE_BYTES


def test_raw_content_and_sensitive_fields_cannot_enter_scan_messages() -> None:
    with pytest.raises(TypeError):
        ScanTask(**{**asdict(_task()), "content": b"MZ hostile bytes"})  # type: ignore[arg-type]

    payload = json.loads(encode_scan_task(_task()))
    for forbidden_field, value in {
        "content": "TVogaG9zdGlsZSBieXRlcw==",
        "filename": "malware.exe",
        "feature_vector": [0.0] * 3,
        "credentials": "secret",
        "url": "https://storage.invalid/object",
        "upload_grant": "sig=secret",
    }.items():
        poisoned = {**payload, forbidden_field: value}
        with pytest.raises(ScanTaskFormatError, match="unknown fields"):
            decode_scan_task(json.dumps(poisoned).encode())

    assert b"MZ hostile bytes" not in encode_scan_task(_task())


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"schema_version": 2}, "schema version"),
        ({"scan_id": "../escape"}, "scan_id"),
        ({"object_key": "https://storage.invalid/file?sig=secret"}, "object_key"),
        ({"sample_sha256": "A" * 64}, "SHA-256"),
        ({"attempt": -1}, "attempt"),
        ({"attempt": 1.5}, "attempt"),
        ({"attempt": True}, "attempt"),
    ],
)
def test_malformed_task_values_are_rejected(mutation: dict[str, object], message: str) -> None:
    payload = {**json.loads(encode_scan_task(_task())), **mutation}

    with pytest.raises(ScanTaskFormatError, match=message):
        decode_scan_task(json.dumps(payload).encode())


def test_non_finite_duplicate_and_oversized_messages_are_rejected() -> None:
    valid = encode_scan_task(_task()).decode()

    with pytest.raises(ScanTaskFormatError, match="non-finite"):
        decode_scan_task(valid.replace('"attempt":0', '"attempt":NaN').encode())
    with pytest.raises(ScanTaskFormatError, match="duplicate"):
        decode_scan_task(valid.replace("{", '{"scan_id":"duplicate",', 1).encode())
    with pytest.raises(ScanTaskFormatError, match="maximum serialized size"):
        decode_scan_task(b"{" + b" " * MAX_SCAN_TASK_MESSAGE_BYTES + b"}")
    with pytest.raises(ScanTaskFormatError, match="strict UTF-8 JSON"):
        decode_scan_task(b"not-json")


class FakeChannel:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.callback = None
        self.publish_result = True

    def __getattr__(self, name: str):
        def record(**kwargs):
            self.calls.append((name, kwargs))
            if name == "basic_consume":
                self.callback = kwargs["on_message_callback"]
            if name == "basic_publish":
                return self.publish_result
            return None

        return record


class FakeConnection:
    def __init__(self, channel: FakeChannel) -> None:
        self._channel = channel
        self.is_open = True

    def channel(self) -> FakeChannel:
        return self._channel

    def close(self) -> None:
        self.is_open = False


def _connected_queue(monkeypatch: pytest.MonkeyPatch, *, max_attempts: int = 2):
    channel = FakeChannel()
    connection = FakeConnection(channel)
    queue = RabbitMQScanQueue(
        "amqp://guest:guest@localhost/",
        "hostile.scan",
        max_attempts=max_attempts,
    )
    monkeypatch.setattr(queue, "_connect", lambda: connection)
    return queue, channel, connection


def _properties() -> pika.BasicProperties:
    return pika.BasicProperties(
        content_type="application/json",
        content_encoding="utf-8",
        delivery_mode=2,
        type="malware.scan-task.v1",
    )


def test_publish_declares_durable_dlq_and_confirms_persistent_delivery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue, channel, connection = _connected_queue(monkeypatch)

    queue.publish(_task())

    declarations = [kwargs for name, kwargs in channel.calls if name == "queue_declare"]
    assert {item["queue"] for item in declarations} == {
        "hostile.scan",
        "hostile.scan.dead-letter",
    }
    assert all(item["durable"] is True for item in declarations)
    primary = next(item for item in declarations if item["queue"] == "hostile.scan")
    assert primary["arguments"] == {
        "x-dead-letter-exchange": "hostile.scan.dead-letter.exchange",
        "x-dead-letter-routing-key": "hostile.scan.rejected",
    }
    assert any(name == "confirm_delivery" for name, _ in channel.calls)
    publication = next(kwargs for name, kwargs in channel.calls if name == "basic_publish")
    assert publication["mandatory"] is True
    assert publication["properties"].delivery_mode == 2
    assert decode_scan_task(publication["body"]) == _task()
    assert connection.is_open is False


def test_unconfirmed_publication_is_reported_as_queue_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue, channel, _connection = _connected_queue(monkeypatch)
    channel.publish_result = False

    with pytest.raises(ScanQueueUnavailableError, match="did not confirm"):
        queue.publish(_task())


def test_publish_rejects_tasks_outside_the_queue_retry_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue, channel, _connection = _connected_queue(monkeypatch, max_attempts=1)

    with pytest.raises(ScanTaskFormatError, match="retry policy"):
        queue.publish(_task(attempt=2))

    assert not channel.calls


def test_consumer_uses_manual_ack_prefetch_and_attempt_bounded_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue, channel, _connection = _connected_queue(monkeypatch, max_attempts=1)
    seen: list[ScanTask] = []

    def failing_handler(task: ScanTask) -> None:
        seen.append(task)
        raise RuntimeError("transient")

    queue.consume(failing_handler)
    consume_call = next(kwargs for name, kwargs in channel.calls if name == "basic_consume")
    assert consume_call["auto_ack"] is False
    assert any(
        name == "basic_qos" and kwargs == {"prefetch_count": 1}
        for name, kwargs in channel.calls
    )

    method = SimpleNamespace(delivery_tag=41)
    channel.callback(channel, method, _properties(), encode_scan_task(_task()))
    retry_publication = [kwargs for name, kwargs in channel.calls if name == "basic_publish"][-1]
    assert decode_scan_task(retry_publication["body"]).attempt == 1
    assert any(
        name == "basic_ack" and kwargs == {"delivery_tag": 41} for name, kwargs in channel.calls
    )

    method = SimpleNamespace(delivery_tag=42)
    channel.callback(channel, method, _properties(), encode_scan_task(_task(attempt=1)))
    assert any(
        name == "basic_reject"
        and kwargs == {"delivery_tag": 42, "requeue": False}
        for name, kwargs in channel.calls
    )


def test_consumer_rejects_malformed_and_handler_declared_poison_messages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue, channel, _connection = _connected_queue(monkeypatch)

    def poison_handler(_task: ScanTask) -> None:
        raise ScanTaskRejectedError("invalid state")

    queue.consume(poison_handler)
    channel.callback(
        channel,
        SimpleNamespace(delivery_tag=50),
        _properties(),
        b'{"content":"MZ"}',
    )
    channel.callback(
        channel,
        SimpleNamespace(delivery_tag=51),
        _properties(),
        encode_scan_task(_task()),
    )
    channel.callback(
        channel,
        SimpleNamespace(delivery_tag=52),
        pika.BasicProperties(
            content_type="application/json",
            content_encoding="utf-8",
            delivery_mode=1,
            type="malware.scan-task.v1",
        ),
        encode_scan_task(_task()),
    )

    rejected = [kwargs for name, kwargs in channel.calls if name == "basic_reject"]
    assert {item["delivery_tag"] for item in rejected} == {50, 51, 52}
    assert all(item["requeue"] is False for item in rejected)


def test_worker_uses_injected_handler_and_reconnects_after_transport_outage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Consumer:
        calls = 0

        def consume(self, handler) -> None:
            self.calls += 1
            if self.calls == 1:
                raise ScanQueueUnavailableError("offline")
            handler(_task())

    consumer = Consumer()
    handled: list[ScanTask] = []
    sleeps: list[float] = []
    monkeypatch.setattr("malware_robustness.worker.time.sleep", sleeps.append)

    run_worker(consumer, handled.append, retry_delay_seconds=0.25)

    assert consumer.calls == 2
    assert handled == [_task()]
    assert sleeps == [0.25]


@pytest.mark.parametrize("delay", [float("nan"), float("inf"), -1, 301, True])
def test_worker_rejects_unbounded_retry_delays(delay: float) -> None:
    with pytest.raises(ValueError, match="finite"):
        run_worker(
            SimpleNamespace(consume=lambda _handler: None),
            lambda _task: None,
            retry_delay_seconds=delay,
        )
