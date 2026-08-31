"""End-to-end HTTP tests for create, quarantine upload, seal, and status."""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from malware_robustness.api.app import create_app
from malware_robustness.api.dependencies import (
    get_hostile_content_service,
    get_intake_service,
    get_upload_grant_signer,
    get_workflow_repository,
    get_workflow_service,
)
from malware_robustness.core.settings import BackendSettings


def _minimal_pe() -> bytes:
    content = bytearray(0x400)
    content[:2] = b"MZ"
    struct.pack_into("<I", content, 0x3C, 0x80)
    content[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", content, 0x84, 0x14C, 1, 1_700_000_000, 0, 0, 0xE0, 0x0102)
    optional = 0x98
    struct.pack_into("<H", content, optional, 0x10B)
    section = optional + 0xE0
    content[section : section + 8] = b".text\0\0\0"
    struct.pack_into(
        "<IIIIIIHHI",
        content,
        section + 8,
        0x100,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    return bytes(content)


@pytest.fixture
def runtime_client(tmp_path: Path):
    settings = BackendSettings(
        data_directory=tmp_path / "raw",
        artifact_directory=tmp_path / "artifacts",
        scan_directory=tmp_path / "scans",
        quarantine_directory=tmp_path / "quarantine",
        maximum_upload_bytes=1024 * 1024,
        upload_grant_secret="test-secret-that-is-never-used-in-production",
        cors_origins=("http://localhost:3000",),
    )
    for dependency in (
        get_hostile_content_service,
        get_intake_service,
        get_upload_grant_signer,
        get_workflow_service,
        get_workflow_repository,
    ):
        dependency.cache_clear()
    with TestClient(create_app(settings)) as client:
        yield client, settings
    for dependency in (
        get_hostile_content_service,
        get_intake_service,
        get_upload_grant_signer,
        get_workflow_service,
        get_workflow_repository,
    ):
        dependency.cache_clear()


def _create(client: TestClient, content: bytes, *, key: str = "request-123") -> dict:
    response = client.post(
        "/api/v1/scans",
        headers={
            "Idempotency-Key": key,
            "Origin": "http://localhost:3000",
            "X-Aegis-Scan": "hostile-content-v1",
        },
        json={
            "filename": "sample.exe",
            "size_bytes": len(content),
            "content_type": "application/octet-stream",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_create_upload_seal_queues_only_metadata(runtime_client) -> None:
    client, settings = runtime_client
    content = _minimal_pe()
    created = _create(client, content)
    scan_id = created["scan"]["id"]
    assert created["scan"]["status"] == "awaiting_upload"
    assert created["upload"]["method"] == "PUT"
    assert created["upload"]["fields"] == {}

    uploaded = client.put(
        created["upload"]["url"],
        headers=created["upload"]["headers"],
        content=content,
    )
    assert uploaded.status_code == 201, uploaded.text
    generation = uploaded.headers["x-aegis-object-generation"]

    sealed = client.post(
        f"/api/v1/scans/{scan_id}:seal",
        json={
            "sha256": hashlib.sha256(content).hexdigest(),
            "size_bytes": len(content),
            "object_generation": generation,
        },
    )
    assert sealed.status_code == 200, sealed.text
    assert sealed.json()["status"] == "queued"
    assert sealed.json()["sample_sha256"] == hashlib.sha256(content).hexdigest()

    repeated_seal = client.post(
        f"/api/v1/scans/{scan_id}:seal",
        json={
            "sha256": hashlib.sha256(content).hexdigest(),
            "size_bytes": len(content),
            "object_generation": "an-external-storage-version-can-differ",
        },
    )
    assert repeated_seal.status_code == 200, repeated_seal.text
    assert repeated_seal.json()["status"] == "queued"

    status_response = client.get(f"/api/v1/scans/{scan_id}")
    assert status_response.status_code == 200
    assert status_response.json()["status"] == "queued"
    history = client.get("/api/v1/scans?limit=10")
    assert history.status_code == 200
    assert history.json()["items"][0]["id"] == scan_id

    service = get_hostile_content_service(settings)
    intents = service.workflows.repository.pending_outbox()
    assert len(intents) == 1
    intent = intents[0]
    assert intent.topic == "scan.queued"
    assert set(intent.payload) == {
        "analysis_release_id",
        "object_generation",
        "object_key",
        "sample_sha256",
        "scan_id",
        "state",
        "tenant_id",
        "workflow_version",
    }
    serialized = repr(dict(intent.payload)).lower()
    assert "sample.exe" not in serialized
    assert "mz" not in serialized


def test_idempotency_reuses_identical_create_and_rejects_changed_request(
    runtime_client,
) -> None:
    client, _ = runtime_client
    content = _minimal_pe()
    first = _create(client, content, key="same-request")
    second = _create(client, content, key="same-request")
    assert second["scan"]["id"] == first["scan"]["id"]
    assert second["upload"]["url"] == first["upload"]["url"]

    changed = client.post(
        "/api/v1/scans",
        headers={
            "Idempotency-Key": "same-request",
            "X-Aegis-Scan": "hostile-content-v1",
        },
        json={
            "filename": "different.exe",
            "size_bytes": len(content),
            "content_type": "application/octet-stream",
        },
    )
    assert changed.status_code == 409


def test_upload_grant_and_seal_fail_closed(runtime_client) -> None:
    client, _ = runtime_client
    content = _minimal_pe()
    created = _create(client, content, key="fail-closed")
    scan_id = created["scan"]["id"]

    denied = client.put(
        created["upload"]["url"],
        headers={"X-Aegis-Upload-Token": "invalid"},
        content=content,
    )
    assert denied.status_code == 403

    uploaded = client.put(
        created["upload"]["url"],
        headers=created["upload"]["headers"],
        content=content,
    )
    assert uploaded.status_code == 201
    mismatch = client.post(
        f"/api/v1/scans/{scan_id}:seal",
        json={"sha256": "0" * 64, "size_bytes": len(content)},
    )
    assert mismatch.status_code == 422
    assert client.get(f"/api/v1/scans/{scan_id}").json()["status"] == "awaiting_upload"
