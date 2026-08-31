"""Tests for safe PE extraction, model scoring and scan HTTP endpoints."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from malware_robustness.api.app import create_app
from malware_robustness.api.dependencies import get_scan_service
from malware_robustness.domain.scans import ModelScore, ScanValidationError
from malware_robustness.pe_features import PEFeatureExtractor
from malware_robustness.repositories.scans import ScanRepository
from malware_robustness.services.scans import ScanService


class FakeModelRepository:
    """Deterministic model response for service and route tests."""

    def score(self, vector) -> ModelScore:
        assert vector.shape == (2381,)
        contributions = [0.0] * 2381
        contributions[943] = 2.5
        contributions[626] = -0.4
        return ModelScore(
            model_name="robust_test_model",
            decision_threshold=0.56,
            malware_probability=0.91,
            feature_contributions=contributions,
        )

    def is_ready(self) -> bool:
        return True


class UnavailableModelRepository(FakeModelRepository):
    def is_ready(self) -> bool:
        return False


def _minimal_pe() -> bytes:
    """Build a small parseable PE32 image without executing or downloading a fixture."""
    content = bytearray(0x400)
    content[:2] = b"MZ"
    struct.pack_into("<I", content, 0x3C, 0x80)
    content[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", content, 0x84, 0x14C, 1, 1_700_000_000, 0, 0, 0xE0, 0x0102)

    optional = 0x98
    struct.pack_into("<HBBIII", content, optional, 0x10B, 14, 0, 0x200, 0, 0)
    struct.pack_into("<III", content, optional + 16, 0x1000, 0x1000, 0x2000)
    struct.pack_into("<I", content, optional + 28, 0x400000)
    struct.pack_into("<II", content, optional + 32, 0x1000, 0x200)
    struct.pack_into("<HHHHHH", content, optional + 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<I", content, optional + 52, 0)
    struct.pack_into("<II", content, optional + 56, 0x2000, 0x200)
    struct.pack_into("<IHH", content, optional + 64, 0, 3, 0x0140)
    struct.pack_into("<IIIIII", content, optional + 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)

    section = optional + 0xE0
    content[section : section + 8] = b".text\0\0\0"
    struct.pack_into(
        "<IIIIIIHHI", content, section + 8, 0x100, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020
    )
    content[0x200:0x220] = b"This is a harmless PE fixture MZ\0"
    return bytes(content)


def _service(tmp_path: Path) -> ScanService:
    return ScanService(
        ScanRepository(tmp_path / "scans"),
        FakeModelRepository(),  # type: ignore[arg-type]
        PEFeatureExtractor(),
        maximum_file_size=1024 * 1024,
    )


def test_pe_extractor_produces_complete_ember_vector() -> None:
    result = PEFeatureExtractor().extract(_minimal_pe())

    assert result.vector.shape == (2381,)
    assert result.metadata["file_type"] == "PE32"
    assert result.metadata["architecture"] == "I386"
    assert result.metadata["section_count"] == 1


def test_pe_extractor_rejects_non_pe_content() -> None:
    with pytest.raises(ScanValidationError, match="MZ header"):
        PEFeatureExtractor().extract(b"not a portable executable")


def test_scan_service_persists_metadata_but_not_uploaded_binary(tmp_path: Path) -> None:
    service = _service(tmp_path)
    content = _minimal_pe()

    result = service.scan("sample.exe", content)

    assert result["verdict"] == "high_risk"
    assert result["malware_probability"] == 0.91
    assert result["binary_retained"] is False
    assert result["sha256"]
    assert service.get(result["id"]) == result
    assert service.history()[0]["id"] == result["id"]
    stored_files = list((tmp_path / "scans").iterdir())
    assert [path.suffix for path in stored_files] == [".json"]
    assert content not in stored_files[0].read_bytes()


def test_scan_service_rejects_unsupported_and_oversized_files(tmp_path: Path) -> None:
    service = _service(tmp_path)
    with pytest.raises(ScanValidationError, match="Unsupported"):
        service.scan("notes.txt", _minimal_pe())

    oversized = ScanService(
        ScanRepository(tmp_path / "small"),
        FakeModelRepository(),  # type: ignore[arg-type]
        PEFeatureExtractor(),
        maximum_file_size=32,
    )
    with pytest.raises(ScanValidationError, match="upload limit") as error:
        oversized.scan("sample.exe", _minimal_pe())
    assert error.value.status_code == 413


def test_scan_routes_create_list_and_retrieve_results(tmp_path: Path) -> None:
    application = create_app()
    service = _service(tmp_path)
    application.dependency_overrides[get_scan_service] = lambda: service
    client = TestClient(application)

    readiness = client.get("/ready")
    assert readiness.status_code == 200
    assert readiness.json() == {
        "status": "ready",
        "checks": {"model_artifacts": True, "scan_metadata": True},
    }

    created = client.post(
        "/api/v1/scans",
        headers={"X-Aegis-Scan": "static-pe-v1"},
        files={"file": ("suspicious.exe", _minimal_pe(), "application/octet-stream")},
    )
    assert created.status_code == 201
    payload = created.json()
    assert payload["filename"] == "suspicious.exe"
    assert payload["feature_count"] == 2381
    assert payload["binary_retained"] is False

    history = client.get("/api/v1/scans").json()
    assert history["count"] == 1
    assert history["items"][0]["id"] == payload["id"]
    assert client.get(f"/api/v1/scans/{payload['id']}").json() == payload
    assert client.get("/api/v1/scans/missing").status_code == 404


def test_scan_route_requires_the_preflighted_application_header(tmp_path: Path) -> None:
    application = create_app()
    application.dependency_overrides[get_scan_service] = lambda: _service(tmp_path)
    client = TestClient(application)

    response = client.post(
        "/api/v1/scans",
        headers={"X-Aegis-Scan": "unexpected"},
        files={"file": ("sample.exe", _minimal_pe(), "application/octet-stream")},
    )

    assert response.status_code == 403


def test_readiness_rejects_traffic_when_the_model_is_unavailable(tmp_path: Path) -> None:
    application = create_app()
    service = ScanService(
        ScanRepository(tmp_path / "scans"),
        UnavailableModelRepository(),  # type: ignore[arg-type]
        PEFeatureExtractor(),
        maximum_file_size=1024 * 1024,
    )
    application.dependency_overrides[get_scan_service] = lambda: service
    client = TestClient(application)

    response = client.get("/ready")

    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "checks": {"model_artifacts": False, "scan_metadata": True},
    }
