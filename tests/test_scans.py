"""Tests for safe PE extraction, model scoring and scan HTTP endpoints."""

from __future__ import annotations

import struct
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

import pytest
from fastapi.testclient import TestClient

from malware_robustness.api.app import create_app
from malware_robustness.api.dependencies import get_scan_service
from malware_robustness.core.settings import BackendSettings, normalize_origin
from malware_robustness.domain.scans import ModelScore, ScanCapacityError, ScanValidationError
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


class FailingModelRepository:
    """Model adapter that verifies unexpected details stay server-side."""

    def score(self, vector) -> ModelScore:
        raise RuntimeError("sensitive model filesystem detail")


class BlockingExtractor:
    """Hold one extraction open to exercise the service capacity boundary."""

    def __init__(self) -> None:
        self.entered = Event()
        self.release = Event()

    def extract(self, content: bytes):
        self.entered.set()
        assert self.release.wait(timeout=5)
        return PEFeatureExtractor().extract(content)


class ExhaustedExtractor:
    """Simulate a resource failure raised by an underlying parser."""

    def extract(self, content: bytes):
        raise MemoryError("attacker-controlled parser detail")


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


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda content: struct.pack_into("<H", content, 0x86, 97), "number of sections"),
        (lambda content: struct.pack_into("<H", content, 0x94, 2048), "optional header"),
        (
            lambda content: struct.pack_into("<II", content, 0x188, 0x300, 0x300),
            "outside the uploaded file",
        ),
    ],
)
def test_pe_extractor_rejects_pathological_header_ranges(mutate, message: str) -> None:
    content = bytearray(_minimal_pe())
    mutate(content)

    with pytest.raises(ScanValidationError, match=message):
        PEFeatureExtractor().extract(bytes(content))


def test_pe_extractor_bounds_pathological_printable_string_counts() -> None:
    content = _minimal_pe() + (b"AAAAA\0" * 100_001)

    with pytest.raises(ScanValidationError, match="too many printable"):
        PEFeatureExtractor().extract(content)


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


def test_scan_service_sanitizes_cross_platform_display_filenames(tmp_path: Path) -> None:
    service = _service(tmp_path)

    result = service.scan("C:\\incoming\\payload\u202e.exe", _minimal_pe())
    long_result = service.scan(f"../../{'a' * 300}.exe", _minimal_pe())

    assert result["filename"] == "payload_.exe"
    assert "/" not in long_result["filename"]
    assert "\\" not in long_result["filename"]
    assert len(long_result["filename"]) == 255
    assert long_result["filename"].endswith(".exe")


def test_scan_service_converts_parser_resource_failures_to_safe_validation(tmp_path: Path) -> None:
    service = ScanService(
        ScanRepository(tmp_path / "scans"),
        FakeModelRepository(),  # type: ignore[arg-type]
        ExhaustedExtractor(),  # type: ignore[arg-type]
        maximum_file_size=1024 * 1024,
    )

    with pytest.raises(ScanValidationError, match="safe parser complexity") as error:
        service.scan("sample.exe", _minimal_pe())

    assert "attacker-controlled" not in str(error.value)


def test_scan_service_rejects_work_when_capacity_is_exhausted(tmp_path: Path) -> None:
    extractor = BlockingExtractor()
    service = ScanService(
        ScanRepository(tmp_path / "scans"),
        FakeModelRepository(),  # type: ignore[arg-type]
        extractor,  # type: ignore[arg-type]
        maximum_file_size=1024 * 1024,
        maximum_concurrent_scans=1,
    )
    with ThreadPoolExecutor(max_workers=1) as executor:
        running = executor.submit(service.scan, "first.exe", _minimal_pe())
        assert extractor.entered.wait(timeout=5)
        with pytest.raises(ScanCapacityError):
            service.scan("second.exe", _minimal_pe())
        extractor.release.set()
        assert running.result(timeout=5)["filename"] == "first.exe"


def test_scan_repository_handles_concurrent_atomic_history_writes(tmp_path: Path) -> None:
    service = ScanService(
        ScanRepository(tmp_path / "scans"),
        FakeModelRepository(),  # type: ignore[arg-type]
        PEFeatureExtractor(),
        maximum_file_size=1024 * 1024,
        maximum_concurrent_scans=16,
    )

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(
            executor.map(
                lambda index: service.scan(f"sample-{index}.exe", _minimal_pe()), range(32)
            )
        )

    assert len({item["id"] for item in results}) == 32
    assert len(service.history(limit=100)) == 32
    assert len(list((tmp_path / "scans").glob("*.json"))) == 32
    assert not list((tmp_path / "scans").glob("*.tmp"))


def test_scan_repository_ignores_corrupt_history_entries(tmp_path: Path) -> None:
    directory = tmp_path / "scans"
    directory.mkdir()
    corrupt_id = "a" * 32
    (directory / f"{corrupt_id}.json").write_text("uploaded binary, not json", encoding="utf-8")
    repository = ScanRepository(directory)

    assert repository.list() == []
    assert repository.get(corrupt_id) is None


def test_scan_routes_create_list_and_retrieve_results(tmp_path: Path) -> None:
    application = create_app()
    service = _service(tmp_path)
    application.dependency_overrides[get_scan_service] = lambda: service
    client = TestClient(application)

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


def test_scan_openapi_preserves_the_multipart_upload_contract() -> None:
    operation = create_app().openapi()["paths"]["/api/v1/scans"]["post"]
    multipart_schema = operation["requestBody"]["content"]["multipart/form-data"]["schema"]
    header_parameters = {
        item["name"]: item for item in operation["parameters"] if item["in"] == "header"
    }

    assert multipart_schema["required"] == ["file"]
    assert multipart_schema["properties"]["file"]["format"] == "binary"
    assert header_parameters["X-Aegis-Scan"]["required"] is True
    assert operation["responses"]["201"]["content"]["application/json"]


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


def test_scan_route_rejects_oversized_file_and_multipart_envelope(tmp_path: Path) -> None:
    maximum_file_size = len(_minimal_pe()) - 1
    settings = BackendSettings(maximum_upload_bytes=maximum_file_size)
    application = create_app(settings)
    service = ScanService(
        ScanRepository(tmp_path / "scans"),
        FakeModelRepository(),  # type: ignore[arg-type]
        PEFeatureExtractor(),
        maximum_file_size=maximum_file_size,
    )
    application.dependency_overrides[get_scan_service] = lambda: service
    client = TestClient(application)

    file_response = client.post(
        "/api/v1/scans",
        headers={"X-Aegis-Scan": "static-pe-v1"},
        files={"file": ("sample.exe", _minimal_pe(), "application/octet-stream")},
    )
    body_response = client.post(
        "/api/v1/scans",
        headers={
            "X-Aegis-Scan": "static-pe-v1",
            "Content-Type": "application/octet-stream",
        },
        content=b"x" * (settings.maximum_scan_request_bytes + 1),
    )
    boundary = b"bounded-test"
    multipart_prefix = (
        b"--"
        + boundary
        + b'\r\nContent-Disposition: form-data; name="file"; filename="sample.exe"\r\n\r\n'
    )
    multipart_suffix = b"\r\n--" + boundary + b"--\r\n"
    streamed_response = client.post(
        "/api/v1/scans",
        headers={
            "X-Aegis-Scan": "static-pe-v1",
            "Content-Type": "multipart/form-data; boundary=bounded-test",
        },
        content=iter(
            [
                multipart_prefix + b"x" * (settings.maximum_scan_request_bytes // 2),
                b"x" * (settings.maximum_scan_request_bytes // 2 + 2) + multipart_suffix,
            ]
        ),
    )

    assert file_response.status_code == 413
    assert body_response.status_code == 413
    assert streamed_response.status_code == 413
    assert service.history() == []


def test_scan_route_accepts_exactly_one_file_part(tmp_path: Path) -> None:
    application = create_app()
    service = _service(tmp_path)
    application.dependency_overrides[get_scan_service] = lambda: service
    client = TestClient(application)

    response = client.post(
        "/api/v1/scans",
        headers={"X-Aegis-Scan": "static-pe-v1"},
        files=[
            ("file", ("one.exe", _minimal_pe(), "application/octet-stream")),
            ("extra", ("two.exe", _minimal_pe(), "application/octet-stream")),
        ],
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Malformed or excessive multipart upload"}
    assert service.history() == []


def test_scan_route_rejects_excess_concurrent_uploads_before_parsing(tmp_path: Path) -> None:
    settings = BackendSettings(maximum_concurrent_scans=1)
    application = create_app(settings)
    extractor = BlockingExtractor()
    service = ScanService(
        ScanRepository(tmp_path / "scans"),
        FakeModelRepository(),  # type: ignore[arg-type]
        extractor,  # type: ignore[arg-type]
        maximum_file_size=1024 * 1024,
        maximum_concurrent_scans=2,
    )
    application.dependency_overrides[get_scan_service] = lambda: service
    first_client = TestClient(application)
    second_client = TestClient(application)

    def post(client: TestClient, filename: str):
        return client.post(
            "/api/v1/scans",
            headers={"X-Aegis-Scan": "static-pe-v1"},
            files={"file": (filename, _minimal_pe(), "application/octet-stream")},
        )

    with ThreadPoolExecutor(max_workers=1) as executor:
        running = executor.submit(post, first_client, "first.exe")
        assert extractor.entered.wait(timeout=5)
        rejected = post(second_client, "second.exe")
        extractor.release.set()
        completed = running.result(timeout=5)

    assert rejected.status_code == 503
    assert rejected.headers["retry-after"] == "1"
    assert completed.status_code == 201
    assert [item["filename"] for item in service.history()] == ["first.exe"]


def test_scan_route_rejects_disallowed_browser_origin_before_scanning(tmp_path: Path) -> None:
    application = create_app()
    service = _service(tmp_path)
    application.dependency_overrides[get_scan_service] = lambda: service
    client = TestClient(application)

    response = client.post(
        "/api/v1/scans",
        headers={"X-Aegis-Scan": "static-pe-v1", "Origin": "https://attacker.example"},
        files={"file": ("sample.exe", _minimal_pe(), "application/octet-stream")},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Cross-origin scan request is not allowed"}
    assert service.history() == []


def test_scan_route_allows_configured_browser_origin(tmp_path: Path) -> None:
    application = create_app()
    service = _service(tmp_path)
    application.dependency_overrides[get_scan_service] = lambda: service
    client = TestClient(application)

    response = client.post(
        "/api/v1/scans",
        headers={"X-Aegis-Scan": "static-pe-v1", "Origin": "http://localhost:3000"},
        files={"file": ("sample.exe", _minimal_pe(), "application/octet-stream")},
    )

    assert response.status_code == 201
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_scan_route_returns_fixed_error_for_unexpected_internal_failure(tmp_path: Path) -> None:
    application = create_app()
    service = ScanService(
        ScanRepository(tmp_path / "scans"),
        FailingModelRepository(),  # type: ignore[arg-type]
        PEFeatureExtractor(),
        maximum_file_size=1024 * 1024,
    )
    application.dependency_overrides[get_scan_service] = lambda: service
    client = TestClient(application)

    response = client.post(
        "/api/v1/scans",
        headers={"X-Aegis-Scan": "static-pe-v1"},
        files={"file": ("sample.exe", _minimal_pe(), "application/octet-stream")},
    )

    assert response.status_code == 500
    assert response.json() == {"detail": "The scan could not be completed safely"}
    assert "sensitive" not in response.text


def test_cors_settings_reject_wildcards_and_normalize_origins() -> None:
    with pytest.raises(ValueError, match="Wildcard"):
        BackendSettings(cors_origins=("*",))

    assert normalize_origin(" HTTPS://EXAMPLE.COM:443/ ") == "https://example.com"


@pytest.mark.parametrize(
    "release_id",
    (
        "sha256:short",
        "sha256:" + "G" * 64,
        "release-v1",
    ),
)
def test_backend_settings_require_canonical_release_digest(release_id: str) -> None:
    with pytest.raises(ValueError, match="analysis_release_id"):
        BackendSettings(analysis_release_id=release_id)
