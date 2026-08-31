"""Security-focused tests for the hostile-content quarantine intake domain."""

from __future__ import annotations

import hashlib
import os
import struct
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest
from pydantic import ValidationError

from malware_robustness.domain.intake import (
    IntakeValidationError,
    QuarantineConflictError,
    QuarantineReferenceError,
    QuarantineStateError,
    QuarantineUpload,
)
from malware_robustness.repositories.quarantine import LocalFilesystemQuarantine
from malware_robustness.schemas.intake import IntakeSealRequest
from malware_robustness.services.intake import IntakeService


def _minimal_pe(*, pe_offset: int = 0x80, suffix: bytes = b"") -> bytes:
    content = bytearray(max(0x100, pe_offset + 4))
    content[:2] = b"MZ"
    struct.pack_into("<I", content, 0x3C, pe_offset)
    content[pe_offset : pe_offset + 4] = b"PE\0\0"
    return bytes(content) + suffix


def _service(tmp_path: Path, *, maximum: int = 1024 * 1024) -> IntakeService:
    return IntakeService(
        LocalFilesystemQuarantine(tmp_path / "private-quarantine", maximum_object_size=maximum)
    )


def test_create_uses_opaque_server_generated_identity_and_private_paths(tmp_path: Path) -> None:
    service = _service(tmp_path)

    first = service.create()
    second = service.create()

    assert first.object_key != second.object_key
    assert first.generation != second.generation
    assert len(first.object_key) == len(first.generation) == 32
    assert set(first.object_key) <= set("0123456789abcdef")
    assert "/" not in first.object_key and "\\" not in first.object_key
    assert "private-quarantine" not in repr(first)
    if os.name != "nt":
        root_mode = (tmp_path / "private-quarantine").stat().st_mode & 0o777
        object_dir = tmp_path / "private-quarantine" / first.object_key[:2] / first.object_key
        assert root_mode == 0o700
        assert object_dir.stat().st_mode & 0o777 == 0o700


def test_upload_is_bounded_streamed_atomic_and_write_once(tmp_path: Path) -> None:
    service = _service(tmp_path)
    upload = service.create()
    content = _minimal_pe(suffix=b"streamed")

    receipt = service.upload(upload, [content[:17], memoryview(content[17:100]), content[100:]])

    assert receipt.size_bytes == len(content)
    assert receipt.sha256 == hashlib.sha256(content).hexdigest()
    with pytest.raises(QuarantineConflictError, match="write-once|progress or complete"):
        service.upload(upload, [b"replacement"])
    object_dir = tmp_path / "private-quarantine" / upload.object_key[:2] / upload.object_key
    assert not list(object_dir.glob("*.tmp"))
    assert len(list(object_dir.glob("*.object"))) == 1


def test_failed_or_oversized_upload_cleans_partial_data_and_can_retry(tmp_path: Path) -> None:
    service = _service(tmp_path, maximum=300)
    upload = service.create()

    with pytest.raises(IntakeValidationError, match="size limit") as error:
        service.upload(upload, [b"a" * 200, b"b" * 101])
    assert error.value.status_code == 413

    object_dir = tmp_path / "private-quarantine" / upload.object_key[:2] / upload.object_key
    assert not list(object_dir.glob("*.tmp"))
    assert not list(object_dir.glob("*.object"))
    receipt = service.upload(upload, [_minimal_pe()])
    assert receipt.size_bytes == len(_minimal_pe())


def test_upload_rejects_empty_and_non_byte_chunks_without_leaving_files(tmp_path: Path) -> None:
    service = _service(tmp_path)
    empty_upload = service.create()
    invalid_upload = service.create()

    with pytest.raises(IntakeValidationError, match="empty"):
        service.upload(empty_upload, [b"", bytearray()])
    with pytest.raises(IntakeValidationError, match="must be bytes"):
        service.upload(invalid_upload, [b"MZ", "not bytes"])  # type: ignore[list-item]

    assert not list((tmp_path / "private-quarantine").rglob("*.object"))
    assert not list((tmp_path / "private-quarantine").rglob("*.tmp"))


@pytest.mark.parametrize(
    "object_key,generation",
    [
        ("../outside", "a" * 32),
        ("a" * 31, "b" * 32),
        ("A" * 32, "b" * 32),
        ("a" * 32, "..\\outside"),
    ],
)
def test_references_cannot_traverse_or_escape_quarantine(
    tmp_path: Path, object_key: str, generation: str
) -> None:
    service = _service(tmp_path)
    forged = QuarantineUpload(object_key, generation, 1024 * 1024)

    with pytest.raises(QuarantineReferenceError):
        service.upload(forged, [_minimal_pe()])

    assert not (tmp_path / "outside").exists()


def test_capability_policy_and_generation_must_match_persisted_control(tmp_path: Path) -> None:
    service = _service(tmp_path)
    upload = service.create()

    with pytest.raises(QuarantineReferenceError, match="policy"):
        service.upload(replace(upload, maximum_size_bytes=upload.maximum_size_bytes + 1), [b"x"])
    with pytest.raises((QuarantineReferenceError, QuarantineStateError)):
        service.upload(replace(upload, generation="f" * 32), [b"x"])


def test_seal_restreams_hashes_and_returns_byte_free_immutable_descriptor(tmp_path: Path) -> None:
    service = _service(tmp_path)
    upload = service.create()
    content = _minimal_pe(suffix=b"content-after-header")
    receipt = service.upload(upload, [content])

    sealed = service.seal(
        upload,
        expected_size_bytes=receipt.size_bytes,
        expected_sha256=receipt.sha256.upper(),
    )
    message = service.workflow_message(sealed)

    assert sealed.sha256 == hashlib.sha256(content).hexdigest()
    assert sealed.size_bytes == len(content)
    assert sealed.format == "pe"
    assert set(message) == {
        "object_key",
        "generation",
        "size_bytes",
        "sha256",
        "format",
        "sealed_at_utc",
    }
    assert not any(isinstance(value, (bytes, bytearray, memoryview)) for value in message.values())
    assert b"".join(service.stream_sealed(sealed, chunk_size=31)) == content
    with pytest.raises(FrozenInstanceError):
        sealed.sha256 = "0" * 64  # type: ignore[misc]


def test_unsealed_objects_cannot_be_read(tmp_path: Path) -> None:
    service = _service(tmp_path)
    upload = service.create()
    service.upload(upload, [_minimal_pe()])
    fake_sealed = replace(
        service.seal(upload),
        generation="e" * 32,
    )

    with pytest.raises((QuarantineReferenceError, QuarantineStateError)):
        list(service.stream_sealed(fake_sealed))

    fresh = service.create()
    service.upload(fresh, [_minimal_pe()])
    unsealed_descriptor = replace(
        fake_sealed, object_key=fresh.object_key, generation=fresh.generation
    )
    with pytest.raises(QuarantineStateError):
        list(service.stream_sealed(unsealed_descriptor))


@pytest.mark.parametrize(
    "content,message",
    [
        (b"MZ" + b"\0" * 20, "truncated DOS header"),
        (b"ZZ" + b"\0" * 126, "missing MZ header"),
        (_minimal_pe(pe_offset=64).replace(b"PE\0\0", b"NOPE", 1), "invalid PE signature"),
    ],
)
def test_seal_detects_pe_from_bytes_not_filename_or_metadata(
    tmp_path: Path, content: bytes, message: str
) -> None:
    service = _service(tmp_path)
    upload = service.create()
    service.upload(upload, [content])

    with pytest.raises(IntakeValidationError, match=message):
        service.seal(upload)


def test_seal_rejects_signature_offset_outside_object(tmp_path: Path) -> None:
    service = _service(tmp_path)
    upload = service.create()
    content = bytearray(128)
    content[:2] = b"MZ"
    struct.pack_into("<I", content, 0x3C, 10_000)
    service.upload(upload, [content])

    with pytest.raises(IntakeValidationError, match="outside"):
        service.seal(upload)


@pytest.mark.parametrize(
    "expected_size,digest,message",
    [
        (1, None, "size"),
        (None, "0" * 64, "checksum"),
        (None, "not-a-digest", "SHA-256"),
        (0, None, "positive"),
    ],
)
def test_seal_validates_optional_expected_integrity(
    tmp_path: Path, expected_size: int | None, digest: str | None, message: str
) -> None:
    service = _service(tmp_path)
    upload = service.create()
    service.upload(upload, [_minimal_pe()])

    with pytest.raises(IntakeValidationError, match=message):
        service.seal(upload, expected_size_bytes=expected_size, expected_sha256=digest)


def test_failed_seal_does_not_publish_and_allows_corrected_retry(tmp_path: Path) -> None:
    service = _service(tmp_path)
    upload = service.create()
    content = _minimal_pe()
    service.upload(upload, [content])

    with pytest.raises(IntakeValidationError, match="checksum"):
        service.seal(upload, expected_sha256="0" * 64)
    object_dir = tmp_path / "private-quarantine" / upload.object_key[:2] / upload.object_key
    assert not list(object_dir.glob("*.sealed.json"))
    assert not list(object_dir.glob("*.seal.claim"))

    sealed = service.seal(upload, expected_sha256=hashlib.sha256(content).hexdigest())
    assert sealed.sha256 == hashlib.sha256(content).hexdigest()


def test_duplicate_sealing_is_race_safe_and_cannot_overwrite_result(tmp_path: Path) -> None:
    service = _service(tmp_path)
    upload = service.create()
    service.upload(upload, [_minimal_pe(suffix=b"race")])

    def attempt_seal():
        try:
            return service.seal(upload)
        except QuarantineConflictError as error:
            return error

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: attempt_seal(), range(8)))

    sealed_results = [item for item in results if not isinstance(item, Exception)]
    conflicts = [item for item in results if isinstance(item, QuarantineConflictError)]
    assert len(sealed_results) == 1
    assert len(conflicts) == 7
    object_dir = tmp_path / "private-quarantine" / upload.object_key[:2] / upload.object_key
    assert len(list(object_dir.glob("*.sealed.json"))) == 1


def test_post_seal_tampering_is_detected_before_reading(tmp_path: Path) -> None:
    service = _service(tmp_path)
    upload = service.create()
    service.upload(upload, [_minimal_pe()])
    sealed = service.seal(upload)
    object_path = next(
        (tmp_path / "private-quarantine" / upload.object_key[:2] / upload.object_key).glob(
            "*.object"
        )
    )
    object_path.write_bytes(_minimal_pe(suffix=b"tampered"))

    with pytest.raises(QuarantineStateError, match="modified"):
        list(service.stream_sealed(sealed))


def test_seal_schema_rejects_invalid_integrity_metadata() -> None:
    request = IntakeSealRequest(expected_size_bytes=12, expected_sha256="A" * 64)
    assert request.expected_size_bytes == 12

    with pytest.raises(ValidationError):
        IntakeSealRequest(expected_size_bytes=-1, expected_sha256="not-sha256")
