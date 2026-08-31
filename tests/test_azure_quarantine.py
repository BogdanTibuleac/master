"""Deterministic security tests for Azure hostile-content quarantine."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import fields, replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from malware_robustness.domain.intake import (
    IntakeValidationError,
    QuarantineConflictError,
    QuarantineReferenceError,
    QuarantineStateError,
    QuarantineUpload,
)
from malware_robustness.repositories.azure_quarantine import AzureBlobQuarantine
from malware_robustness.services.azure_upload_grants import (
    AzureUploadGrantRequest,
    AzureUploadGrantService,
)

NOW = datetime(2026, 8, 31, 10, 15, tzinfo=UTC)


class FakeAzureError(RuntimeError):
    def __init__(self, status_code: int, error_code: str) -> None:
        super().__init__(error_code)
        self.status_code = status_code
        self.error_code = error_code


class FakeDownload:
    def __init__(self, content: bytes, *, chunk_size: int = 29) -> None:
        self._content = content
        self._chunk_size = chunk_size

    def chunks(self):
        for start in range(0, len(self._content), self._chunk_size):
            yield self._content[start : start + self._chunk_size]


class FakeBlobClient:
    def __init__(
        self, container: FakeContainerClient, blob_name: str, version_id: str | None
    ) -> None:
        self._container = container
        self._blob_name = blob_name
        self._version_id = version_id
        self.url = f"https://scanner.blob.test/{container.container_name}/{blob_name}"

    def get_blob_properties(self) -> dict[str, Any]:
        version = self._version()
        return {
            "blob_type": version["blob_type"],
            "size": len(version["content"]),
            "version_id": version["version_id"] if self._container.versioning else None,
            "etag": version["etag"] if self._container.include_etag else None,
        }

    def upload_blob(self, data, **options: Any) -> None:
        self._container.upload_calls.append((self._blob_name, options))
        exists = bool(self._container.blobs.get(self._blob_name))
        if exists and (not options.get("overwrite") or options.get("if_none_match") == "*"):
            raise FakeAzureError(409, "BlobAlreadyExists")
        content = b"".join(data)
        self._container.put(
            self._blob_name,
            content,
            blob_type=options.get("blob_type", "BlockBlob"),
        )

    def download_blob(self, **options: Any) -> FakeDownload:
        assert options == {"max_concurrency": 1}
        version = self._version()
        self._container.downloaded_versions.append(version["version_id"])
        return FakeDownload(version["content"])

    def _version(self) -> dict[str, Any]:
        versions = self._container.blobs.get(self._blob_name, [])
        if not versions:
            raise FakeAzureError(404, "BlobNotFound")
        if self._version_id is None:
            return versions[-1]
        for version in versions:
            if version["version_id"] == self._version_id:
                return version
        raise FakeAzureError(404, "BlobNotFound")


class FakeContainerClient:
    container_name = "private-quarantine"

    def __init__(
        self,
        *,
        public_access: str | None = None,
        versioning: bool = True,
        include_etag: bool = True,
    ) -> None:
        self.public_access = public_access
        self.versioning = versioning
        self.include_etag = include_etag
        self.blobs: dict[str, list[dict[str, Any]]] = {}
        self.upload_calls: list[tuple[str, dict[str, Any]]] = []
        self.downloaded_versions: list[str] = []
        self._sequence = 0

    def get_container_properties(self) -> dict[str, str | None]:
        return {"public_access": self.public_access}

    def get_blob_client(
        self,
        blob: str,
        *,
        snapshot: str | None = None,
        version_id: str | None = None,
    ) -> FakeBlobClient:
        assert snapshot is None
        return FakeBlobClient(self, blob, version_id)

    def list_blobs(self, *, name_starts_with: str, include: list[str]):
        assert include == ["versions"]
        for name, versions in self.blobs.items():
            if name.startswith(name_starts_with):
                for version in versions:
                    yield {"name": name, "version_id": version["version_id"]}

    def put(self, blob_name: str, content: bytes, *, blob_type: str = "BlockBlob") -> str:
        self._sequence += 1
        version_id = f"2026-08-31T10:15:{self._sequence:02d}.0000000Z"
        self.blobs.setdefault(blob_name, []).append(
            {
                "content": content,
                "blob_type": blob_type,
                "version_id": version_id,
                "etag": f'"0xFAKE{self._sequence:08X}"',
            }
        )
        return version_id

    def put_for_upload(
        self, storage: AzureBlobQuarantine, upload: QuarantineUpload, content: bytes
    ) -> str:
        target = storage.upload_target(upload)
        return self.put(target.blob_name, content)

    def only_version(self) -> dict[str, Any]:
        assert len(self.blobs) == 1
        versions = next(iter(self.blobs.values()))
        assert len(versions) == 1
        return versions[0]


class FakeSigner:
    def __init__(self, *, override_url: str | None = None) -> None:
        self.requests: list[AzureUploadGrantRequest] = []
        self._override_url = override_url

    def sign(self, request: AzureUploadGrantRequest) -> str:
        self.requests.append(request)
        return self._override_url or f"{request.blob_url}?sv=fake&sp=cw&sig=delegated"


def _minimal_pe(*, pe_offset: int = 0x80, suffix: bytes = b"") -> bytes:
    content = bytearray(max(0x100, pe_offset + 4))
    content[:2] = b"MZ"
    struct.pack_into("<I", content, 0x3C, pe_offset)
    content[pe_offset : pe_offset + 4] = b"PE\0\0"
    return bytes(content) + suffix


def _storage(
    container: FakeContainerClient | None = None, *, maximum: int = 1024 * 1024
) -> tuple[AzureBlobQuarantine, FakeContainerClient]:
    client = container or FakeContainerClient()
    return (
        AzureBlobQuarantine(client, maximum_object_size=maximum, clock=lambda: NOW),
        client,
    )


def test_create_allocates_opaque_target_in_verified_private_container() -> None:
    storage, _ = _storage()

    first = storage.create()
    second = storage.create()
    target = storage.upload_target(first)

    assert first.object_key != second.object_key
    assert first.generation != second.generation
    assert len(first.object_key) == len(first.generation) == 32
    assert set(first.object_key + first.generation) <= set("0123456789abcdef")
    assert target.container_name == "private-quarantine"
    assert target.blob_name.split("/") == [
        "objects",
        first.object_key[:2],
        first.object_key,
        f"{first.generation}.blob",
    ]
    assert target.blob_url.startswith("https://scanner.blob.test/private-quarantine/")
    assert "?" not in target.blob_url


def test_direct_upload_grant_is_short_lived_create_only_and_credential_free() -> None:
    storage, _ = _storage()
    signer = FakeSigner()
    service = AzureUploadGrantService(
        storage, signer, grant_ttl=timedelta(minutes=5), clock=lambda: NOW
    )

    capability = service.create()
    request = signer.requests[0]
    response = capability.to_dict()

    assert request.starts_at == NOW
    assert request.expires_at == NOW + timedelta(minutes=5)
    assert request.https_only is True
    assert request.allow_overwrite is False
    assert request.permissions.create is True
    assert request.permissions.write is True
    assert not any(
        getattr(request.permissions, name)
        for name in ("read", "add", "delete", "list", "tag", "move", "permanent_delete")
    )
    assert capability.method == "PUT"
    assert capability.headers["If-None-Match"] == "*"
    assert capability.headers["x-ms-blob-type"] == "BlockBlob"
    assert capability.expires_at_utc == "2026-08-31T10:20:00+00:00"
    assert response["object_key"] == capability.upload.object_key
    assert "account_key" not in response and "credential" not in response
    assert {field.name for field in fields(request)}.isdisjoint(
        {"account_key", "credential", "user_delegation_key"}
    )


@pytest.mark.parametrize(
    "signed_url",
    [
        "http://scanner.blob.test/private-quarantine/object?sig=x",
        "https://attacker.test/private-quarantine/object?sig=x",
        "https://scanner.blob.test/private-quarantine/object",
        "https://scanner.blob.test/private-quarantine/object?sig=x#fragment",
    ],
)
def test_grant_service_rejects_unsafe_signer_output(signed_url: str) -> None:
    storage, _ = _storage()
    service = AzureUploadGrantService(
        storage, FakeSigner(override_url=signed_url), clock=lambda: NOW
    )

    with pytest.raises(QuarantineStateError, match="unsafe target"):
        service.create()


def test_grant_ttl_is_bounded_and_clock_must_be_aware() -> None:
    storage, _ = _storage()
    with pytest.raises(ValueError, match="15 minutes"):
        AzureUploadGrantService(storage, FakeSigner(), grant_ttl=timedelta(hours=1))

    service = AzureUploadGrantService(storage, FakeSigner(), clock=lambda: datetime(2026, 8, 31))
    with pytest.raises(QuarantineStateError, match="aware"):
        service.create()


def test_server_upload_is_streamed_conditional_and_write_once() -> None:
    storage, container = _storage()
    upload = storage.create()
    content = _minimal_pe(suffix=b"streamed")

    receipt = storage.upload(upload, [content[:17], memoryview(content[17:])])

    assert receipt.size_bytes == len(content)
    assert receipt.sha256 == hashlib.sha256(content).hexdigest()
    _, options = container.upload_calls[0]
    assert options["blob_type"] == "BlockBlob"
    assert options["overwrite"] is False
    assert options["if_none_match"] == "*"
    assert options["max_concurrency"] == 1
    with pytest.raises(QuarantineConflictError, match="write-once"):
        storage.upload(upload, [b"replacement"])
    with pytest.raises(QuarantineConflictError, match="write-once"):
        storage.upload_target(upload)


@pytest.mark.parametrize(
    "chunks,message",
    [
        ([b"", bytearray()], "empty"),
        ([b"MZ", "not-bytes"], "must be bytes"),
        ([b"a" * 200, b"b" * 101], "size limit"),
    ],
)
def test_server_upload_rejects_invalid_streams(chunks: list[Any], message: str) -> None:
    storage, _ = _storage(maximum=300)
    upload = storage.create()

    with pytest.raises(IntakeValidationError, match=message):
        storage.upload(upload, chunks)


def test_seal_hashes_bytes_pins_version_and_exact_read_revalidates_integrity() -> None:
    storage, container = _storage()
    upload = storage.create()
    content = _minimal_pe(suffix=b"direct-upload")
    version_id = container.put_for_upload(storage, upload, content)

    sealed = storage.seal(
        upload,
        expected_size_bytes=len(content),
        expected_sha256=hashlib.sha256(content).hexdigest().upper(),
    )

    assert sealed.object_key == upload.object_key
    assert sealed.generation.startswith("az1.")
    assert sealed.generation != upload.generation
    assert sealed.size_bytes == len(content)
    assert sealed.sha256 == hashlib.sha256(content).hexdigest()
    assert sealed.format == "pe"
    assert sealed.sealed_at_utc == NOW.isoformat()
    assert b"".join(storage.stream_sealed(sealed, chunk_size=17)) == content
    assert container.downloaded_versions and set(container.downloaded_versions) == {version_id}


@pytest.mark.parametrize(
    "content,message",
    [
        (b"MZ" + b"\0" * 20, "truncated DOS header"),
        (b"ZZ" + b"\0" * 126, "missing MZ header"),
        (_minimal_pe().replace(b"PE\0\0", b"NOPE", 1), "invalid PE signature"),
    ],
)
def test_seal_detects_supported_content_from_bounded_bytes(content: bytes, message: str) -> None:
    storage, container = _storage()
    upload = storage.create()
    container.put_for_upload(storage, upload, content)

    with pytest.raises(IntakeValidationError, match=message):
        storage.seal(upload)


def test_seal_rejects_checksum_size_and_oversized_blob() -> None:
    content = _minimal_pe()
    storage, container = _storage(maximum=len(content))
    upload = storage.create()
    container.put_for_upload(storage, upload, content)

    with pytest.raises(IntakeValidationError, match="checksum"):
        storage.seal(upload, expected_sha256="0" * 64)
    with pytest.raises(IntakeValidationError, match="expected size"):
        storage.seal(upload, expected_size_bytes=len(content) - 1)

    oversized_storage, oversized_container = _storage(maximum=len(content) - 1)
    oversized_upload = oversized_storage.create()
    oversized_container.put_for_upload(oversized_storage, oversized_upload, content)
    with pytest.raises(IntakeValidationError, match="size limit") as error:
        oversized_storage.seal(oversized_upload)
    assert error.value.status_code == 413


@pytest.mark.parametrize(
    "container,message",
    [
        (FakeContainerClient(versioning=False), "version ID"),
        (FakeContainerClient(include_etag=False), "ETag"),
    ],
)
def test_seal_rejects_missing_immutable_identity(
    container: FakeContainerClient, message: str
) -> None:
    storage, _ = _storage(container)
    upload = storage.create()
    container.put_for_upload(storage, upload, _minimal_pe())

    with pytest.raises(QuarantineStateError, match=message):
        storage.seal(upload)


def test_seal_rejects_non_block_blob_and_any_overwrite_history() -> None:
    storage, container = _storage()
    unsupported = storage.create()
    target = storage.upload_target(unsupported)
    container.put(target.blob_name, _minimal_pe(), blob_type="AppendBlob")
    with pytest.raises(IntakeValidationError, match="block blob"):
        storage.seal(unsupported)

    overwritten = storage.create()
    overwrite_target = storage.upload_target(overwritten)
    container.put(overwrite_target.blob_name, _minimal_pe(suffix=b"first"))
    container.put(overwrite_target.blob_name, _minimal_pe(suffix=b"replacement"))
    with pytest.raises(QuarantineConflictError, match="overwritten"):
        storage.seal(overwritten)


def test_sealed_read_rejects_etag_change_and_content_tampering() -> None:
    storage, container = _storage()
    upload = storage.create()
    content = _minimal_pe(suffix=b"original")
    container.put_for_upload(storage, upload, content)
    sealed = storage.seal(upload)

    version = container.only_version()
    original_etag = version["etag"]
    version["etag"] = '"different"'
    with pytest.raises(QuarantineStateError, match="identity changed"):
        list(storage.stream_sealed(sealed))

    version["etag"] = original_etag
    version["content"] = _minimal_pe(suffix=b"tampered")
    with pytest.raises(QuarantineStateError, match="integrity"):
        b"".join(storage.stream_sealed(sealed))


def test_public_container_and_unverifiable_privacy_are_rejected() -> None:
    with pytest.raises(QuarantineStateError, match="public access disabled"):
        _storage(FakeContainerClient(public_access="blob"))

    class MissingPrivacyContainer(FakeContainerClient):
        def get_container_properties(self) -> dict[str, str]:
            return {"etag": "container"}

    with pytest.raises(QuarantineStateError, match="privacy could not be verified"):
        _storage(MissingPrivacyContainer())


@pytest.mark.parametrize(
    "object_key,generation",
    [
        ("../outside", "a" * 32),
        ("a" * 31, "b" * 32),
        ("A" * 32, "b" * 32),
        ("a" * 32, "..\\outside"),
    ],
)
def test_forged_upload_references_cannot_create_traversal_keys(
    object_key: str, generation: str
) -> None:
    storage, container = _storage()
    forged = QuarantineUpload(object_key, generation, storage.maximum_object_size)

    with pytest.raises(QuarantineReferenceError):
        storage.upload_target(forged)
    assert container.blobs == {}


def test_sealed_identity_is_tamper_evident_and_cannot_select_another_version() -> None:
    storage, container = _storage()
    upload = storage.create()
    container.put_for_upload(storage, upload, _minimal_pe())
    sealed = storage.seal(upload)

    forged = replace(sealed, generation=sealed.generation[:-1] + "!")
    with pytest.raises(QuarantineReferenceError, match="version identity"):
        list(storage.stream_sealed(forged))
