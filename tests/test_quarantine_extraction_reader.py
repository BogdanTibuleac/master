"""Tests for exact-generation quarantine readers used by extraction workers."""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import pytest

from malware_robustness.domain.intake import QuarantineReferenceError
from malware_robustness.repositories.quarantine import LocalFilesystemQuarantine


def _minimal_pe() -> bytes:
    content = bytearray(0x100)
    content[:2] = b"MZ"
    struct.pack_into("<I", content, 0x3C, 0x80)
    content[0x80:0x84] = b"PE\0\0"
    return bytes(content)


def test_local_reader_opens_only_the_exact_sealed_generation(tmp_path: Path) -> None:
    quarantine = LocalFilesystemQuarantine(
        tmp_path / "quarantine",
        maximum_object_size=1024 * 1024,
    )
    upload = quarantine.create()
    content = _minimal_pe()
    quarantine.upload(upload, [content[:31], content[31:]])
    sealed = quarantine.seal(
        upload,
        expected_size_bytes=len(content),
        expected_sha256=hashlib.sha256(content).hexdigest(),
    )

    read = quarantine.read_exact(sealed.object_key, sealed.generation)

    assert read.object_key == sealed.object_key
    assert read.object_generation == sealed.generation
    assert read.sample_sha256 == sealed.sha256
    assert read.size_bytes == len(content)
    assert b"".join(read.chunks) == content


def test_local_reader_rejects_forged_or_latest_style_references(tmp_path: Path) -> None:
    quarantine = LocalFilesystemQuarantine(
        tmp_path / "quarantine",
        maximum_object_size=1024,
    )

    with pytest.raises(QuarantineReferenceError):
        quarantine.read_exact("../latest", "latest")
