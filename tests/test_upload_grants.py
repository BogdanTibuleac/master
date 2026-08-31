"""Tests for short-lived local upload capabilities."""

from datetime import UTC, datetime, timedelta

import pytest

from malware_robustness.services.upload_grants import (
    LocalUploadGrantSigner,
    UploadGrantError,
)


def test_grant_is_bound_to_tenant_scan_and_object() -> None:
    current = [datetime(2026, 8, 31, 12, 0, tzinfo=UTC)]
    signer = LocalUploadGrantSigner(
        b"s" * 32,
        time_to_live=timedelta(minutes=5),
        clock=lambda: current[0],
    )
    grant = signer.issue(
        tenant_id="tenant-a",
        scan_id="scan-a",
        object_key="a" * 32,
        generation="b" * 32,
    )
    signer.verify(
        grant.token,
        tenant_id="tenant-a",
        scan_id="scan-a",
        object_key="a" * 32,
        generation="b" * 32,
    )
    with pytest.raises(UploadGrantError, match="does not match"):
        signer.verify(
            grant.token,
            tenant_id="tenant-b",
            scan_id="scan-a",
            object_key="a" * 32,
            generation="b" * 32,
        )


def test_grant_rejects_tampering_and_expiration() -> None:
    current = [datetime(2026, 8, 31, 12, 0, tzinfo=UTC)]
    signer = LocalUploadGrantSigner(
        b"s" * 32,
        time_to_live=timedelta(seconds=30),
        clock=lambda: current[0],
    )
    grant = signer.issue(
        tenant_id="tenant-a",
        scan_id="scan-a",
        object_key="a" * 32,
        generation="b" * 32,
    )
    with pytest.raises(UploadGrantError, match="invalid"):
        signer.verify(
            grant.token[:-1] + ("A" if grant.token[-1] != "A" else "B"),
            tenant_id="tenant-a",
            scan_id="scan-a",
            object_key="a" * 32,
            generation="b" * 32,
        )
    current[0] += timedelta(seconds=31)
    with pytest.raises(UploadGrantError, match="expired"):
        signer.verify(
            grant.token,
            tenant_id="tenant-a",
            scan_id="scan-a",
            object_key="a" * 32,
            generation="b" * 32,
        )
