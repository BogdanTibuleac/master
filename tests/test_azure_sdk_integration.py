"""SDK-free tests for managed-identity Azure SAS request composition."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from malware_robustness.integrations.azure_blob import AzureUserDelegationSasSigner
from malware_robustness.services.azure_upload_grants import (
    AzureBlobUploadPermissions,
    AzureUploadGrantRequest,
)


class FakeService:
    account_name = "privateaccount"

    def __init__(self) -> None:
        self.key_requests: list[dict[str, object]] = []

    def get_user_delegation_key(self, **kwargs):
        self.key_requests.append(kwargs)
        return "delegation-key"


class FakePermissions:
    def __init__(self, **kwargs) -> None:
        self.values = kwargs


def test_signer_requests_managed_identity_key_and_create_write_only_sas() -> None:
    service = FakeService()
    generated: list[dict[str, object]] = []

    def generate(**kwargs) -> str:
        generated.append(kwargs)
        return "sv=1&sp=cw&sig=opaque"

    starts = datetime(2026, 8, 31, 20, 0, tzinfo=UTC)
    request = AzureUploadGrantRequest(
        container_name="private-quarantine",
        blob_name="objects/aa/object/generation.blob",
        blob_url=(
            "https://privateaccount.blob.core.windows.net/"
            "private-quarantine/objects/aa/object/generation.blob"
        ),
        starts_at=starts,
        expires_at=starts + timedelta(minutes=10),
        permissions=AzureBlobUploadPermissions(),
        https_only=True,
        allow_overwrite=False,
    )

    signed = AzureUserDelegationSasSigner(
        service,
        sas_generator=generate,
        permissions_factory=FakePermissions,
    ).sign(request)

    assert signed == f"{request.blob_url}?sv=1&sp=cw&sig=opaque"
    assert service.key_requests == [
        {
            "key_start_time": request.starts_at,
            "key_expiry_time": request.expires_at,
        }
    ]
    assert generated[0]["account_name"] == service.account_name
    assert generated[0]["container_name"] == request.container_name
    assert generated[0]["blob_name"] == request.blob_name
    assert generated[0]["protocol"] == "https"
    assert generated[0]["permission"].values == {"create": True, "write": True}
