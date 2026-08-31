"""Tests for environment-driven production backend settings."""

import pytest

from malware_robustness.core.settings import load_backend_settings


def test_azure_storage_settings_require_an_https_account_url(monkeypatch) -> None:
    monkeypatch.setenv("MALWARE_STORAGE_BACKEND", "azure_blob")
    monkeypatch.delenv("MALWARE_BLOB_ACCOUNT_URL", raising=False)

    with pytest.raises(ValueError, match="MALWARE_BLOB_ACCOUNT_URL"):
        load_backend_settings()

    monkeypatch.setenv("MALWARE_BLOB_ACCOUNT_URL", "http://storage.example.test")
    with pytest.raises(ValueError, match="HTTPS"):
        load_backend_settings()


def test_azure_storage_settings_load_non_secret_identifiers(monkeypatch) -> None:
    monkeypatch.setenv("MALWARE_STORAGE_BACKEND", "azure_blob")
    monkeypatch.setenv("MALWARE_BLOB_ACCOUNT_URL", "https://account.blob.core.windows.net/")
    monkeypatch.setenv("MALWARE_AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000000")
    monkeypatch.setenv("MALWARE_MODEL_BLOB_PREFIX", "/models/2026-08-31/")
    monkeypatch.setenv("MALWARE_CORS_ORIGINS", "https://scanner.example.test")

    settings = load_backend_settings()

    assert settings.storage_backend == "azure_blob"
    assert settings.model_blob_prefix == "models/2026-08-31"
    assert settings.cors_origins == ("https://scanner.example.test",)
