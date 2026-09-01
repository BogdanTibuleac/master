"""Small composition tests that do not require external infrastructure."""

from __future__ import annotations

import pytest

from malware_robustness.core.settings import BackendSettings
from malware_robustness.repositories.workflows import InMemoryWorkflowRepository
from malware_robustness.runtime_composition import build_workflow_repository


def test_default_runtime_uses_explicit_in_memory_workflow_adapter() -> None:
    repository = build_workflow_repository(BackendSettings())

    assert isinstance(repository, InMemoryWorkflowRepository)


def test_hostile_extraction_requires_an_explicit_safe_or_development_runner() -> None:
    with pytest.raises(ValueError, match="requires an explicitly configured extractor"):
        BackendSettings(runtime_auto_process=True)
    with pytest.raises(ValueError, match="development-only"):
        BackendSettings(extractor_runner="process")
    with pytest.raises(ValueError, match="docker or nerdctl"):
        BackendSettings(extractor_container_cli="podman")


def test_container_settings_accept_a_local_immutable_image_identity() -> None:
    digest = "sha256:" + "a" * 64

    settings = BackendSettings(
        extractor_runner="container",
        extractor_image_digest=digest,
        extractor_image_reference=digest,
        extractor_container_cli="nerdctl",
    )

    assert settings.extractor_image_reference == digest
