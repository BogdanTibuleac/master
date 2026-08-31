"""Small composition tests that do not require external infrastructure."""

from __future__ import annotations

from malware_robustness.core.settings import BackendSettings
from malware_robustness.repositories.workflows import InMemoryWorkflowRepository
from malware_robustness.runtime_composition import build_workflow_repository


def test_default_runtime_uses_explicit_in_memory_workflow_adapter() -> None:
    repository = build_workflow_repository(BackendSettings())

    assert isinstance(repository, InMemoryWorkflowRepository)
