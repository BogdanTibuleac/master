"""Tests for identity-backed Azure Blob persistence adapters."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace

import lightgbm as lgb
import numpy as np
import pytest

from malware_robustness.domain.scans import ModelUnavailableError
from malware_robustness.repositories.azure_blob import (
    AzureBlobHardenedModelRepository,
    AzureBlobScanRepository,
)


class FakeDownload:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def readall(self) -> bytes:
        return self.payload


class FakeBlob:
    def __init__(self, name: str, payloads: dict[str, bytes]) -> None:
        self.name = name
        self.payloads = payloads

    def download_blob(self) -> FakeDownload:
        if self.name not in self.payloads:
            error = RuntimeError("not found")
            error.status_code = 404  # type: ignore[attr-defined]
            raise error
        return FakeDownload(self.payloads[self.name])

    def get_blob_properties(self):
        return SimpleNamespace(etag=f'etag-"{len(self.payloads[self.name])}"')


class FakeContainer:
    def __init__(self, payloads: dict[str, bytes] | None = None) -> None:
        self.payloads = payloads or {}

    def upload_blob(self, *, name: str, data: bytes, overwrite: bool, metadata: dict) -> None:
        assert overwrite is False
        assert metadata == {"record_type": "scan_metadata"}
        self.payloads[name] = data

    def get_blob_client(self, name: str) -> FakeBlob:
        return FakeBlob(name, self.payloads)

    def download_blob(self, name: str) -> FakeDownload:
        return FakeDownload(self.payloads[name])

    def list_blobs(self):
        now = datetime.now(UTC)
        return [SimpleNamespace(name=name, last_modified=now) for name in self.payloads]

    def get_container_properties(self) -> dict:
        return {}


def test_blob_scan_repository_persists_only_serialized_metadata() -> None:
    container = FakeContainer()
    repository = AzureBlobScanRepository(container)
    record = SimpleNamespace(
        id="a" * 32,
        to_dict=lambda: {"id": "a" * 32, "binary_retained": False},
    )

    repository.save(record)  # type: ignore[arg-type]

    payload = container.payloads[f"{'a' * 32}.json"]
    assert json.loads(payload) == {"id": "a" * 32, "binary_retained": False}
    assert repository.get("a" * 32)["binary_retained"] is False
    assert repository.list(limit=1)[0]["id"] == "a" * 32
    assert repository.is_ready() is True


def test_blob_model_repository_downloads_and_validates_versioned_artifacts(tmp_path) -> None:
    features = np.array([[0.0, 0.0], [0.0, 1.0], [1.0, 0.0], [1.0, 1.0]])
    labels = np.array([0, 0, 1, 1])
    model = lgb.train(
        {
            "objective": "binary",
            "verbose": -1,
            "min_data_in_leaf": 1,
            "num_threads": 1,
            "force_col_wise": True,
        },
        lgb.Dataset(features, label=labels),
        num_boost_round=1,
    )
    container = FakeContainer(
        {
            "releases/model-v1/model.txt": model.model_to_string().encode("utf-8"),
            "releases/model-v1/metrics.json": json.dumps(
                {"experiment_name": "test", "decision_threshold": 0.5}
            ).encode("utf-8"),
        }
    )
    repository = AzureBlobHardenedModelRepository(
        container,
        tmp_path / "model-cache",
        "releases/model-v1",
    )

    assert repository.is_ready() is True
    assert (tmp_path / "model-cache" / "model.txt").is_file()
    score = repository.score(np.array([1.0, 0.0]))
    assert 0.0 <= score.malware_probability <= 1.0


def test_blob_model_repository_maps_missing_release_to_service_unavailable(tmp_path) -> None:
    repository = AzureBlobHardenedModelRepository(
        FakeContainer(),
        tmp_path / "model-cache",
        "releases/missing",
    )

    assert repository.is_ready() is False
    with pytest.raises(ModelUnavailableError, match="unavailable"):
        repository.score(np.array([1.0, 0.0]))
