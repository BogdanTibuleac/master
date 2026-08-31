"""Tests for reproducible EMBER2024 acquisition and vector validation."""

import json
from pathlib import Path

import numpy as np
import pytest

from malware_robustness.ember2024 import (
    FILE_TYPE,
    acquire_dotnet_dataset,
    read_vectorized_subset,
    verify_manifest,
)


def test_acquisition_downloads_selected_subsets_and_restores_directory(tmp_path: Path) -> None:
    """The wrapper requests only the MVP subsets and inventories downloaded files."""
    calls: list[tuple[str, str]] = []
    original_directory = Path.cwd()

    def fake_download(download_dir: str, split: str, file_type: str = "all") -> None:
        calls.append((split, file_type))
        Path(download_dir, f"{split}.jsonl").write_text(split, encoding="utf-8")
        # Reproduce the upstream side effect to ensure the wrapper contains it.
        import os

        os.chdir(download_dir)

    manifest_path = acquire_dotnet_dataset(tmp_path, download_function=fake_download)

    assert Path.cwd() == original_directory
    assert calls == [("train", FILE_TYPE), ("test", FILE_TYPE), ("challenge", "all")]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["splits"] == ["train", "test", "challenge"]
    assert {item["path"] for item in manifest["files"]} == {
        "challenge.jsonl",
        "test.jsonl",
        "train.jsonl",
    }
    verify_manifest(tmp_path)


def test_manifest_verification_detects_changed_file(tmp_path: Path) -> None:
    """Modified dataset content is rejected before vectorization."""

    def fake_download(download_dir: str, split: str, file_type: str = "all") -> None:
        Path(download_dir, f"{split}.jsonl").write_text(file_type, encoding="utf-8")

    acquire_dotnet_dataset(tmp_path, download_function=fake_download)
    (tmp_path / "train.jsonl").write_text("changed", encoding="utf-8")

    with pytest.raises(ValueError, match="mismatch"):
        verify_manifest(tmp_path)


def test_vector_reader_validates_official_array_shapes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Valid official vectors are returned through a small typed interface."""

    class FakeThrember:
        @staticmethod
        def read_vectorized_features(
            dataset_dir: str, subset: str
        ) -> tuple[np.ndarray, np.ndarray]:
            assert dataset_dir == str(tmp_path.resolve())
            assert subset == "train"
            return np.ones((3, 2)), np.array([0, 1, 1])

    monkeypatch.setattr("malware_robustness.ember2024._load_thrember", lambda: FakeThrember())

    vectors = read_vectorized_subset(tmp_path, "train")

    assert vectors.features.shape == (3, 2)
    assert vectors.labels.tolist() == [0, 1, 1]
