"""Tests for official EMBER2018 ingestion and vectorization."""

import json
from pathlib import Path

import numpy as np
import pytest

from malware_robustness.ember2018 import (
    FEATURE_DIMENSION,
    iter_raw_records,
    iter_vector_batches,
    vectorize_record,
)


def _raw_record(label: int = 1) -> dict[str, object]:
    return {
        "label": label,
        "histogram": [1] * 256,
        "byteentropy": [1] * 256,
        "strings": {
            "numstrings": 1,
            "avlength": 5.0,
            "printabledist": [1] * 96,
            "printables": 96,
            "entropy": 1.0,
            "paths": 0,
            "urls": 0,
            "registry": 0,
            "MZ": 1,
        },
        "general": {
            "size": 10,
            "vsize": 20,
            "has_debug": 0,
            "exports": 0,
            "imports": 1,
            "has_relocations": 0,
            "has_resources": 0,
            "has_signature": 0,
            "has_tls": 0,
            "symbols": 0,
        },
        "header": {
            "coff": {"timestamp": 0, "machine": "I386", "characteristics": []},
            "optional": {
                "subsystem": "WINDOWS_GUI",
                "dll_characteristics": [],
                "magic": "PE32",
                "major_image_version": 0,
                "minor_image_version": 0,
                "major_linker_version": 0,
                "minor_linker_version": 0,
                "major_operating_system_version": 0,
                "minor_operating_system_version": 0,
                "major_subsystem_version": 0,
                "minor_subsystem_version": 0,
                "sizeof_code": 0,
                "sizeof_headers": 0,
                "sizeof_heap_commit": 0,
            },
        },
        "section": {"entry": ".text", "sections": []},
        "imports": {"kernel32.dll": ["CreateFileW"]},
        "exports": [],
        "datadirectories": [],
    }


def test_vectorize_record_matches_official_feature_dimension() -> None:
    """A raw version-2 record maps to the benchmark model's 2,381 inputs."""
    vector = vectorize_record(_raw_record())

    assert vector.shape == (FEATURE_DIMENSION,)
    assert vector.dtype == np.float32
    assert np.isfinite(vector).all()


def test_raw_reader_and_batches_stream_jsonl(tmp_path: Path) -> None:
    """Records are streamed and grouped without loading a complete subset."""
    dataset_directory = tmp_path / "ember2018"
    dataset_directory.mkdir()
    test_path = dataset_directory / "test_features.jsonl"
    records = [_raw_record(0), _raw_record(1), _raw_record(1)]
    test_path.write_text("\n".join(json.dumps(record) for record in records), encoding="utf-8")

    assert [record["label"] for record in iter_raw_records(dataset_directory, "test")] == [
        0,
        1,
        1,
    ]
    batches = list(iter_vector_batches(dataset_directory, "test", batch_size=2))
    assert [features.shape for features, _ in batches] == [
        (2, FEATURE_DIMENSION),
        (1, FEATURE_DIMENSION),
    ]
    assert np.concatenate([labels for _, labels in batches]).tolist() == [0, 1, 1]


def test_raw_reader_rejects_unknown_subset(tmp_path: Path) -> None:
    """Only the official train and test partitions are accepted."""
    with pytest.raises(ValueError, match="train or test"):
        next(iter_raw_records(tmp_path, "validation"))
