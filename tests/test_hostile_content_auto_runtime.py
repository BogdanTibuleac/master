"""HTTP-to-isolated-extractor integration for explicit local auto-processing mode."""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import lightgbm as lgb
import numpy as np
from fastapi.testclient import TestClient

from malware_robustness.api.app import create_app
from malware_robustness.api.dependencies import (
    get_hostile_content_service,
    get_intake_service,
    get_local_hostile_runtime,
    get_quarantine_storage,
    get_result_repository,
    get_upload_grant_signer,
    get_workflow_repository,
    get_workflow_service,
)
from malware_robustness.core.settings import BackendSettings
from malware_robustness.domain.analysis import EMBER_V2_FEATURE_COUNT

_CACHED_DEPENDENCIES = (
    get_hostile_content_service,
    get_intake_service,
    get_local_hostile_runtime,
    get_quarantine_storage,
    get_result_repository,
    get_upload_grant_signer,
    get_workflow_repository,
    get_workflow_service,
)


def _minimal_pe() -> bytes:
    content = bytearray(0x400)
    content[:2] = b"MZ"
    struct.pack_into("<I", content, 0x3C, 0x80)
    content[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", content, 0x84, 0x14C, 1, 1_700_000_000, 0, 0, 0xE0, 0x0102)
    optional = 0x98
    struct.pack_into("<H", content, optional, 0x10B)
    section = optional + 0xE0
    content[section : section + 8] = b".text\0\0\0"
    struct.pack_into(
        "<IIIIIIHHI",
        content,
        section + 8,
        0x100,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    return bytes(content)


def _write_model(artifact_root: Path) -> None:
    output = artifact_root / "robust_lightgbm"
    output.mkdir(parents=True)
    features = np.zeros((6, EMBER_V2_FEATURE_COUNT), dtype=np.float32)
    features[1, 0] = 1
    features[3, 1] = 1
    features[5, 2] = 1
    labels = np.asarray([0, 1, 0, 1, 0, 1], dtype=np.int8)
    dataset = lgb.Dataset(features, label=labels, free_raw_data=False)
    model = lgb.train(
        {
            "objective": "binary",
            "verbosity": -1,
            "num_threads": 1,
            "min_data_in_leaf": 1,
            "min_data_in_bin": 1,
            "feature_pre_filter": False,
        },
        dataset,
        num_boost_round=1,
    )
    model.save_model(output / "model.txt")


def test_seal_background_pass_completes_and_exposes_immutable_manifest(
    tmp_path: Path,
) -> None:
    for dependency in _CACHED_DEPENDENCIES:
        dependency.cache_clear()
    artifact_root = tmp_path / "artifacts"
    _write_model(artifact_root)
    settings = BackendSettings(
        data_directory=tmp_path / "raw",
        artifact_directory=artifact_root,
        scan_directory=tmp_path / "scans",
        quarantine_directory=tmp_path / "quarantine",
        result_directory=tmp_path / "results",
        maximum_upload_bytes=1024 * 1024,
        upload_grant_secret="local-runtime-test-secret",
        runtime_auto_process=True,
        cors_origins=("http://localhost:3000",),
    )
    content = _minimal_pe()

    try:
        with TestClient(create_app(settings)) as client:
            created_response = client.post(
                "/api/v1/scans",
                headers={
                    "Idempotency-Key": "auto-runtime-request",
                    "X-Aegis-Scan": "hostile-content-v1",
                },
                json={
                    "filename": "sample.exe",
                    "size_bytes": len(content),
                    "content_type": "application/octet-stream",
                },
            )
            assert created_response.status_code == 201, created_response.text
            created = created_response.json()
            uploaded = client.put(
                created["upload"]["url"],
                headers=created["upload"]["headers"],
                content=content,
            )
            assert uploaded.status_code == 201, uploaded.text

            sealed = client.post(
                f"/api/v1/scans/{created['scan']['id']}:seal",
                json={
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size_bytes": len(content),
                    "object_generation": uploaded.headers["x-aegis-object-generation"],
                },
            )
            assert sealed.status_code == 200, sealed.text

            completed = client.get(f"/api/v1/scans/{created['scan']['id']}")
            assert completed.status_code == 200, completed.text
            payload = completed.json()
            assert payload["status"] == "complete"
            assert payload["progress_percent"] == 100
            assert payload["result"]["manifest_schema"] == "static-pe-result/v1"
            assert payload["result"]["decision"]["label"] in {
                "likely_benign",
                "needs_review",
                "likely_malicious",
                "high_risk",
                "inconclusive",
            }
            assert payload["result"]["executed"] is False
            assert not list((tmp_path / "results").rglob("*.exe"))
    finally:
        for dependency in _CACHED_DEPENDENCIES:
            dependency.cache_clear()
