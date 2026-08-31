"""Tests for experiment configuration validation."""

from pathlib import Path

import pytest

from malware_robustness.config import load_experiment_config


def test_load_experiment_config_reads_baseline_settings() -> None:
    """The checked-in baseline configuration can be loaded as typed settings."""
    config = load_experiment_config(Path("configs/baseline.yaml"))

    assert config.experiment_name == "baseline_lightgbm"
    assert config.data.label_column == "label"
    assert config.decision_threshold == 0.5


def test_load_experiment_config_rejects_invalid_threshold(tmp_path: Path) -> None:
    """Decision thresholds outside the probability range are rejected."""
    invalid_config = tmp_path / "invalid.yaml"
    invalid_config.write_text(
        """
experiment_name: invalid
random_seed: 1
data:
  train_path: train.parquet
  validation_path: validation.parquet
  test_path: test.parquet
  label_column: label
model: {}
evaluation:
  decision_threshold: 1.0
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="decision_threshold"):
        load_experiment_config(invalid_config)
