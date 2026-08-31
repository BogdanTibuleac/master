from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from malware_robustness.config import DataConfig, ExperimentConfig
from malware_robustness.modeling import evaluate_binary_classifier, train_baseline


def test_evaluate_binary_classifier_calculates_expected_metrics() -> None:
    metrics = evaluate_binary_classifier([0, 0, 1, 1], np.array([0.1, 0.6, 0.8, 0.9]))

    assert metrics.accuracy == 0.75
    assert metrics.true_negatives == 1
    assert metrics.false_positives == 1
    assert metrics.false_negatives == 0
    assert metrics.true_positives == 2
    assert metrics.roc_auc == 1.0


def test_evaluate_binary_classifier_rejects_invalid_probabilities() -> None:
    with pytest.raises(ValueError, match="between 0 and 1"):
        evaluate_binary_classifier([0, 1], np.array([0.2, 1.1]))


def test_train_baseline_writes_loadable_artifacts(tmp_path: Path) -> None:
    rng = np.random.default_rng(42)
    paths = []
    for name, size in (("train", 160), ("validation", 60), ("test", 60)):
        first = rng.normal(size=size)
        second = rng.normal(size=size)
        table = pd.DataFrame({"first": first, "second": second, "label": (first + second > 0)})
        path = tmp_path / f"{name}.csv"
        table.to_csv(path, index=False)
        paths.append(path)

    config = ExperimentConfig(
        experiment_name="test_baseline",
        random_seed=42,
        data=DataConfig(paths[0], paths[1], paths[2], "label"),
        model={"objective": "binary", "n_estimators": 60, "learning_rate": 0.1},
        decision_threshold=0.5,
    )
    result = train_baseline(config, tmp_path / "artifacts")

    assert result.model_path.is_file()
    assert result.metrics_path.is_file()
    assert result.test.roc_auc > 0.9
