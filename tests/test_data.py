"""Tests for validated feature data loading and splitting."""

from pathlib import Path

import pandas as pd
import pytest

from malware_robustness.data import load_feature_table, split_feature_table


@pytest.fixture
def feature_table() -> pd.DataFrame:
    """A balanced synthetic table suitable for stratified splitting."""
    return pd.DataFrame(
        {
            "feature_one": list(range(40)),
            "feature_two": [value / 10 for value in range(40)],
            "label": [0, 1] * 20,
        }
    )


def test_load_feature_table_reads_csv(tmp_path: Path, feature_table: pd.DataFrame) -> None:
    """CSV feature tables load when their schema is valid."""
    dataset_path = tmp_path / "features.csv"
    feature_table.to_csv(dataset_path, index=False)

    loaded = load_feature_table(dataset_path, "label")

    pd.testing.assert_frame_equal(loaded, feature_table)


def test_load_feature_table_rejects_missing_label(
    tmp_path: Path, feature_table: pd.DataFrame
) -> None:
    """A useful error is raised when the configured label is absent."""
    dataset_path = tmp_path / "features.csv"
    feature_table.drop(columns="label").to_csv(dataset_path, index=False)

    with pytest.raises(ValueError, match="missing label column"):
        load_feature_table(dataset_path, "label")


def test_split_feature_table_is_reproducible_and_stratified(feature_table: pd.DataFrame) -> None:
    """One seed creates stable split membership with comparable class balance."""
    first_split = split_feature_table(feature_table, "label", random_seed=7)
    second_split = split_feature_table(feature_table, "label", random_seed=7)

    pd.testing.assert_frame_equal(first_split.x_train, second_split.x_train)
    assert len(first_split.x_train) == 28
    assert len(first_split.x_validation) == 6
    assert len(first_split.x_test) == 6
    for labels in (first_split.y_train, first_split.y_validation, first_split.y_test):
        assert labels.mean() == 0.5


def test_split_feature_table_rejects_invalid_partition_sizes(feature_table: pd.DataFrame) -> None:
    """Partition sizes must leave a non-empty training split."""
    with pytest.raises(ValueError, match="sum to less than one"):
        split_feature_table(feature_table, "label", validation_size=0.5, test_size=0.5)
