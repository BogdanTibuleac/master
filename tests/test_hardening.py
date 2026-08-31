import numpy as np
import pandas as pd

from malware_robustness.ember2018 import FEATURE_DIMENSION
from malware_robustness.hardening import augment_training_table


def test_augmentation_doubles_rows_and_preserves_class_balance() -> None:
    features = np.zeros((6, FEATURE_DIMENSION), dtype=np.float32)
    features[:, 0] = np.arange(1, 7)
    columns = [f"feature_{index:04d}" for index in range(FEATURE_DIMENSION)]
    table = pd.DataFrame(features, columns=columns)
    table["label"] = [0, 1, 0, 1, 0, 1]

    augmented = augment_training_table(table, "label", random_seed=7)

    assert len(augmented) == 12
    assert augmented["label"].value_counts().to_dict() == {0: 6, 1: 6}
    assert not augmented.drop(columns="label").isna().any().any()
