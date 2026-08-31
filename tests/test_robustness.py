import numpy as np
import pytest

from malware_robustness.ember2018 import FEATURE_DIMENSION
from malware_robustness.robustness import HISTOGRAM, perturb_features


def test_histogram_smoothing_preserves_distribution_mass() -> None:
    features = np.zeros((2, FEATURE_DIMENSION), dtype=np.float32)
    features[:, HISTOGRAM] = np.arange(1, 257, dtype=np.float32)

    perturbed = perturb_features(features, "histogram_smoothing", 0.5)

    assert np.allclose(
        perturbed[:, HISTOGRAM].sum(axis=1), features[:, HISTOGRAM].sum(axis=1)
    )
    assert not np.array_equal(perturbed[:, HISTOGRAM], features[:, HISTOGRAM])
    assert np.array_equal(features[:, 512:], perturbed[:, 512:])


def test_hashed_dropout_is_deterministic_and_does_not_mutate_input() -> None:
    features = np.ones((3, FEATURE_DIMENSION), dtype=np.float32)

    first = perturb_features(features, "hashed_feature_dropout", 0.25, random_seed=7)
    second = perturb_features(features, "hashed_feature_dropout", 0.25, random_seed=7)

    assert np.array_equal(first, second)
    assert np.all(features == 1)
    assert np.count_nonzero(first == 0) > 0


def test_perturbation_rejects_invalid_intensity() -> None:
    with pytest.raises(ValueError, match="between 0 and 1"):
        perturb_features(np.zeros((1, FEATURE_DIMENSION)), "combined", 0)
