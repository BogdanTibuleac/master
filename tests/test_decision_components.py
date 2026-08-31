"""Tests for trusted native model and calibration adapters."""

from __future__ import annotations

import math
from pathlib import Path

import pytest

from malware_robustness.repositories.decision_components import LogisticMarginCalibrator


@pytest.mark.parametrize(
    ("margin", "expected"),
    [
        (0.0, 0.5),
        (math.log(3), 0.75),
        (-math.log(3), 0.25),
        (1000.0, 1.0),
        (-1000.0, 0.0),
    ],
)
def test_logistic_calibrator_is_stable_and_bounded(margin: float, expected: float) -> None:
    assert LogisticMarginCalibrator.calibrate(margin) == pytest.approx(expected)


@pytest.mark.parametrize("value", [True, float("nan"), float("inf"), "1"])
def test_logistic_calibrator_rejects_invalid_margins(value: object) -> None:
    with pytest.raises(ValueError):
        LogisticMarginCalibrator.calibrate(value)  # type: ignore[arg-type]


def test_margin_model_rejects_missing_or_symlinked_artifacts(tmp_path: Path) -> None:
    from malware_robustness.repositories.decision_components import LightGBMMarginModel

    with pytest.raises(FileNotFoundError):
        LightGBMMarginModel(tmp_path / "missing.txt")

    target = tmp_path / "model.txt"
    target.write_text("not a model", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Symbolic links are unavailable on this platform")
    with pytest.raises(FileNotFoundError):
        LightGBMMarginModel(link)
