"""Focused tests for the trusted decision boundary and immutable result contract."""

from __future__ import annotations

import json
import math
from copy import deepcopy

import pytest
from pydantic import ValidationError

from malware_robustness.domain.analysis import (
    EMBER_V2_FEATURE_COUNT,
    MAX_EVIDENCE_ITEMS,
    MAX_WARNING_ITEMS,
    AnalysisRelease,
    DecisionOutcome,
    EvidenceSeverity,
    ModelContributor,
    PolicyThresholds,
)
from malware_robustness.schemas.analysis import ExtractionEnvelopeSchema, ResultManifestSchema
from malware_robustness.services.decision import DecisionService

_SAMPLE_DIGEST = "sha256:" + "a" * 64
_EXTRACTOR_DIGEST = "sha256:" + "b" * 64
_WORKER_DIGEST = "sha256:" + "c" * 64
_SCHEMA_DIGEST = "sha256:" + "d" * 64
_RELEASE_DIGEST = "sha256:" + "e" * 64


class FakeModel:
    model_id = "ember-v2-lightgbm/17"

    def __init__(self, margin: object = 0.4) -> None:
        self.margin = margin
        self.calls = 0

    def predict_margin(self, features: tuple[float, ...]) -> object:
        self.calls += 1
        assert len(features) == EMBER_V2_FEATURE_COUNT
        return self.margin


class FakeCalibrator:
    calibrator_id = "platt/9"

    def __init__(self, risk: object) -> None:
        self.risk = risk
        self.calls = 0

    def calibrate(self, raw_margin: float) -> object:
        self.calls += 1
        assert math.isfinite(raw_margin)
        return self.risk


class FakeExplainer:
    def explain(self, features: tuple[float, ...]) -> list[ModelContributor]:
        assert len(features) == EMBER_V2_FEATURE_COUNT
        return [
            ModelContributor(943, "hashed imports", 1.25),
            ModelContributor(626, "PE headers", -0.2),
        ]


class FailingExplainer:
    def explain(self, features: tuple[float, ...]):
        raise RuntimeError("explanation backend detail must not escape")


def _release(**overrides: str) -> AnalysisRelease:
    values = {
        "analysis_release_id": _RELEASE_DIGEST,
        "extractor_image_digest": _EXTRACTOR_DIGEST,
        "worker_image_digest": _WORKER_DIGEST,
        "feature_schema_id": "ember-v2/2381",
        "feature_schema_digest": _SCHEMA_DIGEST,
        "model_id": FakeModel.model_id,
        "calibrator_id": FakeCalibrator.calibrator_id,
    }
    values.update(overrides)
    return AnalysisRelease(**values)


def _thresholds() -> PolicyThresholds:
    return PolicyThresholds(
        policy_id="static-pe-policy/17",
        t_b=0.2,
        t_m=0.6,
        t_h=0.9,
        high_risk_min_families=2,
    )


def _evidence(
    indicator_id: str,
    family: str,
    *,
    severity: str = "high",
    summary: str = "A deterministic PE observation.",
) -> dict:
    return {
        "indicator_id": indicator_id,
        "family": family,
        "severity": severity,
        "summary": summary,
    }


def _envelope(*, evidence: list[dict] | None = None, warnings: list[str] | None = None) -> dict:
    return {
        "sample_digest": _SAMPLE_DIGEST,
        "job_nonce": "job_nonce_0123456789",
        "extractor_image_digest": _EXTRACTOR_DIGEST,
        "worker_image_digest": _WORKER_DIGEST,
        "feature_schema_id": "ember-v2/2381",
        "feature_schema_digest": _SCHEMA_DIGEST,
        "analysis_release_id": _RELEASE_DIGEST,
        "extraction_completeness": "complete",
        "warnings": warnings or [],
        "evidence": evidence or [],
        "features": [0.0] * EMBER_V2_FEATURE_COUNT,
    }


def _service(
    risk: object,
    *,
    margin: object = 0.4,
    explainer=None,
    release: AnalysisRelease | None = None,
) -> tuple[DecisionService, FakeModel, FakeCalibrator]:
    model = FakeModel(margin)
    calibrator = FakeCalibrator(risk)
    return (
        DecisionService(
            model,
            calibrator,
            release or _release(),
            _thresholds(),
            explainer=explainer,
        ),
        model,
        calibrator,
    )


def test_valid_envelope_separates_prediction_evidence_explanation_and_policy() -> None:
    indicators = [
        _evidence("pe.imports.injection", "imports"),
        _evidence("pe.sections.rwx", "sections", summary="An RWX section was observed."),
    ]
    service, model, calibrator = _service(0.95, explainer=FakeExplainer())

    manifest = service.decide(_envelope(evidence=indicators))
    payload = manifest.to_dict()

    assert manifest.decision.label is DecisionOutcome.HIGH_RISK
    assert manifest.prediction is not None
    assert manifest.prediction.raw_margin == 0.4
    assert manifest.prediction.calibrated_risk_score == 0.95
    assert [item.family for item in manifest.observed_indicators] == ["imports", "sections"]
    assert [item.feature_family for item in manifest.model_contributors] == [
        "hashed imports",
        "PE headers",
    ]
    assert manifest.explanation_status == "available"
    assert manifest.executed is False
    assert payload["manifest_digest"].startswith("sha256:")
    assert model.calls == calibrator.calls == 1
    ResultManifestSchema.model_validate(payload)


@pytest.mark.parametrize(
    ("risk", "expected"),
    [
        (0.19, DecisionOutcome.LIKELY_BENIGN),
        (0.2, DecisionOutcome.NEEDS_REVIEW),
        (0.59, DecisionOutcome.NEEDS_REVIEW),
        (0.6, DecisionOutcome.LIKELY_MALICIOUS),
        (0.89, DecisionOutcome.LIKELY_MALICIOUS),
    ],
)
def test_versioned_threshold_boundaries(risk: float, expected: DecisionOutcome) -> None:
    service, _, _ = _service(risk)

    assert service.decide(_envelope()).decision.label is expected


def test_high_risk_requires_configured_distinct_evidence_families() -> None:
    same_family = [
        _evidence("pe.imports.injection", "imports"),
        _evidence("pe.imports.network", "imports", severity="critical"),
    ]
    service, _, _ = _service(0.99)

    manifest = service.decide(_envelope(evidence=same_family))

    assert manifest.decision.label is DecisionOutcome.LIKELY_MALICIOUS
    assert manifest.decision.corroborating_families == ("imports",)
    assert manifest.decision.reason_codes == ("high_risk_corroboration_not_met",)


def test_low_severity_evidence_does_not_corroborate_high_risk() -> None:
    evidence = [
        _evidence("pe.imports.injection", "imports"),
        _evidence("pe.signature.absent", "signature", severity="low"),
    ]
    service, _, _ = _service(0.99)

    assert service.decide(_envelope(evidence=evidence)).decision.label is (
        DecisionOutcome.LIKELY_MALICIOUS
    )


def test_quality_warning_prevents_likely_benign_label() -> None:
    service, _, _ = _service(0.05)

    manifest = service.decide(_envelope(warnings=["Secondary parser disagreed on one field."]))

    assert manifest.decision.label is DecisionOutcome.NEEDS_REVIEW
    assert manifest.decision.reason_codes == ("quality_warning",)


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        (lambda item: item.pop("analysis_release_id"), "missing_required_identity"),
        (lambda item: item.__setitem__("feature_schema_id", "unknown"), "invalid_version_identity"),
        (lambda item: item.__setitem__("sample_digest", "not-a-digest"), "invalid_digest"),
        (lambda item: item.__setitem__("features", item["features"][:-1]), "invalid_feature_count"),
        (
            lambda item: item.__setitem__("features", [*item["features"], 0.0]),
            "invalid_feature_count",
        ),
        (lambda item: item["features"].__setitem__(3, float("nan")), "non_finite_feature"),
        (lambda item: item["features"].__setitem__(3, float("inf")), "non_finite_feature"),
        (
            lambda item: item.__setitem__(
                "evidence",
                [_evidence(f"rule.{index}", "imports") for index in range(MAX_EVIDENCE_ITEMS + 1)],
            ),
            "oversized_evidence",
        ),
        (
            lambda item: item.__setitem__(
                "warnings", [f"warning {index}" for index in range(MAX_WARNING_ITEMS + 1)]
            ),
            "oversized_warnings",
        ),
    ],
)
def test_invalid_untrusted_envelopes_are_inconclusive_without_scoring(
    mutation, reason: str
) -> None:
    envelope = _envelope()
    mutation(envelope)
    service, model, calibrator = _service(0.01)

    manifest = service.decide(envelope)

    assert manifest.analysis_status == "inconclusive"
    assert manifest.decision.label is DecisionOutcome.INCONCLUSIVE
    assert manifest.decision.reason_codes == (reason,)
    assert manifest.prediction is None
    assert model.calls == calibrator.calls == 0


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("feature_schema_id", "ember-v3/2568", "feature_schema_mismatch"),
        ("feature_schema_digest", "sha256:" + "1" * 64, "feature_schema_mismatch"),
        ("extractor_image_digest", "sha256:" + "2" * 64, "extractor_image_mismatch"),
        ("worker_image_digest", "sha256:" + "3" * 64, "worker_image_mismatch"),
        ("analysis_release_id", "sha256:" + "4" * 64, "analysis_release_mismatch"),
    ],
)
def test_pinned_release_mismatch_is_inconclusive(field: str, value: str, reason: str) -> None:
    envelope = _envelope()
    envelope[field] = value
    service, model, _ = _service(0.01)

    manifest = service.decide(envelope)

    assert manifest.decision.label is DecisionOutcome.INCONCLUSIVE
    assert manifest.decision.reason_codes == (reason,)
    assert model.calls == 0


@pytest.mark.parametrize("completeness", ["partial", "failed"])
def test_incomplete_extraction_never_reaches_the_model(completeness: str) -> None:
    envelope = _envelope()
    envelope["extraction_completeness"] = completeness
    service, model, _ = _service(0.01)

    manifest = service.decide(envelope)

    assert manifest.decision.label is DecisionOutcome.INCONCLUSIVE
    assert manifest.decision.reason_codes == (f"extraction_{completeness}",)
    assert model.calls == 0


def test_explanation_failure_preserves_an_otherwise_valid_verdict() -> None:
    service, _, _ = _service(0.72, explainer=FailingExplainer())

    manifest = service.decide(_envelope())

    assert manifest.decision.label is DecisionOutcome.LIKELY_MALICIOUS
    assert manifest.explanation_status == "unavailable"
    assert manifest.model_contributors == ()
    assert any("verdict remains valid" in limitation for limitation in manifest.limitations)


@pytest.mark.parametrize(
    ("margin", "risk", "reason"),
    [
        (float("nan"), 0.5, "invalid_model_margin"),
        (float("inf"), 0.5, "invalid_model_margin"),
        (0.0, float("nan"), "invalid_calibrated_risk"),
        (0.0, -0.01, "invalid_calibrated_risk"),
        (0.0, 1.01, "invalid_calibrated_risk"),
    ],
)
def test_invalid_prediction_components_are_inconclusive(
    margin: float, risk: float, reason: str
) -> None:
    service, _, _ = _service(risk, margin=margin)

    manifest = service.decide(_envelope())

    assert manifest.decision.label is DecisionOutcome.INCONCLUSIVE
    assert manifest.decision.reason_codes == (reason,)


def test_missing_or_unknown_adapter_identity_is_inconclusive() -> None:
    service, model, _ = _service(0.5)
    model.model_id = "latest"

    manifest = service.decide(_envelope())

    assert manifest.decision.reason_codes == ("model_identity_mismatch",)
    assert model.calls == 0


def test_manifest_hash_is_canonical_stable_and_covers_content() -> None:
    service, _, _ = _service(0.4, explainer=FakeExplainer())
    first = service.decide(_envelope())
    second = service.decide(deepcopy(_envelope()))
    changed = _envelope()
    changed["job_nonce"] = "different_nonce_12345"
    third = service.decide(changed)

    assert first.manifest_digest == second.manifest_digest
    assert first.manifest_digest != third.manifest_digest
    payload = first.to_dict()
    assert payload["executed"] is False
    assert json.loads(json.dumps(payload, allow_nan=False))["manifest_digest"] == (
        first.manifest_digest
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda item: item.__setitem__("unexpected", "field"),
        lambda item: item.__setitem__("features", item["features"][:-1]),
        lambda item: item["features"].__setitem__(0, float("nan")),
        lambda item: item.__setitem__(
            "evidence", [_evidence("rule.too-long", "imports", summary="x" * 513)]
        ),
    ],
)
def test_http_schema_rejects_untrusted_contract_violations(mutation) -> None:
    envelope = _envelope()
    mutation(envelope)

    with pytest.raises((ValidationError, ValueError)):
        ExtractionEnvelopeSchema.model_validate(envelope)


def test_http_schema_normalizes_plain_sample_sha256_without_altering_features() -> None:
    envelope = _envelope()
    envelope["sample_digest"] = "a" * 64

    schema = ExtractionEnvelopeSchema.model_validate(envelope)

    assert schema.sample_digest == _SAMPLE_DIGEST
    assert len(schema.features) == EMBER_V2_FEATURE_COUNT
    assert schema.to_domain().features == schema.features


@pytest.mark.parametrize(
    "values",
    [
        {"t_b": 0.6, "t_m": 0.2, "t_h": 0.9},
        {"t_b": 0.2, "t_m": 0.6, "t_h": float("nan")},
        {"t_b": -0.1, "t_m": 0.6, "t_h": 0.9},
    ],
)
def test_policy_thresholds_must_be_finite_ordered_and_bounded(values: dict) -> None:
    with pytest.raises(ValueError):
        PolicyThresholds(policy_id="static-pe-policy/17", **values)


def test_corroborating_severity_configuration_is_versioned_and_enforced() -> None:
    thresholds = PolicyThresholds(
        policy_id="static-pe-policy/critical-only",
        t_b=0.2,
        t_m=0.6,
        t_h=0.9,
        corroborating_severities=frozenset({EvidenceSeverity.CRITICAL}),
    )
    model = FakeModel()
    calibrator = FakeCalibrator(0.99)
    service = DecisionService(model, calibrator, _release(), thresholds)
    evidence = [
        _evidence("rule.imports", "imports", severity="high"),
        _evidence("rule.sections", "sections", severity="high"),
    ]

    manifest = service.decide(_envelope(evidence=evidence))

    assert manifest.decision.label is DecisionOutcome.LIKELY_MALICIOUS
    assert manifest.decision.corroborating_families == ()
