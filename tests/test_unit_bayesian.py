"""Unit tests for the multi-hypothesis damped Bayesian Threat Matrix scorer."""

from __future__ import annotations

import pytest

from scripts import ValidationError
from scripts.bayesian_scorer import score_indicators
from scripts.taxonomy_engine import load_and_validate_assets


def test_bayesian_posteriors_always_sum_to_one_with_zero_evidence() -> None:
    assets = load_and_validate_assets()
    res = score_indicators({}, assets, risk_profile="standard")
    total = sum(res["posteriors"].values())
    assert abs(total - 1.0) < 1e-5
    assert res["posteriors"] == {
        k: round(v, 6) for k, v in assets.taxonomy["prior_profiles"]["standard"].items()
    }
    assert res["confidence"]["insufficient_data"] is True
    assert res["confidence"]["level"] == "low"


def test_bayesian_monotonicity_under_positive_and_negative_ci_evidence() -> None:
    assets = load_and_validate_assets()
    base = score_indicators({}, assets)
    one_ci = score_indicators(
        {"IE-01": {"id": "IE-01", "status": "present", "confidence": 0.90}},
        assets,
    )
    multi_ci = score_indicators(
        {
            "AV-01": {"id": "AV-01", "status": "present", "confidence": 0.90},
            "LV-02": {"id": "LV-02", "status": "present", "confidence": 0.90},
            "IE-01": {"id": "IE-01", "status": "present", "confidence": 0.90},
            "TP-02": {"id": "TP-02", "status": "present", "confidence": 0.95},
        },
        assets,
    )
    negated = score_indicators(
        {
            "AV-01": {"id": "AV-01", "status": "absent", "confidence": 0.90},
            "LV-02": {"id": "LV-02", "status": "absent", "confidence": 0.90},
            "IE-01": {"id": "IE-01", "status": "absent", "confidence": 0.90},
            "TP-02": {"id": "TP-02", "status": "absent", "confidence": 0.90},
        },
        assets,
    )

    assert (
        multi_ci["posteriors"]["tier_3_ci_honeypot"]
        > one_ci["posteriors"]["tier_3_ci_honeypot"]
        > base["posteriors"]["tier_3_ci_honeypot"]
        > negated["posteriors"]["tier_3_ci_honeypot"]
    )
    assert negated["classification"]["id"] == "tier_1_benign"
    assert multi_ci["classification"]["id"] == "tier_3_ci_honeypot"


def test_bayesian_intra_tier_damping_is_deterministic_and_bounded() -> None:
    assets = load_and_validate_assets()
    indicators = {
        "IE-01": {"id": "IE-01", "status": "present", "confidence": 0.9},
        "IE-02": {"id": "IE-02", "status": "present", "confidence": 0.9},
        "IE-03": {"id": "IE-03", "status": "present", "confidence": 0.9},
    }
    res_a = score_indicators(indicators, assets)
    res_b = score_indicators(dict(reversed(list(indicators.items()))), assets)

    assert res_a["posteriors"] == res_b["posteriors"]
    dampings = sorted(d["damping_factor"] for d in res_a["top_drivers"])
    # Rank 1 -> 1.0, Rank 2 -> 0.7071, Rank 3 -> 0.5774
    assert dampings == [0.5774, 0.7071, 1.0]


def test_bayesian_separates_commercial_fraud_from_ci_honeypot() -> None:
    assets = load_and_validate_assets()
    fraud_state = {
        "FF-01": {"id": "FF-01", "status": "present", "confidence": 0.90},
        "FF-02": {"id": "FF-02", "status": "present", "confidence": 0.95},
        "FF-03": {"id": "FF-03", "status": "present", "confidence": 0.95},
        "IA-01": {"id": "IA-01", "status": "present", "confidence": 0.90},
        "IE-01": {"id": "IE-01", "status": "absent", "confidence": 0.95},
        "TP-01": {"id": "TP-01", "status": "absent", "confidence": 0.95},
    }
    res = score_indicators(fraud_state, assets)
    assert res["classification"]["id"] == "tier_2_commercial_fraud"
    assert res["posteriors"]["tier_2_commercial_fraud"] > 0.85


def test_invalid_risk_profile_raises_validation_error() -> None:
    assets = load_and_validate_assets()
    with pytest.raises(ValidationError):
        score_indicators({}, assets, risk_profile="invalid_profile")
