"""Quantitative multi-hypothesis Bayesian Threat Matrix scoring engine.

Computes normalized posterior probabilities over three mutually exclusive threat
hypotheses (Tier 1 Benign, Tier 2 Commercial Fraud, Tier 3 Advanced CI Threat)
with intra-tier correlation damping, per-tier severity indices, and transparent
log-likelihood attribution.
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from typing import Any

from scripts import ValidationError
from scripts.taxonomy_engine import HYPOTHESIS_IDS, LoadedAssets

logger = logging.getLogger("honeypot_skill.bayesian")

_EPSILON = 1e-9


def _effective_likelihood(
    raw_prob_present: float,
    status: str,
    confidence: float,
) -> float:
    """Blend conditional likelihood with uninformative 0.5 baseline by confidence."""
    if status == "present":
        base = raw_prob_present
    elif status == "absent":
        base = 1.0 - raw_prob_present
    else:
        return 0.5
    blended = confidence * base + (1.0 - confidence) * 0.5
    return min(max(blended, _EPSILON), 1.0 - _EPSILON)


def _log_sum_exp(log_values: dict[str, float]) -> dict[str, float]:
    """Normalize log-posterior scores stably into exact probabilities summing to 1.0."""
    max_log = max(log_values.values())
    exps = {k: math.exp(v - max_log) for k, v in log_values.items()}
    total = sum(exps.values())
    return {k: exps[k] / total for k in HYPOTHESIS_IDS}


def score_indicators(
    indicator_states: dict[str, dict[str, Any]],
    assets: LoadedAssets,
    risk_profile: str = "standard",
    covered_tiers: list[str] | set[str] | None = None,
) -> dict[str, Any]:
    """Evaluate assessed indicators through the damped Bayesian Threat Matrix."""
    prior_profiles = assets.taxonomy["prior_profiles"]
    if risk_profile not in prior_profiles:
        raise ValidationError(
            f"Unknown risk_profile '{risk_profile}'. "
            f"Allowed values: {sorted(prior_profiles.keys())}."
        )

    priors = {h: float(prior_profiles[risk_profile][h]) for h in HYPOTHESIS_IDS}
    log_posteriors = {h: math.log(max(priors[h], _EPSILON)) for h in HYPOTHESIS_IDS}

    # Group assessed indicators by tier for deterministic intra-tier damping.
    assessed_by_tier: dict[str, list[tuple[float, str, dict[str, Any], dict[str, float]]]] = (
        defaultdict(list)
    )
    present_count = 0
    absent_count = 0

    for ind_id, state in indicator_states.items():
        if ind_id not in assets.indicators_by_id:
            continue
        status = state.get("status", "unknown")
        if status not in {"present", "absent"}:
            continue
        confidence = float(state.get("confidence", 0.0))
        if confidence <= 0.0:
            continue

        if status == "present":
            present_count += 1
        else:
            absent_count += 1

        ind = assets.indicators_by_id[ind_id]
        eff_likes = {
            h: _effective_likelihood(ind.likelihoods[h], status, confidence)
            for h in HYPOTHESIS_IDS
        }
        # Strength score ensures deterministic descending ordering before damping.
        log_vals = [math.log(v) for v in eff_likes.values()]
        max_log_spread = max(log_vals) - min(log_vals)
        assessed_by_tier[ind.tier].append((max_log_spread, ind_id, state, eff_likes))

    driver_records: list[dict[str, Any]] = []

    for tier_id, items in assessed_by_tier.items():
        # Strongest evidence first gets exponent 1.0; correlated siblings inside the
        # same tier receive diminishing exponent 1 / sqrt(m).
        items.sort(key=lambda row: (-row[0], row[1]))
        for rank_idx, (_, ind_id, state, eff_likes) in enumerate(items, start=1):
            damping = 1.0 / math.sqrt(rank_idx)
            log_deltas: dict[str, float] = {}
            for h_id in HYPOTHESIS_IDS:
                delta = damping * math.log(eff_likes[h_id])
                log_posteriors[h_id] += delta
                log_deltas[h_id] = delta

            ind = assets.indicators_by_id[ind_id]
            driver_records.append(
                {
                    "id": ind_id,
                    "name": ind.name,
                    "tier": tier_id,
                    "status": state["status"],
                    "confidence": float(state["confidence"]),
                    "damping_factor": round(damping, 4),
                    "log_likelihood_deltas": {
                        h: round(log_deltas[h], 4) for h in HYPOTHESIS_IDS
                    },
                    "impact_spread": round(
                        max(log_deltas.values()) - min(log_deltas.values()), 4
                    ),
                }
            )

    posteriors = _log_sum_exp(log_posteriors)
    winning_id = max(HYPOTHESIS_IDS, key=lambda h: posteriors[h])
    hyp_meta = {h["id"]: h for h in assets.taxonomy["hypotheses"]}

    # Compute per-tier severity risk indices and coverage status.
    explicitly_covered = set(covered_tiers or [])
    for tier_id in assessed_by_tier:
        explicitly_covered.add(tier_id)

    tier_breakdown: list[dict[str, Any]] = []
    tier_max_weights: dict[str, float] = defaultdict(float)
    tier_active_weights: dict[str, float] = defaultdict(float)
    tier_present_lists: dict[str, list[str]] = defaultdict(list)
    tier_absent_lists: dict[str, list[str]] = defaultdict(list)

    for ind in assets.indicators_by_id.values():
        tier_max_weights[ind.tier] += ind.severity_weight
        st = indicator_states.get(ind.id)
        if st and st.get("status") == "present":
            tier_active_weights[ind.tier] += ind.severity_weight * float(
                st.get("confidence", 0.0)
            )
            tier_present_lists[ind.tier].append(ind.id)
        elif st and st.get("status") == "absent":
            tier_absent_lists[ind.tier].append(ind.id)

    core_tiers_total = 0
    core_tiers_covered = 0
    blind_spots: list[str] = []

    ordered_tiers = sorted(
        assets.tiers_by_id.values(), key=lambda t: int(t.get("priority", 99))
    )
    for tier_obj in ordered_tiers:
        t_id = tier_obj["id"]
        is_core = bool(tier_obj.get("core_ci_tier", False))
        is_covered = t_id in explicitly_covered
        if is_core:
            core_tiers_total += 1
            if is_covered:
                core_tiers_covered += 1
        if not is_covered:
            blind_spots.append(tier_obj["label"])

        max_w = tier_max_weights.get(t_id, 1.0)
        # Saturate tier index around 65% of max theoretical tier weight so
        # multi-indicator triggers register clearly without requiring every sub-pattern.
        raw_ratio = tier_active_weights.get(t_id, 0.0) / max(max_w * 0.65, 1.0)
        tier_score = round(min(raw_ratio, 1.0) * 100.0, 1)

        tier_breakdown.append(
            {
                "tier_id": t_id,
                "label": tier_obj["label"],
                "core_ci_tier": is_core,
                "covered": is_covered,
                "risk_index": tier_score,
                "active_indicators": sorted(tier_present_lists.get(t_id, [])),
                "disconfirming_indicators": sorted(tier_absent_lists.get(t_id, [])),
            }
        )

    # Composite threat score blends threat posterior probability with active breadth.
    non_benign_prob = 1.0 - posteriors["tier_1_benign"]
    active_tier_count = sum(1 for row in tier_breakdown if row["active_indicators"])
    breadth_factor = min(active_tier_count / 4.0, 1.0)
    if present_count == 0:
        composite_risk_score = round(non_benign_prob * 35.0, 1)
    else:
        composite_risk_score = round(
            min((0.75 * non_benign_prob + 0.25 * breadth_factor) * 100.0, 100.0), 1
        )

    coverage_pct = round(
        (core_tiers_covered / max(core_tiers_total, 1)) * 100.0, 1
    )
    insufficient_data = core_tiers_covered < 3
    max_post = posteriors[winning_id]

    if insufficient_data or max_post < 0.60:
        confidence_level = "low"
    elif core_tiers_covered >= 4 and max_post >= 0.80:
        confidence_level = "high"
    else:
        confidence_level = "moderate"

    driver_records.sort(key=lambda d: (-d["impact_spread"], d["id"]))

    logger.debug(
        "Scored %d present / %d absent indicators -> %s (%.2f%%)",
        present_count,
        absent_count,
        winning_id,
        posteriors[winning_id] * 100.0,
    )

    return {
        "risk_profile": risk_profile,
        "priors": priors,
        "posteriors": {h: round(posteriors[h], 6) for h in HYPOTHESIS_IDS},
        "classification": {
            "id": winning_id,
            "label": hyp_meta[winning_id]["label"],
            "description": hyp_meta[winning_id]["description"],
        },
        "composite_risk_score": composite_risk_score,
        "confidence": {
            "level": confidence_level,
            "insufficient_data": insufficient_data,
            "core_tiers_covered": core_tiers_covered,
            "core_tiers_total": core_tiers_total,
            "coverage_percent": coverage_pct,
        },
        "indicators_summary": {
            "total_catalog_indicators": len(assets.indicators_by_id),
            "present_count": present_count,
            "absent_count": absent_count,
            "unassessed_count": len(assets.indicators_by_id)
            - present_count
            - absent_count,
        },
        "tier_breakdown": tier_breakdown,
        "blind_spots": blind_spots,
        "top_drivers": driver_records[:10],
    }
