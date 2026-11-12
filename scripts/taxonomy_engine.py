"""Declarative 32-indicator taxonomy loader, validator, and hybrid matcher.

Maps sanitized executive narratives and optional LLM-extracted structured
observations against the counterintelligence and romance-fraud taxonomy defined
in assets/indicators_taxonomy.json.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scripts import TaxonomyError, ValidationError, get_assets_dir
from scripts.sanitizer import make_safe_excerpt

logger = logging.getLogger("honeypot_skill.taxonomy")

EXPECTED_INDICATOR_COUNT = 32
VALID_STATUSES = frozenset({"present", "absent", "unknown"})
HYPOTHESIS_IDS = (
    "tier_1_benign",
    "tier_2_commercial_fraud",
    "tier_3_ci_honeypot",
)

# Keyword heuristics used strictly for tailoring passive Canary Protocol examples.
_CANARY_DOMAIN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ma_strategy",
        re.compile(
            r"\b(?:m&a|merger|acquisition|deal\s+pipeline|valuation|due\s+diligence|divestiture)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "technical_roadmap",
        re.compile(
            r"\b(?:roadmap|proprietary\s+(?:tech|technology|ip|specs)|source\s+code|r&d|patent|architecture|clinical\s+trial)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "board_governance",
        re.compile(
            r"\b(?:board\s+(?:disputes|politics|votes|meeting)|governance|reorganization|restructuring|succession)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "procurement_supply_chain",
        re.compile(
            r"\b(?:procurement|sovereign\s+contract|vendor|supply\s+chain|defense\s+program|tender)\b",
            re.IGNORECASE,
        ),
    ),
)


@dataclass(frozen=True)
class CompiledIndicator:
    """In-memory representation of a validated taxonomy indicator."""

    id: str
    tier: str
    stage_mapping: str
    name: str
    description: str
    severity_weight: float
    likelihoods: dict[str, float]
    positive_patterns: tuple[re.Pattern[str], ...]
    negation_patterns: tuple[re.Pattern[str], ...]
    followup_probe_id: str
    dynamic_action: str


@dataclass(frozen=True)
class LoadedAssets:
    """Validated bundle of taxonomy, compiled indicators, probes, and templates."""

    taxonomy: dict[str, Any]
    probes_config: dict[str, Any]
    indicators_by_id: dict[str, CompiledIndicator]
    tiers_by_id: dict[str, dict[str, Any]]
    report_template: str


def _load_json_file(path: Path, label: str) -> dict[str, Any]:
    """Read and parse a JSON asset file with explicit error reporting."""
    if not path.is_file():
        raise TaxonomyError(f"Required {label} asset file not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TaxonomyError(f"Failed to parse {label} JSON ({path}): {exc}") from exc
    if not isinstance(data, dict):
        raise TaxonomyError(f"{label} root must be a JSON object: {path}")
    return data


def load_and_validate_assets(assets_dir: str | Path | None = None) -> LoadedAssets:
    """Load and validate all declarative JSON/template assets."""
    resolved_dir = get_assets_dir(assets_dir)
    taxonomy = _load_json_file(resolved_dir / "indicators_taxonomy.json", "taxonomy")
    probes_cfg = _load_json_file(
        resolved_dir / "probes_and_countermeasures.json", "probes and countermeasures"
    )

    template_path = resolved_dir / "report_template.md"
    if not template_path.is_file():
        raise TaxonomyError(f"Required report template not found: {template_path}")
    report_template = template_path.read_text(encoding="utf-8")

    # Validate prior profiles sum to 1.0 across all hypotheses.
    prior_profiles = taxonomy.get("prior_profiles")
    if not isinstance(prior_profiles, dict) or not prior_profiles:
        raise TaxonomyError("Taxonomy missing valid 'prior_profiles' mapping.")
    for profile_name, priors in prior_profiles.items():
        if not isinstance(priors, dict):
            raise TaxonomyError(f"Prior profile '{profile_name}' must be an object.")
        if set(priors.keys()) != set(HYPOTHESIS_IDS):
            raise TaxonomyError(
                f"Prior profile '{profile_name}' must define exact hypotheses {HYPOTHESIS_IDS}."
            )
        total = sum(float(v) for v in priors.values())
        if abs(total - 1.0) > 1e-6:
            raise TaxonomyError(
                f"Prior profile '{profile_name}' probabilities must sum to 1.0 (got {total:.6f})."
            )
        for h_id, prob in priors.items():
            if not (0.0 < float(prob) < 1.0):
                raise TaxonomyError(
                    f"Prior '{profile_name}.{h_id}' must be strictly between 0 and 1."
                )

    # Validate tiers and baseline probes.
    tiers_list = taxonomy.get("tiers")
    probes_map = probes_cfg.get("probes", {})
    if not isinstance(tiers_list, list) or not tiers_list:
        raise TaxonomyError("Taxonomy missing valid 'tiers' array.")
    if not isinstance(probes_map, dict) or not probes_map:
        raise TaxonomyError("probes_and_countermeasures.json missing 'probes' mapping.")

    tiers_by_id: dict[str, dict[str, Any]] = {}
    for tier_obj in tiers_list:
        t_id = tier_obj.get("id")
        baseline_probe = tier_obj.get("baseline_probe_id")
        if not t_id or t_id in tiers_by_id:
            raise TaxonomyError(f"Duplicate or missing tier id: {t_id!r}")
        if baseline_probe not in probes_map:
            raise TaxonomyError(
                f"Tier '{t_id}' references unknown baseline_probe_id '{baseline_probe}'."
            )
        tiers_by_id[t_id] = tier_obj

    # Validate exactly 32 discrete indicators.
    raw_indicators = taxonomy.get("indicators")
    if not isinstance(raw_indicators, list):
        raise TaxonomyError("Taxonomy missing 'indicators' list.")
    if len(raw_indicators) != EXPECTED_INDICATOR_COUNT:
        raise TaxonomyError(
            f"Taxonomy must define exactly {EXPECTED_INDICATOR_COUNT} indicators; "
            f"found {len(raw_indicators)}."
        )

    indicators_by_id: dict[str, CompiledIndicator] = {}
    for item in raw_indicators:
        ind_id = item.get("id")
        if not ind_id or ind_id in indicators_by_id:
            raise TaxonomyError(f"Duplicate or missing indicator id: {ind_id!r}")

        tier_id = item.get("tier")
        if tier_id not in tiers_by_id:
            raise TaxonomyError(f"Indicator '{ind_id}' references unknown tier '{tier_id}'.")

        followup_id = item.get("followup_probe_id")
        if followup_id not in probes_map:
            raise TaxonomyError(
                f"Indicator '{ind_id}' references unknown followup_probe_id '{followup_id}'."
            )

        likelihoods = item.get("likelihoods", {})
        if set(likelihoods.keys()) != set(HYPOTHESIS_IDS):
            raise TaxonomyError(
                f"Indicator '{ind_id}' likelihoods must contain exact hypotheses {HYPOTHESIS_IDS}."
            )
        parsed_likelihoods: dict[str, float] = {}
        for h_id, val in likelihoods.items():
            fval = float(val)
            if not (0.0 < fval < 1.0):
                raise TaxonomyError(
                    f"Indicator '{ind_id}' likelihood '{h_id}'={fval} must be strictly in (0, 1)."
                )
            parsed_likelihoods[h_id] = fval

        weight = float(item.get("severity_weight", 0.0))
        if not (1.0 <= weight <= 5.0):
            raise TaxonomyError(
                f"Indicator '{ind_id}' severity_weight={weight} must be within [1.0, 5.0]."
            )

        try:
            pos_patterns = tuple(
                re.compile(p, re.IGNORECASE) for p in item.get("positive_patterns", [])
            )
            neg_patterns = tuple(
                re.compile(p, re.IGNORECASE) for p in item.get("negation_patterns", [])
            )
        except re.error as exc:
            raise TaxonomyError(
                f"Invalid regex pattern in indicator '{ind_id}': {exc}"
            ) from exc

        if not pos_patterns:
            raise TaxonomyError(
                f"Indicator '{ind_id}' must define at least one positive_patterns regex."
            )

        indicators_by_id[ind_id] = CompiledIndicator(
            id=ind_id,
            tier=tier_id,
            stage_mapping=str(item.get("stage_mapping", "")),
            name=str(item.get("name", "")),
            description=str(item.get("description", "")),
            severity_weight=weight,
            likelihoods=parsed_likelihoods,
            positive_patterns=pos_patterns,
            negation_patterns=neg_patterns,
            followup_probe_id=followup_id,
            dynamic_action=str(item.get("dynamic_action", "")),
        )

    # Validate dynamic follow-up rules reference known indicators and probes.
    for rule in probes_cfg.get("dynamic_followup_rules", []):
        r_id = rule.get("rule_id")
        for ind_id in rule.get("trigger_indicators", []):
            if ind_id not in indicators_by_id:
                raise TaxonomyError(
                    f"Dynamic rule '{r_id}' references unknown indicator '{ind_id}'."
                )
        for p_id in rule.get("priority_probes", []):
            if p_id not in probes_map:
                raise TaxonomyError(
                    f"Dynamic rule '{r_id}' references unknown probe '{p_id}'."
                )

    # Validate countermeasures exist for all hypotheses.
    countermeasures = probes_cfg.get("countermeasures", {})
    if set(countermeasures.keys()) != set(HYPOTHESIS_IDS):
        raise TaxonomyError(
            f"Countermeasures must be defined for all hypotheses {HYPOTHESIS_IDS}."
        )

    logger.debug("Validated taxonomy with %d indicators.", len(indicators_by_id))
    return LoadedAssets(
        taxonomy=taxonomy,
        probes_config=probes_cfg,
        indicators_by_id=indicators_by_id,
        tiers_by_id=tiers_by_id,
        report_template=report_template,
    )


def validate_structured_observations(
    observations: Any,
    indicators_by_id: dict[str, CompiledIndicator],
) -> list[dict[str, Any]]:
    """Validate optional structured indicator observations supplied by an agent."""
    if observations is None:
        return []
    if not isinstance(observations, list):
        raise ValidationError("observations payload must be a JSON array.")

    validated: list[dict[str, Any]] = []
    for idx, entry in enumerate(observations):
        if not isinstance(entry, dict):
            raise ValidationError(f"Observation entry at index {idx} must be an object.")
        ind_id = entry.get("id")
        if ind_id not in indicators_by_id:
            raise ValidationError(
                f"Observation entry at index {idx} references unknown indicator id '{ind_id}'."
            )
        status = entry.get("status")
        if status not in VALID_STATUSES:
            raise ValidationError(
                f"Observation '{ind_id}' has invalid status '{status}'. "
                f"Allowed values: {sorted(VALID_STATUSES)}."
            )
        raw_conf = entry.get("confidence", 0.85)
        try:
            confidence = float(raw_conf)
        except (TypeError, ValueError) as exc:
            raise ValidationError(
                f"Observation '{ind_id}' confidence must be numeric."
            ) from exc
        if status != "unknown" and not (0.0 < confidence <= 1.0):
            raise ValidationError(
                f"Observation '{ind_id}' confidence={confidence} must be in (0.0, 1.0]."
            )
        if status == "unknown":
            confidence = 0.0

        evidence = str(entry.get("evidence", "")).strip()
        validated.append(
            {
                "id": ind_id,
                "status": status,
                "confidence": round(confidence, 4),
                "evidence": evidence,
            }
        )
    return validated


def infer_canary_domain(
    sanitized_text: str,
    active_indicator_ids: set[str],
    previous_domain: str = "general_operations",
) -> str:
    """Infer the most relevant corporate domain for passive Canary Protocol tailoring."""
    for domain_key, pattern in _CANARY_DOMAIN_PATTERNS:
        if pattern.search(sanitized_text):
            return domain_key
    if previous_domain != "general_operations":
        return previous_domain
    if "IE-01" in active_indicator_ids:
        return "ma_strategy"
    if "IE-02" in active_indicator_ids or "TP-02" in active_indicator_ids:
        return "technical_roadmap"
    if "IE-03" in active_indicator_ids or "IE-05" in active_indicator_ids:
        return "board_governance"
    return "general_operations"


def _has_unnegated_positive_match(
    text: str,
    positive_patterns: tuple[re.Pattern[str], ...],
    neg_spans: list[tuple[int, int]],
) -> bool:
    """Return True only if at least one positive match is not contained in a negation span."""
    for pattern in positive_patterns:
        for match in pattern.finditer(text):
            m_start, m_end = match.span()
            enclosed_by_negation = any(
                n_start <= m_start and m_end <= n_end for n_start, n_end in neg_spans
            )
            if not enclosed_by_negation:
                return True
    return False


def extract_indicators(
    sanitized_text: str,
    assets: LoadedAssets,
    structured_observations: list[dict[str, Any]] | None = None,
    existing_indicators: dict[str, dict[str, Any]] | None = None,
    previous_canary_domain: str = "general_operations",
) -> dict[str, Any]:
    """Perform hybrid deterministic regex and structured indicator evaluation.

    Returns newly detected indicators, the merged indicator state map, triggered
    dynamic follow-up rules, newly covered tier IDs, and an inferred Canary domain.
    """
    validated_obs = validate_structured_observations(
        structured_observations, assets.indicators_by_id
    )
    structured_map = {item["id"]: item for item in validated_obs}

    merged: dict[str, dict[str, Any]] = {
        k: dict(v) for k, v in (existing_indicators or {}).items()
    }
    excerpt = make_safe_excerpt(sanitized_text)
    turn_matches: list[dict[str, Any]] = []
    touched_tiers: set[str] = set()

    for ind_id, ind in assets.indicators_by_id.items():
        neg_spans = [
            match.span()
            for p in ind.negation_patterns
            for match in p.finditer(sanitized_text)
        ]
        neg_hit = bool(neg_spans)
        pos_hit = _has_unnegated_positive_match(
            sanitized_text, ind.positive_patterns, neg_spans
        )
        struct_item = structured_map.get(ind_id)

        regex_status: str | None = None
        regex_conf = 0.0
        conflict_flagged = False

        if pos_hit and neg_hit:
            # Conflicting signals within the same turn trigger conservative low-confidence flag.
            regex_status = "present"
            regex_conf = 0.45
            conflict_flagged = True
        elif pos_hit:
            regex_status = "present"
            regex_conf = 0.80
        elif neg_hit:
            regex_status = "absent"
            regex_conf = 0.80

        if regex_status is None and struct_item is None:
            continue

        if struct_item is not None and struct_item["status"] != "unknown":
            final_status = struct_item["status"]
            final_conf = struct_item["confidence"]
            final_evidence = struct_item["evidence"] or excerpt
            if regex_status is not None and regex_status == final_status:
                source = "hybrid"
                final_conf = max(final_conf, regex_conf)
            elif regex_status is not None and regex_status != final_status:
                source = "structured"
                conflict_flagged = True
            else:
                source = "structured"
        elif regex_status is not None:
            final_status = regex_status
            final_conf = regex_conf
            final_evidence = excerpt
            source = "regex"
        else:
            # Explicit 'unknown' observation clears nothing unless absent from map.
            continue

        prior = merged.get(ind_id)
        if prior and prior.get("status") in {"present", "absent"}:
            if prior["status"] != final_status:
                conflict_flagged = True
                # Preserve higher-confidence state on cross-turn contradiction,
                # preferring explicit structured evidence on ties.
                prior_conf = float(prior.get("confidence", 0.0))
                if final_conf < prior_conf and source == "regex":
                    final_status = prior["status"]
                    final_conf = prior_conf
            else:
                final_conf = max(float(prior.get("confidence", 0.0)), final_conf)
                if prior.get("source") != source:
                    source = "hybrid"

        record = {
            "id": ind_id,
            "tier": ind.tier,
            "status": final_status,
            "confidence": round(final_conf, 4),
            "source": source,
            "evidence_excerpt": make_safe_excerpt(final_evidence),
            "conflict_flagged": conflict_flagged,
        }
        merged[ind_id] = record
        turn_matches.append(record)
        touched_tiers.add(ind.tier)

    # Identify dynamic follow-up rules activated by present indicators in this turn or session.
    present_turn_ids = {
        m["id"] for m in turn_matches if m["status"] == "present"
    }
    all_present_ids = {
        k for k, v in merged.items() if v.get("status") == "present"
    }

    triggered_rules: list[dict[str, Any]] = []
    followup_probes: list[str] = []

    for m in turn_matches:
        if m["status"] == "present":
            ind = assets.indicators_by_id[m["id"]]
            if ind.followup_probe_id not in followup_probes:
                followup_probes.append(ind.followup_probe_id)

    for rule in assets.probes_config.get("dynamic_followup_rules", []):
        triggers = set(rule.get("trigger_indicators", []))
        if triggers & present_turn_ids:
            triggered_rules.append(rule)
            for p_id in rule.get("priority_probes", []):
                if p_id not in followup_probes:
                    followup_probes.append(p_id)

    canary_domain = infer_canary_domain(
        sanitized_text,
        all_present_ids,
        previous_domain=previous_canary_domain,
    )

    return {
        "turn_matches": turn_matches,
        "merged_indicators": merged,
        "touched_tiers": sorted(touched_tiers),
        "triggered_rules": triggered_rules,
        "followup_probe_ids": followup_probes,
        "inferred_canary_domain": canary_domain,
    }
