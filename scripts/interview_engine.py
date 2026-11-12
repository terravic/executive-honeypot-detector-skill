"""Dynamic Interview Core state machine and adaptive probe selection engine.

Manages ephemeral diagnostic sessions, prevents redundant questioning, tracks
coverage across all six diagnostic domains, and prioritizes high-risk
follow-up probes when counterintelligence or fraud indicators are detected.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scripts import SessionError, ValidationError
from scripts.bayesian_scorer import score_indicators
from scripts.sanitizer import (
    make_safe_excerpt,
    normalize_sensitive_terms,
    sanitize_text,
    validate_narrative,
    validate_safe_path,
)
from scripts.taxonomy_engine import (
    LoadedAssets,
    extract_indicators,
    load_and_validate_assets,
)

logger = logging.getLogger("honeypot_skill.interview")

SESSION_SCHEMA_VERSION = "1.0.0"
REQUIRED_SESSION_KEYS = frozenset(
    {
        "schema_version",
        "session_id",
        "created_at",
        "updated_at",
        "stage",
        "risk_profile",
        "turn_count",
        "redaction_count",
        "covered_tiers",
        "asked_probe_ids",
        "pending_followup_probes",
        "dynamic_rules_triggered",
        "indicators",
        "inferred_canary_domain",
    }
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def create_session(
    risk_profile: str = "standard",
    sensitive_terms: list[str] | None = None,
    assets: LoadedAssets | None = None,
) -> dict[str, Any]:
    """Initialize a fresh ephemeral diagnostic session."""
    loaded = assets or load_and_validate_assets()
    if risk_profile not in loaded.taxonomy["prior_profiles"]:
        raise ValidationError(
            f"Unsupported risk_profile '{risk_profile}'. "
            f"Allowed: {sorted(loaded.taxonomy['prior_profiles'].keys())}."
        )

    now = _utc_now()
    inception = loaded.probes_config["inception_prompt"]
    session = {
        "schema_version": SESSION_SCHEMA_VERSION,
        "session_id": f"diag-{uuid.uuid4().hex[:12]}",
        "created_at": now,
        "updated_at": now,
        "stage": "inception",
        "risk_profile": risk_profile,
        "turn_count": 0,
        "redaction_count": 0,
        "sensitive_terms": normalize_sensitive_terms(sensitive_terms),
        "covered_tiers": [],
        "asked_probe_ids": [inception["probe_id"]],
        "last_probe_tier": inception["tier"],
        "pending_followup_probes": [],
        "dynamic_rules_triggered": [],
        "inferred_canary_domain": "general_operations",
        "turn_history": [],
        "indicators": {},
    }
    return session


def validate_session_dict(data: Any) -> dict[str, Any]:
    """Verify structural integrity of a loaded ephemeral session dictionary."""
    if not isinstance(data, dict):
        raise SessionError("Session payload must be a JSON object.")
    missing = REQUIRED_SESSION_KEYS - set(data.keys())
    if missing:
        raise SessionError(
            f"Session payload missing required keys: {sorted(missing)}."
        )
    if data.get("stage") not in {
        "inception",
        "probing",
        "ready_for_synthesis",
        "completed",
    }:
        raise SessionError(f"Invalid session stage: {data.get('stage')!r}.")
    if not isinstance(data.get("indicators"), dict):
        raise SessionError("Session field 'indicators' must be a JSON object.")
    if not isinstance(data.get("asked_probe_ids"), list):
        raise SessionError("Session field 'asked_probe_ids' must be a list.")
    if not isinstance(data.get("covered_tiers"), list):
        raise SessionError("Session field 'covered_tiers' must be a list.")
    return data


def load_session_from_file(path: str | Path) -> dict[str, Any]:
    """Load and validate an ephemeral session JSON file."""
    target = validate_safe_path(path, must_exist=True)
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SessionError(f"Failed to read or parse session file ({target}): {exc}") from exc
    return validate_session_dict(raw)


def load_session_from_json(raw_json: str) -> dict[str, Any]:
    """Parse and validate a session JSON string."""
    try:
        raw = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise SessionError(f"Corrupted session JSON string: {exc}") from exc
    return validate_session_dict(raw)


def save_session_to_file(session: dict[str, Any], path: str | Path) -> Path:
    """Persist a sanitized ephemeral session JSON to disk."""
    target = validate_safe_path(path, must_exist=False)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(session, indent=2), encoding="utf-8")
    except OSError as exc:
        raise SessionError(f"Failed to write session file ({target}): {exc}") from exc
    return target


def select_next_probe(
    session: dict[str, Any],
    risk_snapshot: dict[str, Any],
    assets: LoadedAssets,
) -> dict[str, Any] | None:
    """Choose the highest-value unasked probe or signal synthesis readiness.

    Selection strategy:
    1. Never repeat any probe ID already in session['asked_probe_ids'].
    2. Check stopping criteria: all 6 tiers covered, OR >= 4 core CI tiers covered
       with >= 0.92 posterior certainty and no urgent technical/elicitation probe left.
    3. Prioritize queued follow-up probes sorted by probe priority descending, while
       capping follow-ups within a single tier to 2 probes if core tiers remain uncovered.
    4. Fall back to the baseline probe for the next uncovered tier in priority order.
    """
    asked = set(session.get("asked_probe_ids", []))
    covered = set(session.get("covered_tiers", []))
    probes_map = assets.probes_config["probes"]

    asked_per_tier: dict[str, int] = {}
    for p_id in asked:
        meta = probes_map.get(p_id)
        if meta:
            t_id = meta["tier"]
            asked_per_tier[t_id] = asked_per_tier.get(t_id, 0) + 1

    ordered_tiers = sorted(
        assets.tiers_by_id.values(), key=lambda t: int(t.get("priority", 99))
    )
    uncovered_core_tiers = [
        t for t in ordered_tiers if t.get("core_ci_tier") and t["id"] not in covered
    ]
    uncovered_all_tiers = [t for t in ordered_tiers if t["id"] not in covered]

    # Prune already asked probes from pending follow-up queue.
    pending = [
        p_id
        for p_id in session.get("pending_followup_probes", [])
        if p_id in probes_map and p_id not in asked
    ]
    pending.sort(
        key=lambda p_id: (-int(probes_map[p_id].get("priority", 0)), p_id)
    )

    # Check high-priority urgent follow-up probes (technical/elicitation priority >= 35).
    urgent_pending = [
        p_id for p_id in pending if int(probes_map[p_id].get("priority", 0)) >= 35
    ]

    max_post = max(risk_snapshot["posteriors"].values())
    core_covered = risk_snapshot["confidence"]["core_tiers_covered"]

    if not uncovered_all_tiers and not urgent_pending:
        return None
    if core_covered >= 4 and max_post >= 0.92 and not urgent_pending and not uncovered_all_tiers:
        return None

    # First select from pending follow-ups if tier has not exceeded breadth cap.
    for p_id in pending:
        p_meta = probes_map[p_id]
        p_tier = p_meta["tier"]
        if uncovered_core_tiers and asked_per_tier.get(p_tier, 0) >= 2:
            # Defer secondary probes inside an already probed tier until core breadth is covered.
            continue
        return {
            "probe_id": p_id,
            "tier": p_tier,
            "reason": "triggered_indicator_followup",
            "priority": int(p_meta.get("priority", 0)),
            "question": p_meta["question"],
        }

    # Next select the baseline probe for the highest-priority uncovered tier.
    for tier_obj in uncovered_all_tiers:
        base_id = tier_obj["baseline_probe_id"]
        if base_id not in asked and base_id in probes_map:
            p_meta = probes_map[base_id]
            return {
                "probe_id": base_id,
                "tier": tier_obj["id"],
                "reason": "uncovered_tier_baseline",
                "priority": int(p_meta.get("priority", 0)),
                "question": p_meta["question"],
            }

    # Finally consume any remaining deferred follow-up probe if not yet ready.
    if pending:
        p_id = pending[0]
        p_meta = probes_map[p_id]
        return {
            "probe_id": p_id,
            "tier": p_meta["tier"],
            "reason": "secondary_followup",
            "priority": int(p_meta.get("priority", 0)),
            "question": p_meta["question"],
        }

    return None


def process_turn(
    session: dict[str, Any],
    narrative: str,
    structured_observations: list[dict[str, Any]] | None = None,
    assets: LoadedAssets | None = None,
) -> dict[str, Any]:
    """Ingest one sanitized executive turn, update risk scores, and select next probe."""
    loaded = assets or load_and_validate_assets()
    validated_session = validate_session_dict(session)
    cleaned_input = validate_narrative(narrative)

    san_res = sanitize_text(
        cleaned_input,
        sensitive_terms=validated_session.get("sensitive_terms", []),
    )

    extraction = extract_indicators(
        sanitized_text=san_res.sanitized_text,
        assets=loaded,
        structured_observations=structured_observations,
        existing_indicators=validated_session.get("indicators", {}),
        previous_canary_domain=validated_session.get(
            "inferred_canary_domain", "general_operations"
        ),
    )

    # Update session coverage: include tiers matched in this turn AND the tier of the
    # immediately preceding probe so neutral/negative conversational responses advance cleanly.
    covered = set(validated_session.get("covered_tiers", []))
    covered.update(extraction["touched_tiers"])
    last_tier = validated_session.get("last_probe_tier")
    if last_tier and last_tier in loaded.tiers_by_id:
        covered.add(last_tier)

    # Merge new pending follow-up probes while excluding already asked probes.
    asked = list(validated_session.get("asked_probe_ids", []))
    asked_set = set(asked)
    pending = list(validated_session.get("pending_followup_probes", []))
    for p_id in extraction["followup_probe_ids"]:
        if p_id not in asked_set and p_id not in pending:
            pending.append(p_id)

    rules_triggered = list(validated_session.get("dynamic_rules_triggered", []))
    for rule in extraction["triggered_rules"]:
        r_id = rule["rule_id"]
        if r_id not in rules_triggered:
            rules_triggered.append(r_id)

    # Prefer specific inferred Canary domains over generic fallback.
    prev_domain = validated_session.get("inferred_canary_domain", "general_operations")
    new_domain = extraction["inferred_canary_domain"]
    final_domain = new_domain if new_domain != "general_operations" else prev_domain

    validated_session["turn_count"] = int(validated_session.get("turn_count", 0)) + 1
    validated_session["redaction_count"] = (
        int(validated_session.get("redaction_count", 0)) + san_res.redaction_count
    )
    validated_session["updated_at"] = _utc_now()
    validated_session["covered_tiers"] = sorted(covered)
    validated_session["indicators"] = extraction["merged_indicators"]
    validated_session["pending_followup_probes"] = pending
    validated_session["dynamic_rules_triggered"] = rules_triggered
    validated_session["inferred_canary_domain"] = final_domain

    turn_history = list(validated_session.get("turn_history", []))
    turn_history.append(
        {
            "turn": validated_session["turn_count"],
            "timestamp": validated_session["updated_at"],
            "sanitized_excerpt": make_safe_excerpt(san_res.sanitized_text),
            "matched_indicator_ids": [m["id"] for m in extraction["turn_matches"]],
            "redactions_in_turn": san_res.redaction_count,
        }
    )
    validated_session["turn_history"] = turn_history

    risk_snapshot = score_indicators(
        indicator_states=validated_session["indicators"],
        assets=loaded,
        risk_profile=validated_session["risk_profile"],
        covered_tiers=validated_session["covered_tiers"],
    )

    next_probe = select_next_probe(validated_session, risk_snapshot, loaded)
    if next_probe is None:
        validated_session["stage"] = "ready_for_synthesis"
        validated_session["last_probe_tier"] = None
    else:
        validated_session["stage"] = "probing"
        validated_session["asked_probe_ids"].append(next_probe["probe_id"])
        validated_session["last_probe_tier"] = next_probe["tier"]
        validated_session["pending_followup_probes"] = [
            p
            for p in validated_session["pending_followup_probes"]
            if p != next_probe["probe_id"]
        ]

    return {
        "session": validated_session,
        "turn_analysis": {
            "turn": validated_session["turn_count"],
            "sanitized_excerpt": make_safe_excerpt(san_res.sanitized_text),
            "redactions_applied": san_res.redaction_count,
            "redacted_categories": san_res.redacted_categories,
            "matched_indicators": extraction["turn_matches"],
            "triggered_dynamic_rules": [
                {
                    "rule_id": r["rule_id"],
                    "vector_label": r["vector_label"],
                    "next_action": r["next_action"],
                }
                for r in extraction["triggered_rules"]
            ],
        },
        "risk_snapshot": risk_snapshot,
        "next_probe": next_probe,
        "ready_for_synthesis": next_probe is None,
    }
