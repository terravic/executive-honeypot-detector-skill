"""Executive Synthesis Module and passive Canary Protocol generator.

Transforms scored session indicators into structured JSON and Markdown
executive diagnostic briefs with OPSEC redaction verification and
domain-tailored countermeasures.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from scripts.bayesian_scorer import score_indicators
from scripts.interview_engine import validate_session_dict
from scripts.sanitizer import sanitize_text
from scripts.taxonomy_engine import LoadedAssets, load_and_validate_assets

REPORT_SCHEMA_VERSION = "1.0.0"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_report(
    session: dict[str, Any],
    assets: LoadedAssets | None = None,
    session_purged: bool = False,
) -> dict[str, Any]:
    """Synthesize both structured JSON and rendered Markdown executive reports."""
    loaded = assets or load_and_validate_assets()
    validated_session = validate_session_dict(session)
    generated_at = _utc_now()

    risk = score_indicators(
        indicator_states=validated_session.get("indicators", {}),
        assets=loaded,
        risk_profile=validated_session.get("risk_profile", "standard"),
        covered_tiers=validated_session.get("covered_tiers", []),
    )

    class_id = risk["classification"]["id"]
    cm_block = loaded.probes_config["countermeasures"][class_id]
    canary_domain = validated_session.get("inferred_canary_domain", "general_operations")
    canary_map = loaded.probes_config["canary_protocols"]
    canary_entry = canary_map.get(canary_domain, canary_map["general_operations"])
    disclaimer = loaded.probes_config["legal_disclaimer"]

    canary_recommended = class_id == "tier_3_ci_honeypot" or (
        risk["posteriors"]["tier_3_ci_honeypot"] >= 0.25
    )

    report_json: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "session_id": validated_session["session_id"],
        "generated_at": generated_at,
        "risk_profile": validated_session["risk_profile"],
        "classification": {
            "id": class_id,
            "label": risk["classification"]["label"],
            "posture_summary": cm_block["posture_summary"],
        },
        "confidence": risk["confidence"],
        "posteriors": risk["posteriors"],
        "composite_risk_score": risk["composite_risk_score"],
        "tier_breakdown": risk["tier_breakdown"],
        "blind_spots": risk["blind_spots"],
        "indicators_summary": risk["indicators_summary"],
        "top_drivers": risk["top_drivers"],
        "countermeasures": cm_block["phases"],
        "canary_protocol": {
            "recommended": canary_recommended,
            "domain_key": canary_domain,
            "domain_label": canary_entry["domain_label"],
            "script": canary_entry["script"],
            "observation_criteria": canary_entry["observation_criteria"],
            "safety_guardrail": canary_entry["safety_guardrail"],
        },
        "opsec_metadata": {
            "redaction_count": int(validated_session.get("redaction_count", 0)),
            "turn_count": int(validated_session.get("turn_count", 0)),
            "session_purged": bool(session_purged),
        },
        "legal_disclaimer": disclaimer,
    }

    markdown_text = _render_markdown(
        report_json=report_json,
        indicators=validated_session.get("indicators", {}),
        loaded=loaded,
        sensitive_terms=validated_session.get("sensitive_terms", []),
    )

    return {
        "report_json": report_json,
        "report_markdown": markdown_text,
    }


def _render_markdown(
    report_json: dict[str, Any],
    indicators: dict[str, dict[str, Any]],
    loaded: LoadedAssets,
    sensitive_terms: list[str],
) -> str:
    """Populate assets/report_template.md and perform final OPSEC scrub."""
    conf = report_json["confidence"]
    if conf["insufficient_data"]:
        confidence_warning = (
            "> **PRELIMINARY ASSESSMENT NOTICE:** Fewer than 3 of the 5 core "
            "counterintelligence tiers have been evaluated "
            f"({conf['core_tiers_covered']}/5 covered). Treat this classification "
            "as provisional until the unassessed blind spots below are reviewed."
        )
    else:
        confidence_warning = (
            f"Assessment completed across {conf['core_tiers_covered']} of 5 core "
            "counterintelligence dimensions."
        )

    tier_rows: list[str] = []
    for row in report_json["tier_breakdown"]:
        status_label = "Assessed" if row["covered"] else "Unassessed"
        active_str = ", ".join(row["active_indicators"]) or "None"
        neg_str = ", ".join(row["disconfirming_indicators"]) or "None"
        tier_rows.append(
            f"| {row['label']} | {status_label} | `{row['risk_index']:.1f}` | "
            f"{active_str} | {neg_str} |"
        )

    if report_json["blind_spots"]:
        blind_spots_md = "\n".join(
            f"- {label}: Not evaluated during this session."
            for label in report_json["blind_spots"]
        )
    else:
        blind_spots_md = "All six diagnostic domains were evaluated during this session."

    top_drivers = report_json["top_drivers"]
    if top_drivers:
        evidence_lines = [
            "| Indicator ID | Indicator Name | Status | Confidence | Damping | Log-LR Impact |",
            "|---|---|---|---|---|---|",
        ]
        for drv in top_drivers:
            state_record = indicators.get(drv["id"], {})
            conflict_note = " (conflict flagged)" if state_record.get("conflict_flagged") else ""
            evidence_lines.append(
                f"| `{drv['id']}` | {drv['name']} | {drv['status']}{conflict_note} | "
                f"`{drv['confidence']:.2f}` | `{drv['damping_factor']:.2f}` | "
                f"`{drv['impact_spread']:.2f}` |"
            )
        indicator_evidence_md = "\n".join(evidence_lines)
    else:
        indicator_evidence_md = (
            "No specific positive or disconfirming indicators were recorded."
        )

    cm_lines: list[str] = []
    for phase in report_json["countermeasures"]:
        cm_lines.append(f"### {phase['phase']}")
        cm_lines.append(f"- **Action:** {phase['action']}")
        cm_lines.append(f"- **Operational Objective:** {phase['objective']}")
        cm_lines.append("")
    countermeasures_md = "\n".join(cm_lines).strip()

    canary = report_json["canary_protocol"]
    if canary["recommended"]:
        canary_md = "\n".join(
            [
                f"- **Deployment Recommendation:** Recommended (coordinate with CSO/General Counsel before executing)",
                f"- **Tailored Domain:** {canary['domain_label']}",
                f"- **Passive Canary Script:** {canary['script']}",
                f"- **Observation Criteria:** {canary['observation_criteria']}",
                f"- **Legal and Operational Guardrail:** {canary['safety_guardrail']}",
            ]
        )
    else:
        canary_md = "\n".join(
            [
                "- **Deployment Recommendation:** Not required under current risk classification.",
                f"- **Reference Domain (If Conditions Change):** {canary['domain_label']}",
                f"- **Reference Script:** {canary['script']}",
                f"- **Guardrail:** {canary['safety_guardrail']}",
            ]
        )

    posteriors = report_json["posteriors"]
    summary = report_json["indicators_summary"]

    rendered = loaded.report_template.format(
        session_id=report_json["session_id"],
        generated_at=report_json["generated_at"],
        risk_profile=report_json["risk_profile"],
        redaction_count=report_json["opsec_metadata"]["redaction_count"],
        classification_label=report_json["classification"]["label"],
        confidence_level=conf["level"].upper(),
        coverage_percent=f"{conf['coverage_percent']:.1f}",
        composite_risk_score=f"{report_json['composite_risk_score']:.1f}",
        present_count=summary["present_count"],
        absent_count=summary["absent_count"],
        confidence_warning=confidence_warning,
        posture_summary=report_json["classification"]["posture_summary"],
        p_benign_pct=f"{posteriors['tier_1_benign'] * 100.0:.2f}",
        p_fraud_pct=f"{posteriors['tier_2_commercial_fraud'] * 100.0:.2f}",
        p_ci_pct=f"{posteriors['tier_3_ci_honeypot'] * 100.0:.2f}",
        tier_breakdown_rows="\n".join(tier_rows),
        blind_spots_section=blind_spots_md,
        indicator_evidence_section=indicator_evidence_md,
        countermeasures_section=countermeasures_md,
        canary_section=canary_md,
        legal_disclaimer=report_json["legal_disclaimer"],
    )

    # Final defensive pass guaranteeing zero sensitive terms survive into rendered markdown.
    final_scrub = sanitize_text(rendered, sensitive_terms=sensitive_terms)
    return final_scrub.sanitized_text
