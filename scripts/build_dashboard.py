"""Standalone HTML Dashboard Builder for the Counterintelligence Honeypot Skill.

Runs the deterministic skill engines over either a live/ephemeral session, a
generated JSON report, or the repository's synthetic calibration scenarios, and
emits a self-contained, offline interactive `dashboard.html`. Uses only the
Python 3.10+ standard library.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_ROOT_DIR = Path(__file__).resolve().parent.parent
if str(_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(_ROOT_DIR))

from scripts import PROJECT_ROOT, SkillError, ValidationError, configure_logging, get_assets_dir
from scripts.bayesian_scorer import _effective_likelihood, score_indicators
from scripts.interview_engine import (
    create_session,
    load_session_from_file,
    load_session_from_json,
    process_turn,
)
from scripts.report_generator import generate_report
from scripts.sanitizer import sanitize_text, validate_safe_path
from scripts.taxonomy_engine import HYPOTHESIS_IDS, LoadedAssets, load_and_validate_assets

DEFAULT_OUTPUT_PATH = PROJECT_ROOT / "dashboard.html"
DEFAULT_SCENARIOS_PATH = PROJECT_ROOT / "tests" / "fixtures" / "synthetic_scenarios.json"
DATA_PLACEHOLDER = "__DASHBOARD_DATA_JSON__"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def detect_system_theme() -> str:
    """Query host OS appearance preference ('light' or 'dark')."""
    platform = sys.platform

    if platform == "darwin":
        try:
            proc = subprocess.run(
                ["defaults", "read", "-g", "AppleInterfaceStyle"],
                capture_output=True,
                text=True,
                timeout=1.5,
                check=False,
            )
            if proc.returncode == 0 and "dark" in proc.stdout.lower():
                return "dark"
        except (OSError, subprocess.SubprocessError):
            pass
        return "light"

    if platform.startswith("win"):
        try:
            import winreg  # type: ignore[import-not-found]

            key_path = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                val, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
                return "dark" if int(val) == 0 else "light"
        except Exception:
            return "light"

    # Linux / POSIX fallback checks: GTK_THEME, gsettings, kdeglobals.
    gtk_theme = os.environ.get("GTK_THEME", "").lower()
    if "dark" in gtk_theme:
        return "dark"

    for key in ("color-scheme", "gtk-theme"):
        try:
            proc = subprocess.run(
                ["gsettings", "get", "org.gnome.desktop.interface", key],
                capture_output=True,
                text=True,
                timeout=1.5,
                check=False,
            )
            if proc.returncode == 0 and "dark" in proc.stdout.lower():
                return "dark"
        except (OSError, subprocess.SubprocessError):
            continue

    kde_cfg = Path.home() / ".config" / "kdeglobals"
    try:
        if kde_cfg.is_file():
            for line in kde_cfg.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.strip().lower().startswith("colorscheme=") and "dark" in line.lower():
                    return "dark"
    except OSError:
        pass

    return "light"


def compute_all_indicator_drivers(
    indicator_states: dict[str, dict[str, Any]],
    assets: LoadedAssets,
) -> list[dict[str, Any]]:
    """Compute exact damped log-likelihood attribution across ALL assessed indicators."""
    assessed_by_tier: dict[str, list[tuple[float, str, dict[str, Any], dict[str, float]]]] = (
        defaultdict(list)
    )

    for ind_id, state in indicator_states.items():
        if ind_id not in assets.indicators_by_id:
            continue
        status = state.get("status", "unknown")
        if status not in {"present", "absent"}:
            continue
        confidence = float(state.get("confidence", 0.0))
        if confidence <= 0.0:
            continue

        ind = assets.indicators_by_id[ind_id]
        eff_likes = {
            h: _effective_likelihood(ind.likelihoods[h], status, confidence)
            for h in HYPOTHESIS_IDS
        }
        log_vals = [math.log(v) for v in eff_likes.values()]
        max_log_spread = max(log_vals) - min(log_vals)
        assessed_by_tier[ind.tier].append((max_log_spread, ind_id, state, eff_likes))

    records: list[dict[str, Any]] = []
    for tier_id, items in assessed_by_tier.items():
        items.sort(key=lambda row: (-row[0], row[1]))
        for rank_idx, (_, ind_id, state, eff_likes) in enumerate(items, start=1):
            damping = 1.0 / math.sqrt(rank_idx)
            log_deltas = {
                h_id: round(damping * math.log(eff_likes[h_id]), 4)
                for h_id in HYPOTHESIS_IDS
            }
            ind = assets.indicators_by_id[ind_id]
            records.append(
                {
                    "id": ind_id,
                    "name": ind.name,
                    "tier": tier_id,
                    "stage_mapping": ind.stage_mapping,
                    "severity_weight": ind.severity_weight,
                    "status": state["status"],
                    "confidence": round(float(state["confidence"]), 4),
                    "source": state.get("source", "structured"),
                    "conflict_flagged": bool(state.get("conflict_flagged", False)),
                    "damping_rank": rank_idx,
                    "damping_factor": round(damping, 4),
                    "log_likelihood_deltas": log_deltas,
                    "impact_spread": round(
                        max(log_deltas.values()) - min(log_deltas.values()), 4
                    ),
                }
            )

    records.sort(key=lambda d: (-d["impact_spread"], d["id"]))
    return records


def _serialize_catalog(assets: LoadedAssets) -> dict[str, Any]:
    """Serialize authoritative taxonomy and probes for client-side engine parity."""
    return {
        "taxonomy": assets.taxonomy,
        "probes_config": assets.probes_config,
    }


def _prior_trajectory_entry(risk_profile: str, assets: LoadedAssets) -> dict[str, Any]:
    priors = {
        h: round(float(assets.taxonomy["prior_profiles"][risk_profile][h]), 6)
        for h in HYPOTHESIS_IDS
    }
    non_benign = 1.0 - priors["tier_1_benign"]
    prior_score = round(non_benign * 35.0, 1)
    inception = assets.probes_config["inception_prompt"]
    return {
        "turn": 0,
        "label": "Prior",
        "timestamp": None,
        "sanitized_excerpt": f"Baseline prior profile ({risk_profile}) before narrative evidence.",
        "posteriors": priors,
        "composite_risk_score": prior_score,
        "matched_indicators": [],
        "triggered_dynamic_rules": [],
        "redactions_applied": 0,
        "redacted_categories": {},
        "probe_asked": {
            "probe_id": inception["probe_id"],
            "tier": inception["tier"],
            "question": inception["question"],
        },
        "next_probe": None,
    }


def _build_rules_detail(rule_ids: list[str], assets: LoadedAssets) -> list[dict[str, Any]]:
    rules_by_id = {
        r["rule_id"]: r for r in assets.probes_config.get("dynamic_followup_rules", [])
    }
    return [rules_by_id[rid] for rid in rule_ids if rid in rules_by_id]


def build_scenario_dataset(
    scenario: dict[str, Any],
    assets: LoadedAssets,
) -> dict[str, Any]:
    """Execute a multi-turn scenario through the live skill pipeline and collect telemetry."""
    risk_profile = scenario.get("risk_profile", "standard")
    sensitive_terms = scenario.get("sensitive_terms", [])
    session = create_session(
        risk_profile=risk_profile,
        sensitive_terms=sensitive_terms,
        assets=assets,
    )

    trajectory: list[dict[str, Any]] = [_prior_trajectory_entry(risk_profile, assets)]
    redacted_totals: dict[str, int] = {}
    current_probe: dict[str, Any] = {
        "probe_id": assets.probes_config["inception_prompt"]["probe_id"],
        "tier": assets.probes_config["inception_prompt"]["tier"],
        "question": assets.probes_config["inception_prompt"]["question"],
    }

    for turn in scenario.get("turns", []):
        res = process_turn(
            session=session,
            narrative=turn["narrative"],
            structured_observations=turn.get("observations") or None,
            assets=assets,
        )
        session = res["session"]
        ta = res["turn_analysis"]
        snap = res["risk_snapshot"]

        for cat, cnt in ta.get("redacted_categories", {}).items():
            redacted_totals[cat] = redacted_totals.get(cat, 0) + int(cnt)

        trajectory.append(
            {
                "turn": ta["turn"],
                "label": f"Turn {ta['turn']}",
                "timestamp": session["updated_at"],
                "sanitized_excerpt": ta["sanitized_excerpt"],
                "posteriors": snap["posteriors"],
                "composite_risk_score": snap["composite_risk_score"],
                "matched_indicators": [
                    {
                        "id": m["id"],
                        "tier": m["tier"],
                        "status": m["status"],
                        "confidence": m["confidence"],
                        "source": m["source"],
                        "conflict_flagged": bool(m.get("conflict_flagged", False)),
                    }
                    for m in ta["matched_indicators"]
                ],
                "triggered_dynamic_rules": ta["triggered_dynamic_rules"],
                "redactions_applied": ta["redactions_applied"],
                "redacted_categories": ta["redacted_categories"],
                "probe_asked": current_probe,
                "next_probe": res["next_probe"],
            }
        )
        if res["next_probe"]:
            current_probe = {
                "probe_id": res["next_probe"]["probe_id"],
                "tier": res["next_probe"]["tier"],
                "question": res["next_probe"]["question"],
            }

    report_bundle = generate_report(session=session, assets=assets, session_purged=True)
    report_json = report_bundle["report_json"]
    all_drivers = compute_all_indicator_drivers(session.get("indicators", {}), assets)

    # Extra defensive pass guaranteeing zero sensitive_terms survive anywhere in dataset.
    scrubbed_indicators: dict[str, dict[str, Any]] = {}
    for ind_id, rec in session.get("indicators", {}).items():
        clean_rec = dict(rec)
        if "evidence_excerpt" in clean_rec and isinstance(clean_rec["evidence_excerpt"], str):
            clean_rec["evidence_excerpt"] = sanitize_text(
                clean_rec["evidence_excerpt"], sensitive_terms=sensitive_terms
            ).sanitized_text
        scrubbed_indicators[ind_id] = clean_rec

    return {
        "id": scenario["id"],
        "label": scenario["label"],
        "source_type": "reference_scenario",
        "risk_profile": risk_profile,
        "session_id": session["session_id"],
        "stage": "completed",
        "generated_at": report_json["generated_at"],
        "priors": trajectory[0]["posteriors"],
        "report": report_json,
        "all_drivers": all_drivers,
        "indicator_states": scrubbed_indicators,
        "trajectory": trajectory,
        "dynamic_rules_triggered": _build_rules_detail(
            session.get("dynamic_rules_triggered", []), assets
        ),
        "covered_tiers": session.get("covered_tiers", []),
        "asked_probe_ids": session.get("asked_probe_ids", []),
        "redacted_categories_totals": redacted_totals,
    }


def build_session_dataset(
    session: dict[str, Any],
    assets: LoadedAssets,
    dataset_id: str = "live_session",
    label: str = "Active Diagnostic Session",
    session_purged: bool = False,
) -> dict[str, Any]:
    """Convert an existing ephemeral session JSON into a complete dashboard dataset."""
    risk_profile = session.get("risk_profile", "standard")
    sensitive_terms = session.get("sensitive_terms", [])
    report_bundle = generate_report(
        session=session, assets=assets, session_purged=session_purged
    )
    report_json = report_bundle["report_json"]
    indicators = session.get("indicators", {})
    all_drivers = compute_all_indicator_drivers(indicators, assets)

    # Reconstruct turn-by-turn trajectory deterministically from session turn_history.
    trajectory: list[dict[str, Any]] = [_prior_trajectory_entry(risk_profile, assets)]
    cumulative_indicators: dict[str, dict[str, Any]] = {}
    cumulative_tiers: set[str] = set()
    rules_by_trigger = assets.probes_config.get("dynamic_followup_rules", [])

    for entry in session.get("turn_history", []):
        matched_records: list[dict[str, Any]] = []
        turn_present: set[str] = set()
        for ind_id in entry.get("matched_indicator_ids", []):
            if ind_id in indicators:
                rec = indicators[ind_id]
                cumulative_indicators[ind_id] = rec
                cumulative_tiers.add(rec["tier"])
                if rec.get("status") == "present":
                    turn_present.add(ind_id)
                matched_records.append(
                    {
                        "id": rec["id"],
                        "tier": rec["tier"],
                        "status": rec["status"],
                        "confidence": rec["confidence"],
                        "source": rec["source"],
                        "conflict_flagged": bool(rec.get("conflict_flagged", False)),
                    }
                )
        snap = score_indicators(
            indicator_states=cumulative_indicators,
            assets=assets,
            risk_profile=risk_profile,
            covered_tiers=sorted(cumulative_tiers),
        )
        triggered = [
            {
                "rule_id": r["rule_id"],
                "vector_label": r["vector_label"],
                "next_action": r["next_action"],
            }
            for r in rules_by_trigger
            if set(r.get("trigger_indicators", [])) & turn_present
        ]
        safe_excerpt = sanitize_text(
            str(entry.get("sanitized_excerpt", "")), sensitive_terms=sensitive_terms
        ).sanitized_text
        trajectory.append(
            {
                "turn": int(entry.get("turn", len(trajectory))),
                "label": f"Turn {entry.get('turn', len(trajectory))}",
                "timestamp": entry.get("timestamp"),
                "sanitized_excerpt": safe_excerpt,
                "posteriors": snap["posteriors"],
                "composite_risk_score": snap["composite_risk_score"],
                "matched_indicators": matched_records,
                "triggered_dynamic_rules": triggered,
                "redactions_applied": int(entry.get("redactions_in_turn", 0)),
                "redacted_categories": {},
                "probe_asked": None,
                "next_probe": None,
            }
        )

    scrubbed_indicators: dict[str, dict[str, Any]] = {}
    for ind_id, rec in indicators.items():
        clean_rec = dict(rec)
        if "evidence_excerpt" in clean_rec and isinstance(clean_rec["evidence_excerpt"], str):
            clean_rec["evidence_excerpt"] = sanitize_text(
                clean_rec["evidence_excerpt"], sensitive_terms=sensitive_terms
            ).sanitized_text
        scrubbed_indicators[ind_id] = clean_rec

    return {
        "id": dataset_id,
        "label": label,
        "source_type": "live_session",
        "risk_profile": risk_profile,
        "session_id": session["session_id"],
        "stage": session.get("stage", "completed"),
        "generated_at": report_json["generated_at"],
        "priors": trajectory[0]["posteriors"],
        "report": report_json,
        "all_drivers": all_drivers,
        "indicator_states": scrubbed_indicators,
        "trajectory": trajectory,
        "dynamic_rules_triggered": _build_rules_detail(
            session.get("dynamic_rules_triggered", []), assets
        ),
        "covered_tiers": session.get("covered_tiers", []),
        "asked_probe_ids": session.get("asked_probe_ids", []),
        "redacted_categories_totals": {},
    }


def build_report_dataset(
    report_json: dict[str, Any],
    assets: LoadedAssets,
    dataset_id: str = "imported_report",
    label: str = "Imported Executive Report",
) -> dict[str, Any]:
    """Convert a standalone generated report JSON into a dashboard dataset."""
    risk_profile = report_json.get("risk_profile", "standard")
    prior_entry = _prior_trajectory_entry(risk_profile, assets)

    indicator_states: dict[str, dict[str, Any]] = {}
    for tb in report_json.get("tier_breakdown", []):
        for ind_id in tb.get("active_indicators", []):
            indicator_states[ind_id] = {
                "id": ind_id,
                "tier": tb["tier_id"],
                "status": "present",
                "confidence": 0.85,
                "source": "structured",
                "evidence_excerpt": "Imported from finalized diagnostic report.",
                "conflict_flagged": False,
            }
        for ind_id in tb.get("disconfirming_indicators", []):
            indicator_states[ind_id] = {
                "id": ind_id,
                "tier": tb["tier_id"],
                "status": "absent",
                "confidence": 0.85,
                "source": "structured",
                "evidence_excerpt": "Imported from finalized diagnostic report.",
                "conflict_flagged": False,
            }

    for drv in report_json.get("top_drivers", []):
        if drv["id"] in indicator_states:
            indicator_states[drv["id"]]["confidence"] = drv["confidence"]

    all_drivers = compute_all_indicator_drivers(indicator_states, assets)
    active_ids = {
        k for k, v in indicator_states.items() if v.get("status") == "present"
    }
    triggered_rules = [
        r
        for r in assets.probes_config.get("dynamic_followup_rules", [])
        if set(r.get("trigger_indicators", [])) & active_ids
    ]

    trajectory = [
        prior_entry,
        {
            "turn": max(1, int(report_json.get("opsec_metadata", {}).get("turn_count", 1))),
            "label": "Final",
            "timestamp": report_json.get("generated_at"),
            "sanitized_excerpt": "Imported finalized report snapshot (per-turn history not present in standalone report JSON).",
            "posteriors": report_json["posteriors"],
            "composite_risk_score": report_json["composite_risk_score"],
            "matched_indicators": [
                {
                    "id": k,
                    "tier": v["tier"],
                    "status": v["status"],
                    "confidence": v["confidence"],
                    "source": v["source"],
                    "conflict_flagged": False,
                }
                for k, v in sorted(indicator_states.items())
            ],
            "triggered_dynamic_rules": [
                {
                    "rule_id": r["rule_id"],
                    "vector_label": r["vector_label"],
                    "next_action": r["next_action"],
                }
                for r in triggered_rules
            ],
            "redactions_applied": int(
                report_json.get("opsec_metadata", {}).get("redaction_count", 0)
            ),
            "redacted_categories": {},
            "probe_asked": None,
            "next_probe": None,
        },
    ]

    return {
        "id": dataset_id,
        "label": label,
        "source_type": "imported_report",
        "risk_profile": risk_profile,
        "session_id": report_json.get("session_id", "report-import"),
        "stage": "completed",
        "generated_at": report_json.get("generated_at", _utc_now()),
        "priors": prior_entry["posteriors"],
        "report": report_json,
        "all_drivers": all_drivers,
        "indicator_states": indicator_states,
        "trajectory": trajectory,
        "dynamic_rules_triggered": triggered_rules,
        "covered_tiers": [
            tb["tier_id"]
            for tb in report_json.get("tier_breakdown", [])
            if tb.get("covered")
        ],
        "asked_probe_ids": [],
        "redacted_categories_totals": {},
    }


def build_dashboard_bundle(
    assets: LoadedAssets | None = None,
    session: dict[str, Any] | None = None,
    report_json: dict[str, Any] | None = None,
    include_reference_scenarios: bool = True,
    scenarios_path: Path | None = None,
) -> dict[str, Any]:
    """Assemble the complete JSON data bundle injected into dashboard.html."""
    loaded = assets or load_and_validate_assets()
    datasets: list[dict[str, Any]] = []
    default_dataset_id: str | None = None

    if session is not None:
        ds = build_session_dataset(session, loaded)
        datasets.append(ds)
        default_dataset_id = ds["id"]
    elif report_json is not None:
        ds = build_report_dataset(report_json, loaded)
        datasets.append(ds)
        default_dataset_id = ds["id"]

    if include_reference_scenarios:
        sc_path = scenarios_path or DEFAULT_SCENARIOS_PATH
        if sc_path.is_file():
            raw = json.loads(sc_path.read_text(encoding="utf-8"))
            for sc in raw.get("scenarios", []):
                datasets.append(build_scenario_dataset(sc, loaded))

    if not datasets:
        raise ValidationError(
            "No datasets available to render. Provide --session-file, --report-json, "
            "or retain synthetic reference scenarios."
        )

    if default_dataset_id is None:
        ids = [d["id"] for d in datasets]
        default_dataset_id = (
            "scenario_c_ci_honeypot" if "scenario_c_ci_honeypot" in ids else ids[0]
        )

    return {
        "schema_version": "1.0.0",
        "generated_at": _utc_now(),
        "system_theme": detect_system_theme(),
        "default_dataset_id": default_dataset_id,
        "catalog": _serialize_catalog(loaded),
        "datasets": datasets,
    }


def render_dashboard_html(
    bundle: dict[str, Any],
    assets_dir: str | Path | None = None,
) -> str:
    """Inject the JSON data bundle safely into assets/dashboard_template.html."""
    template_path = get_assets_dir(assets_dir) / "dashboard_template.html"
    if not template_path.is_file():
        raise ValidationError(f"Dashboard template not found: {template_path}")

    template = template_path.read_text(encoding="utf-8")
    if DATA_PLACEHOLDER not in template:
        raise ValidationError(
            f"Dashboard template missing required placeholder {DATA_PLACEHOLDER}."
        )

    # Escape closing script sequences defensively before inline embedding.
    serialized = json.dumps(bundle, ensure_ascii=True, separators=(",", ":")).replace(
        "</", "<\\/"
    )
    return template.replace(DATA_PLACEHOLDER, serialized, 1)


def write_dashboard(
    output_path: str | Path = DEFAULT_OUTPUT_PATH,
    assets_dir: str | Path | None = None,
    session: dict[str, Any] | None = None,
    report_json: dict[str, Any] | None = None,
    include_reference_scenarios: bool = True,
) -> dict[str, Any]:
    """Build and write standalone dashboard.html to disk safely."""
    loaded = load_and_validate_assets(assets_dir)
    bundle = build_dashboard_bundle(
        assets=loaded,
        session=session,
        report_json=report_json,
        include_reference_scenarios=include_reference_scenarios,
    )
    html = render_dashboard_html(bundle, assets_dir=assets_dir)
    target = validate_safe_path(output_path, must_exist=False)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(html, encoding="utf-8")

    return {
        "status": "ok",
        "output_path": str(target),
        "bytes_written": len(html.encode("utf-8")),
        "default_dataset_id": bundle["default_dataset_id"],
        "dataset_count": len(bundle["datasets"]),
        "system_theme": bundle["system_theme"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="build_dashboard.py",
        description="Generate standalone interactive dashboard.html for Executive Honeypot Diagnostics.",
    )
    parser.add_argument(
        "--session-file",
        default=None,
        help="Optional ephemeral session JSON file to feature as the active dataset.",
    )
    parser.add_argument(
        "--session-json",
        default=None,
        help="Optional inline session JSON string to feature as the active dataset.",
    )
    parser.add_argument(
        "--report-json",
        default=None,
        help="Optional finalized diagnostic report JSON file to render.",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT_PATH),
        help="Output HTML file path (default: ./dashboard.html).",
    )
    parser.add_argument(
        "--assets-dir",
        default=None,
        help="Optional override path for declarative assets directory.",
    )
    parser.add_argument(
        "--no-scenarios",
        action="store_true",
        help="Omit synthetic reference calibration scenarios (requires --session-file, --session-json, or --report-json).",
    )
    parser.add_argument(
        "--log-level",
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Optional logging verbosity sent strictly to stderr.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2

    configure_logging(args.log_level)

    try:
        session_obj: dict[str, Any] | None = None
        report_obj: dict[str, Any] | None = None

        if args.session_file:
            session_obj = load_session_from_file(args.session_file)
        elif args.session_json:
            session_obj = load_session_from_json(args.session_json)
        elif args.report_json:
            rep_path = validate_safe_path(args.report_json, must_exist=True)
            try:
                report_obj = json.loads(rep_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValidationError(
                    f"Unable to read or parse report JSON ({rep_path}): {exc}"
                ) from exc

        result = write_dashboard(
            output_path=args.output,
            assets_dir=args.assets_dir,
            session=session_obj,
            report_json=report_obj,
            include_reference_scenarios=not args.no_scenarios,
        )
        sys.stdout.write(json.dumps(result, indent=2) + "\n")
        return 0
    except SkillError as exc:
        sys.stderr.write(
            json.dumps(
                {
                    "status": "error",
                    "error_type": type(exc).__name__,
                    "message": str(exc),
                },
                indent=2,
            )
            + "\n"
        )
        return exc.exit_code
    except Exception as exc:  # pragma: no cover - defensive fallback
        sys.stderr.write(
            json.dumps(
                {
                    "status": "error",
                    "error_type": "UnexpectedError",
                    "message": str(exc),
                },
                indent=2,
            )
            + "\n"
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
