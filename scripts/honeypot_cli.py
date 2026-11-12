"""Unified command-line interface for the Counterintelligence Honeypot Diagnostic Skill.

Provides deterministic, harness-agnostic subcommands returning structured JSON on
stdout and standard exit codes (0 success, 1 internal error, 2 validation error).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Ensure relative imports succeed whether executed as `python3 scripts/honeypot_cli.py`
# or `python3 -m scripts.honeypot_cli` from the repository root.
_ROOT_DIR = Path(__file__).resolve().parent.parent
if str(_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(_ROOT_DIR))

from scripts import SessionError, SkillError, ValidationError, configure_logging
from scripts.bayesian_scorer import score_indicators
from scripts.interview_engine import (
    create_session,
    load_session_from_file,
    load_session_from_json,
    process_turn,
    save_session_to_file,
)
from scripts.report_generator import generate_report
from scripts.sanitizer import secure_purge_file, validate_safe_path
from scripts.taxonomy_engine import (
    load_and_validate_assets,
    validate_structured_observations,
)


def _emit_json(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, indent=2) + "\n")


def _emit_error(error_type: str, message: str) -> None:
    sys.stderr.write(
        json.dumps(
            {
                "status": "error",
                "error_type": error_type,
                "message": message,
            },
            indent=2,
        )
        + "\n"
    )


def _parse_json_arg(raw: str | None, field_name: str) -> Any:
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"Invalid JSON passed to {field_name}: {exc}") from exc


def _load_session_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if getattr(args, "session_file", None):
        return load_session_from_file(args.session_file)
    if getattr(args, "session_json", None):
        return load_session_from_json(args.session_json)
    raise ValidationError(
        "Either --session-file or --session-json must be provided."
    )


def _cmd_validate_taxonomy(args: argparse.Namespace) -> int:
    assets = load_and_validate_assets(args.assets_dir)
    tier_counts: dict[str, int] = {}
    for ind in assets.indicators_by_id.values():
        tier_counts[ind.tier] = tier_counts.get(ind.tier, 0) + 1

    _emit_json(
        {
            "status": "ok",
            "schema_version": assets.taxonomy.get("schema_version"),
            "indicator_count": len(assets.indicators_by_id),
            "tier_counts": tier_counts,
            "prior_profiles": sorted(assets.taxonomy["prior_profiles"].keys()),
            "probe_count": len(assets.probes_config["probes"]),
            "dynamic_rule_count": len(assets.probes_config["dynamic_followup_rules"]),
        }
    )
    return 0


def _cmd_init_session(args: argparse.Namespace) -> int:
    assets = load_and_validate_assets(args.assets_dir)
    sensitive_terms = args.sensitive_terms or []
    session = create_session(
        risk_profile=args.risk_profile,
        sensitive_terms=sensitive_terms,
        assets=assets,
    )

    saved_path: str | None = None
    if args.session_file:
        path = save_session_to_file(session, args.session_file)
        saved_path = str(path)

    _emit_json(
        {
            "status": "ok",
            "session_file": saved_path,
            "session": session,
            "inception_prompt": assets.probes_config["inception_prompt"],
        }
    )
    return 0


def _cmd_analyze_turn(args: argparse.Namespace) -> int:
    assets = load_and_validate_assets(args.assets_dir)
    session = _load_session_from_args(args)

    if args.narrative is not None:
        narrative_text = args.narrative
    elif args.narrative_file is not None:
        narrative_path = validate_safe_path(args.narrative_file, must_exist=True)
        try:
            narrative_text = narrative_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ValidationError(
                f"Unable to read narrative file ({narrative_path}): {exc}"
            ) from exc
    else:
        raise ValidationError(
            "Either --narrative or --narrative-file must be provided."
        )

    observations = _parse_json_arg(args.observations_json, "--observations-json")
    result = process_turn(
        session=session,
        narrative=narrative_text,
        structured_observations=observations,
        assets=assets,
    )

    if args.session_file:
        save_session_to_file(result["session"], args.session_file)

    _emit_json(
        {
            "status": "ok",
            "session": result["session"],
            "turn_analysis": result["turn_analysis"],
            "risk_snapshot": result["risk_snapshot"],
            "next_probe": result["next_probe"],
            "ready_for_synthesis": result["ready_for_synthesis"],
        }
    )
    return 0


def _cmd_score(args: argparse.Namespace) -> int:
    assets = load_and_validate_assets(args.assets_dir)
    if args.session_file or args.session_json:
        session = _load_session_from_args(args)
        indicator_states = session.get("indicators", {})
        risk_profile = args.risk_profile or session.get("risk_profile", "standard")
        covered_tiers = session.get("covered_tiers", [])
    elif args.observations_json:
        obs_raw = _parse_json_arg(args.observations_json, "--observations-json")
        validated = validate_structured_observations(obs_raw, assets.indicators_by_id)
        indicator_states = {
            item["id"]: {
                "id": item["id"],
                "tier": assets.indicators_by_id[item["id"]].tier,
                "status": item["status"],
                "confidence": item["confidence"],
                "source": "structured",
            }
            for item in validated
        }
        risk_profile = args.risk_profile or "standard"
        covered_tiers = sorted({v["tier"] for v in indicator_states.values()})
    else:
        raise ValidationError(
            "Provide --observations-json, --session-file, or --session-json."
        )

    result = score_indicators(
        indicator_states=indicator_states,
        assets=assets,
        risk_profile=risk_profile,
        covered_tiers=covered_tiers,
    )
    _emit_json({"status": "ok", "risk_assessment": result})
    return 0


def _cmd_generate_report(args: argparse.Namespace) -> int:
    assets = load_and_validate_assets(args.assets_dir)
    session = _load_session_from_args(args)

    purged = False
    purge_details: dict[str, Any] | None = None

    # Render report before purging so report metadata reflects purge accurately.
    will_purge = bool(args.purge_session and args.session_file)
    report_bundle = generate_report(
        session=session,
        assets=assets,
        session_purged=will_purge,
    )

    if args.output_md:
        md_path = validate_safe_path(args.output_md, must_exist=False)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(report_bundle["report_markdown"], encoding="utf-8")

    if args.output_json:
        json_path = validate_safe_path(args.output_json, must_exist=False)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(
            json.dumps(report_bundle["report_json"], indent=2),
            encoding="utf-8",
        )

    if will_purge:
        purge_details = secure_purge_file(args.session_file)
        purged = True
    elif args.session_file:
        session["stage"] = "completed"
        save_session_to_file(session, args.session_file)

    _emit_json(
        {
            "status": "ok",
            "report_json": report_bundle["report_json"],
            "report_markdown": report_bundle["report_markdown"],
            "session_purged": purged,
            "purge_details": purge_details,
        }
    )
    return 0


def _cmd_purge_session(args: argparse.Namespace) -> int:
    details = secure_purge_file(args.session_file)
    _emit_json({"status": "ok", "purge_details": details})
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="honeypot_cli.py",
        description="Counterintelligence Honeypot Diagnostic Agent Skill CLI",
    )
    parser.add_argument(
        "--assets-dir",
        default=None,
        help="Optional override path for declarative assets directory.",
    )
    parser.add_argument(
        "--log-level",
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Optional logging verbosity sent strictly to stderr.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    p_val = subparsers.add_parser(
        "validate-taxonomy",
        help="Validate the 32-indicator catalog, probes, and Bayesian calibration.",
    )
    p_val.set_defaults(handler=_cmd_validate_taxonomy)

    p_init = subparsers.add_parser(
        "init-session",
        help="Initialize an ephemeral diagnostic session and return the Stage 1 prompt.",
    )
    p_init.add_argument(
        "--risk-profile",
        default="standard",
        choices=["standard", "high_exposure"],
        help="Baseline executive threat prior profile.",
    )
    p_init.add_argument(
        "--sensitive-terms",
        nargs="*",
        default=[],
        help="Optional sensitive names/entities to redact deterministically during the session.",
    )
    p_init.add_argument(
        "--session-file",
        default=None,
        help="Optional ephemeral JSON path for pause-and-resume state.",
    )
    p_init.set_defaults(handler=_cmd_init_session)

    p_turn = subparsers.add_parser(
        "analyze-turn",
        help="Sanitize a narrative turn, extract indicators, update scores, and select next probe.",
    )
    p_turn.add_argument("--session-file", default=None, help="Ephemeral session JSON file path.")
    p_turn.add_argument("--session-json", default=None, help="Inline ephemeral session JSON string.")
    p_turn.add_argument("--narrative", default=None, help="Executive narrative text for this turn.")
    p_turn.add_argument("--narrative-file", default=None, help="UTF-8 text file containing narrative.")
    p_turn.add_argument(
        "--observations-json",
        default=None,
        help="Optional JSON array of structured indicator observations.",
    )
    p_turn.set_defaults(handler=_cmd_analyze_turn)

    p_score = subparsers.add_parser(
        "score",
        help="Compute Bayesian Threat Matrix posteriors for structured indicators or a session.",
    )
    p_score.add_argument("--session-file", default=None, help="Ephemeral session JSON file path.")
    p_score.add_argument("--session-json", default=None, help="Inline session JSON string.")
    p_score.add_argument("--observations-json", default=None, help="Structured indicator observations JSON.")
    p_score.add_argument(
        "--risk-profile",
        default=None,
        choices=["standard", "high_exposure"],
        help="Optional baseline prior override.",
    )
    p_score.set_defaults(handler=_cmd_score)

    p_rep = subparsers.add_parser(
        "generate-report",
        help="Synthesize final Markdown and JSON executive diagnostic report.",
    )
    p_rep.add_argument("--session-file", default=None, help="Ephemeral session JSON file path.")
    p_rep.add_argument("--session-json", default=None, help="Inline session JSON string.")
    p_rep.add_argument("--output-md", default=None, help="Optional file path to save Markdown report.")
    p_rep.add_argument("--output-json", default=None, help="Optional file path to save JSON report.")
    p_rep.add_argument(
        "--purge-session",
        action="store_true",
        help="Securely overwrite and delete --session-file after generating the report.",
    )
    p_rep.set_defaults(handler=_cmd_generate_report)

    p_purge = subparsers.add_parser(
        "purge-session",
        help="Securely overwrite with zeros and delete an ephemeral session file.",
    )
    p_purge.add_argument("--session-file", required=True, help="Ephemeral session JSON path to wipe.")
    p_purge.set_defaults(handler=_cmd_purge_session)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # Preserve standard argparse exit code (2 on CLI syntax errors, 0 on --help).
        return int(exc.code) if isinstance(exc.code, int) else 2

    configure_logging(args.log_level)

    try:
        return int(args.handler(args))
    except SkillError as exc:
        _emit_error(type(exc).__name__, str(exc))
        return exc.exit_code
    except Exception as exc:  # pragma: no cover - defensive fallback
        _emit_error("UnexpectedError", str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
