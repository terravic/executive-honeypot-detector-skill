"""End-to-end CLI smoke and system tests across synthetic scenarios."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CLI_PATH = PROJECT_ROOT / "scripts" / "honeypot_cli.py"
FIXTURES_PATH = PROJECT_ROOT / "tests" / "fixtures" / "synthetic_scenarios.json"


def _run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CLI_PATH), *args],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )


def _load_scenarios() -> dict[str, dict[str, Any]]:
    raw = json.loads(FIXTURES_PATH.read_text(encoding="utf-8"))
    return {s["id"]: s for s in raw["scenarios"]}


def test_cli_validate_taxonomy_smoke() -> None:
    proc = _run_cli(["validate-taxonomy"])
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["status"] == "ok"
    assert payload["indicator_count"] == 32


def test_cli_end_to_end_synthetic_scenarios(tmp_path: Path) -> None:
    scenarios = _load_scenarios()

    for sc_id, sc in scenarios.items():
        session_file = tmp_path / f"{sc_id}_session.json"
        md_out = tmp_path / f"{sc_id}_report.md"
        json_out = tmp_path / f"{sc_id}_report.json"

        init_args = [
            "init-session",
            "--risk-profile",
            sc["risk_profile"],
            "--session-file",
            str(session_file),
        ]
        if sc.get("sensitive_terms"):
            init_args.extend(["--sensitive-terms", *sc["sensitive_terms"]])

        init_proc = _run_cli(init_args)
        assert init_proc.returncode == 0, init_proc.stderr
        assert session_file.exists()

        for turn in sc["turns"]:
            turn_args = [
                "analyze-turn",
                "--session-file",
                str(session_file),
                "--narrative",
                turn["narrative"],
            ]
            if turn.get("observations"):
                turn_args.extend(
                    ["--observations-json", json.dumps(turn["observations"])]
                )
            t_proc = _run_cli(turn_args)
            assert t_proc.returncode == 0, t_proc.stderr

        rep_proc = _run_cli(
            [
                "generate-report",
                "--session-file",
                str(session_file),
                "--output-md",
                str(md_out),
                "--output-json",
                str(json_out),
                "--purge-session",
            ]
        )
        assert rep_proc.returncode == 0, rep_proc.stderr
        # Ephemeral session file must be purged immediately upon report generation.
        assert not session_file.exists()
        assert md_out.is_file()
        assert json_out.is_file()

        report_json = json.loads(json_out.read_text(encoding="utf-8"))
        report_md = md_out.read_text(encoding="utf-8")

        # Validate exact normalization of posteriors.
        assert abs(sum(report_json["posteriors"].values()) - 1.0) < 1e-4

        if "expected_classification" in sc:
            expected_cls = sc["expected_classification"]
            assert report_json["classification"]["id"] == expected_cls, sc_id
            assert (
                report_json["posteriors"][expected_cls] >= sc["min_expected_posterior"]
            ), f"{sc_id} posterior too low: {report_json['posteriors']}"

        if "expected_confidence_level" in sc:
            assert (
                report_json["confidence"]["level"] == sc["expected_confidence_level"]
            )

        if "expected_insufficient_data" in sc:
            assert (
                report_json["confidence"]["insufficient_data"]
                is sc["expected_insufficient_data"]
            )

        if "expected_canary_recommended" in sc:
            assert (
                report_json["canary_protocol"]["recommended"]
                is sc["expected_canary_recommended"]
            )

        if "forbidden_output_tokens" in sc:
            assert report_json["opsec_metadata"]["redaction_count"] >= 6
            for token in sc["forbidden_output_tokens"]:
                assert token not in report_md
                assert token not in json.dumps(report_json)


def test_cli_stateless_score_and_error_exit_codes(tmp_path: Path) -> None:
    # Standalone scoring works without session files.
    ok_proc = _run_cli(
        [
            "score",
            "--observations-json",
            '[{"id":"AV-01","status":"present","confidence":0.9},{"id":"TP-02","status":"present","confidence":0.95}]',
        ]
    )
    assert ok_proc.returncode == 0, ok_proc.stderr
    assert json.loads(ok_proc.stdout)["status"] == "ok"

    # Empty narrative exits non-zero (exit code 2).
    session_file = tmp_path / "err_session.json"
    _run_cli(["init-session", "--session-file", str(session_file)])
    empty_proc = _run_cli(
        ["analyze-turn", "--session-file", str(session_file), "--narrative", "   "]
    )
    assert empty_proc.returncode == 2

    # Corrupted session JSON exits non-zero (exit code 2).
    bad_json_proc = _run_cli(
        ["analyze-turn", "--session-json", "{broken", "--narrative", "Met overseas."]
    )
    assert bad_json_proc.returncode == 2

    # Path traversal attempt exits non-zero (exit code 2).
    trav_proc = _run_cli(
        ["init-session", "--session-file", "../illegal_traversal.json"]
    )
    assert trav_proc.returncode == 2

    # Standalone purge works cleanly and fails safely on missing file.
    purge_ok = _run_cli(["purge-session", "--session-file", str(session_file)])
    assert purge_ok.returncode == 0
    purge_missing = _run_cli(["purge-session", "--session-file", str(session_file)])
    assert purge_missing.returncode == 2
