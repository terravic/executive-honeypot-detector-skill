"""Automated verification for standalone dashboard builder, theme tokens,
OPSEC scrubbing, and Python-vs-JS engine parity across all synthetic scenarios.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BUILDER_CLI = PROJECT_ROOT / "scripts" / "build_dashboard.py"
HONEYPOT_CLI = PROJECT_ROOT / "scripts" / "honeypot_cli.py"
FIXTURES_PATH = PROJECT_ROOT / "tests" / "fixtures" / "synthetic_scenarios.json"

_PICTOGRAPH_PATTERN = re.compile(
    "["
    "\U0001F300-\U0001F9FF"
    "\U0001FA00-\U0001FAFF"
    "\u2600-\u26FF"
    "\u2700-\u27BF"
    "\uFE0F"
    "]"
)


def _extract_embedded_bundle(html: str) -> dict[str, Any]:
    match = re.search(
        r'<script id="dashboard-data" type="application/json">(.*?)</script>',
        html,
        re.DOTALL,
    )
    assert match is not None, "Missing embedded #dashboard-data JSON script."
    raw = match.group(1).replace("<\\/", "</")
    return json.loads(raw)


def _run_py(script: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script), *args],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )


def test_build_dashboard_default_scenarios_and_design_tokens(tmp_path: Path) -> None:
    out_html = tmp_path / "dashboard.html"
    proc = _run_py(BUILDER_CLI, ["--output", str(out_html)])
    assert proc.returncode == 0, proc.stderr
    meta = json.loads(proc.stdout)
    assert meta["status"] == "ok"
    assert meta["dataset_count"] == 5
    assert meta["default_dataset_id"] == "scenario_c_ci_honeypot"
    assert meta["system_theme"] in {"light", "dark"}
    assert out_html.is_file()

    html = out_html.read_text(encoding="utf-8")

    # Verify light and dark surface, border, and text hex tokens.
    for token in (
        "#FAFAF9",
        "#FFFFFF",
        "#E7E5E4",
        "#1C1917",
        "#787774",
        "#0D0E11",
        "#16171D",
        "#292A30",
        "#ECE8E2",
        "#9A9895",
    ):
        assert token in html, f"Missing theme token: {token}"

    # Verify semantic data visualization palette tokens.
    for color in ("#0D9488", "#D97706", "#4F46E5", "#059669", "#E11D48"):
        assert color in html, f"Missing semantic palette color: {color}"

    # Verify 3-icon theme selector IDs and system OS tracking hooks.
    for selector_id in ("theme-btn-light", "theme-btn-dark", "theme-btn-system"):
        assert f'id="{selector_id}"' in html
    assert "prefers-color-scheme: dark" in html

    # Verify typography and tabular monospaced numeric formatting.
    for font_token in ("Instrument Serif", "DM Sans", "IBM Plex Mono", "tabular-nums"):
        assert font_token in html
    assert "Roboto" not in html

    # Verify dual-mode interview and live update controls exist.
    for ctrl in (
        'id="btn-start-interview"',
        'id="btn-purge-ram"',
        'id="interview-workspace"',
        "window.updateDashboardData",
    ):
        assert ctrl in html

    # Verify domain-accurate 3D visualization title and plain-text output hygiene.
    assert "Interactive Threat Topology &amp; Indicator Map" in html
    assert _PICTOGRAPH_PATTERN.search(html) is None, "Unexpected pictograph character detected"

    # Verify embedded empirical data bundle integrity and OPSEC scrubbing.
    bundle = _extract_embedded_bundle(html)
    assert len(bundle["datasets"]) == 5
    assert len(bundle["catalog"]["taxonomy"]["indicators"]) == 32

    scenarios_raw = json.loads(FIXTURES_PATH.read_text(encoding="utf-8"))["scenarios"]
    by_id = {d["id"]: d for d in bundle["datasets"]}
    for sc in scenarios_raw:
        ds = by_id[sc["id"]]
        posteriors = ds["report"]["posteriors"]
        assert abs(sum(posteriors.values()) - 1.0) < 1e-4
        assert len(ds["trajectory"]) == len(sc["turns"]) + 1
        if "forbidden_output_tokens" in sc:
            for token in sc["forbidden_output_tokens"]:
                assert token not in html, f"OPSEC token leaked into dashboard.html: {token}"


def test_build_dashboard_from_live_session_and_report_json(tmp_path: Path) -> None:
    session_file = tmp_path / "ephemeral_session.json"
    report_json = tmp_path / "diagnostic_report.json"

    init_proc = _run_py(
        HONEYPOT_CLI,
        [
            "init-session",
            "--risk-profile",
            "high_exposure",
            "--sensitive-terms",
            "Morgan Placeholder",
            "--session-file",
            str(session_file),
        ],
    )
    assert init_proc.returncode == 0, init_proc.stderr

    turn_proc = _run_py(
        HONEYPOT_CLI,
        [
            "analyze-turn",
            "--session-file",
            str(session_file),
            "--narrative",
            "Morgan Placeholder approached me at a Geneva summit hotel lounge and asked to charge her phone on my laptop via USB.",
            "--observations-json",
            '[{"id":"AV-01","status":"present","confidence":0.9},{"id":"TP-02","status":"present","confidence":0.95}]',
        ],
    )
    assert turn_proc.returncode == 0, turn_proc.stderr

    # 1. Build directly from ephemeral session before purge.
    sess_dash = tmp_path / "from_session.html"
    b1 = _run_py(
        BUILDER_CLI,
        ["--session-file", str(session_file), "--output", str(sess_dash), "--no-scenarios"],
    )
    assert b1.returncode == 0, b1.stderr
    b1_meta = json.loads(b1.stdout)
    assert b1_meta["default_dataset_id"] == "live_session"
    assert b1_meta["dataset_count"] == 1
    sess_html = sess_dash.read_text(encoding="utf-8")
    assert "Morgan Placeholder" not in sess_html

    # 2. Generate report & purge session, then build from standalone report JSON.
    rep_proc = _run_py(
        HONEYPOT_CLI,
        [
            "generate-report",
            "--session-file",
            str(session_file),
            "--output-json",
            str(report_json),
            "--purge-session",
        ],
    )
    assert rep_proc.returncode == 0, rep_proc.stderr
    assert not session_file.exists()

    rep_dash = tmp_path / "from_report.html"
    b2 = _run_py(
        BUILDER_CLI,
        ["--report-json", str(report_json), "--output", str(rep_dash), "--no-scenarios"],
    )
    assert b2.returncode == 0, b2.stderr
    b2_meta = json.loads(b2.stdout)
    assert b2_meta["default_dataset_id"] == "imported_report"
    assert rep_dash.is_file()

    # 3. Path traversal rejection returns exit code 2.
    bad = _run_py(BUILDER_CLI, ["--output", "../escape_dashboard.html"])
    assert bad.returncode == 2


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js runtime not available")
def test_js_in_browser_interview_engine_matches_python_exact_parity(tmp_path: Path) -> None:
    """Run all 5 synthetic scenarios through the embedded JS HoneypotEngine in Node.js
    and verify exact parity with the Python backend outputs."""
    out_html = tmp_path / "parity_dashboard.html"
    proc = _run_py(BUILDER_CLI, ["--output", str(out_html)])
    assert proc.returncode == 0, proc.stderr
    html = out_html.read_text(encoding="utf-8")
    bundle = _extract_embedded_bundle(html)

    # Extract section 1 (HoneypotEngine) directly from the generated dashboard script.
    script_match = re.search(
        r"(/\* =+\s*1\. DETERMINISTIC IN-BROWSER DIAGNOSTIC ENGINE.*?window\.HoneypotEngine = \{.*?\};)",
        html,
        re.DOTALL,
    )
    assert script_match is not None, "Could not locate HoneypotEngine block in dashboard.html"
    engine_code = script_match.group(1)

    js_harness = f"""
const window = {{}};
{engine_code}
const fs = require('fs');
const catalog = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const scenarios = JSON.parse(fs.readFileSync(process.argv[3], 'utf8')).scenarios;
const compiled = window.HoneypotEngine.compileCatalog(catalog);
const out = {{}};

for (const sc of scenarios) {{
  let sess = window.HoneypotEngine.createBrowserSession(sc.risk_profile, sc.sensitive_terms || [], compiled);
  const turnSnapshots = [];
  for (const t of sc.turns) {{
    const res = window.HoneypotEngine.processBrowserTurn(sess, t.narrative, t.observations || null, compiled);
    sess = res.session;
    turnSnapshots.push({{
      posteriors: res.risk_snapshot.posteriors,
      score: res.risk_snapshot.composite_risk_score,
      redactions: res.turn_analysis.redactions_applied,
      next_probe_id: res.next_probe ? res.next_probe.probe_id : null
    }});
  }}
  const rep = window.HoneypotEngine.buildReportFromSession(sess, compiled, true);
  out[sc.id] = {{ report: rep, turns: turnSnapshots }};
}}
process.stdout.write(JSON.stringify(out));
"""

    catalog_file = tmp_path / "catalog.json"
    harness_file = tmp_path / "parity_check.js"
    catalog_file.write_text(json.dumps(bundle["catalog"]), encoding="utf-8")
    harness_file.write_text(js_harness, encoding="utf-8")

    node_proc = subprocess.run(
        ["node", str(harness_file), str(catalog_file), str(FIXTURES_PATH)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert node_proc.returncode == 0, node_proc.stderr
    js_results = json.loads(node_proc.stdout)

    py_by_id = {d["id"]: d for d in bundle["datasets"]}
    scenarios_raw = json.loads(FIXTURES_PATH.read_text(encoding="utf-8"))["scenarios"]

    for sc in scenarios_raw:
        sc_id = sc["id"]
        py_rep = py_by_id[sc_id]["report"]
        js_rep = js_results[sc_id]["report"]

        assert js_rep["classification"]["id"] == py_rep["classification"]["id"], sc_id
        for h_id in ("tier_1_benign", "tier_2_commercial_fraud", "tier_3_ci_honeypot"):
            assert abs(js_rep["posteriors"][h_id] - py_rep["posteriors"][h_id]) < 1e-4, (
                f"{sc_id}.{h_id}: JS={js_rep['posteriors'][h_id]} vs PY={py_rep['posteriors'][h_id]}"
            )
        assert abs(js_rep["composite_risk_score"] - py_rep["composite_risk_score"]) <= 0.1, sc_id
        assert js_rep["indicators_summary"] == py_rep["indicators_summary"], sc_id
        assert js_rep["confidence"] == py_rep["confidence"], sc_id
        assert js_rep["opsec_metadata"]["redaction_count"] == py_rep["opsec_metadata"]["redaction_count"], sc_id
        assert js_rep["canary_protocol"]["recommended"] is py_rep["canary_protocol"]["recommended"], sc_id
        assert js_rep["canary_protocol"]["domain_key"] == py_rep["canary_protocol"]["domain_key"], sc_id

        # Verify turn-by-turn adaptive probe selection matches Python identically.
        py_turns = py_by_id[sc_id]["trajectory"][1:]
        js_turns = js_results[sc_id]["turns"]
        assert len(js_turns) == len(py_turns)
        for idx, (pt, jt) in enumerate(zip(py_turns, js_turns)):
            py_next = pt["next_probe"]["probe_id"] if pt["next_probe"] else None
            assert jt["next_probe_id"] == py_next, f"{sc_id} turn {idx + 1} probe mismatch"
            assert jt["redactions"] == pt["redactions_applied"], f"{sc_id} turn {idx + 1} redaction mismatch"

        if "forbidden_output_tokens" in sc:
            js_dump = json.dumps(js_rep)
            for token in sc["forbidden_output_tokens"]:
                assert token not in js_dump, f"JS engine leaked OPSEC token: {token}"
