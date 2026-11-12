"""Unit tests for the Executive Synthesis Module and Canary Protocol generator."""

from __future__ import annotations

from scripts.interview_engine import create_session, process_turn
from scripts.report_generator import generate_report
from scripts.taxonomy_engine import load_and_validate_assets


def test_report_generator_renders_complete_ci_brief_with_canary_protocol() -> None:
    assets = load_and_validate_assets()
    session = create_session(
        risk_profile="high_exposure",
        sensitive_terms=["Partner-SecretName"],
        assets=assets,
    )
    turns = [
        "Partner-SecretName met me at a hotel bar during an overseas aerospace conference in Geneva where my keynote schedule was publicized online.",
        "She works in international art logistics with zero corporate footprint and I have never met any family.",
        "She persistently steers conversations toward our unannounced acquisition targets and uses flattery to encourage venting.",
        "She declared love within two weeks and discourages me from telling my advisors.",
        "She picked up my corporate phone and asked to charge her phone on my laptop via USB.",
    ]
    for t in turns:
        session = process_turn(session, t, assets=assets)["session"]

    bundle = generate_report(session, assets=assets, session_purged=True)
    r_json = bundle["report_json"]
    r_md = bundle["report_markdown"]

    assert r_json["classification"]["id"] == "tier_3_ci_honeypot"
    assert r_json["canary_protocol"]["recommended"] is True
    assert r_json["canary_protocol"]["domain_key"] == "ma_strategy"
    assert r_json["opsec_metadata"]["session_purged"] is True
    assert "Partner-SecretName" not in r_md
    assert "OPERATIONAL AND LEGAL DISCLAIMER" in r_md
    assert "Canary Protocol" in r_md
    assert "Bayesian Threat Matrix Posteriors" in r_md


def test_report_generator_marks_low_coverage_blind_spots_explicitly() -> None:
    assets = load_and_validate_assets()
    session = create_session(risk_profile="standard", assets=assets)
    session = process_turn(
        session,
        "We met briefly at a hotel lounge during a conference abroad.",
        assets=assets,
    )["session"]

    bundle = generate_report(session, assets=assets)
    r_json = bundle["report_json"]
    r_md = bundle["report_markdown"]

    assert r_json["confidence"]["insufficient_data"] is True
    assert r_json["confidence"]["level"] == "low"
    assert len(r_json["blind_spots"]) >= 4
    assert "PRELIMINARY ASSESSMENT NOTICE" in r_md
