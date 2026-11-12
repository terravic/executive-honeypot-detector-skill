"""Unit tests for the Dynamic Interview Core state machine and adaptive probing."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts import SessionError
from scripts.interview_engine import (
    create_session,
    load_session_from_file,
    load_session_from_json,
    process_turn,
    save_session_to_file,
)
from scripts.taxonomy_engine import load_and_validate_assets


def test_interview_never_repeats_probes_and_advances_across_all_tiers() -> None:
    assets = load_and_validate_assets()
    session = create_session(risk_profile="standard", assets=assets)
    asked_sequence: list[str] = list(session["asked_probe_ids"])

    neutral_turns = [
        "We met through an alumni gathering in our local city and nothing felt unusual.",
        "She works at a verifiable regional university hospital and I met her family.",
        "She never probes work or proprietary technical details.",
        "Relationship pacing has been completely normal and gradual over months.",
        "Devices remain strictly locked with zero unmonitored access or cable requests.",
        "There have been zero financial requests, loans, or wealth stories.",
    ]

    for text in neutral_turns:
        res = process_turn(session, text, assets=assets)
        session = res["session"]
        if res["next_probe"] is not None:
            p_id = res["next_probe"]["probe_id"]
            assert p_id not in asked_sequence
            asked_sequence.append(p_id)
        if res["ready_for_synthesis"]:
            break

    assert len(asked_sequence) == len(set(asked_sequence))
    assert session["stage"] == "ready_for_synthesis"
    assert len(session["covered_tiers"]) >= 5


def test_high_risk_technical_trigger_immediately_escalates_technical_probe() -> None:
    assets = load_and_validate_assets()
    session = create_session(risk_profile="high_exposure", assets=assets)

    res = process_turn(
        session,
        "We met at a hotel bar overseas, and yesterday she asked to charge her phone on my laptop via USB.",
        assets=assets,
    )
    assert res["next_probe"] is not None
    assert res["next_probe"]["tier"] == "tier_5_technical"
    assert res["next_probe"]["reason"] == "triggered_indicator_followup"


def test_pause_resume_session_roundtrip_and_corrupted_json_handling(
    tmp_path: Path,
) -> None:
    assets = load_and_validate_assets()
    session = create_session(
        risk_profile="standard",
        sensitive_terms=["Avery Placeholder"],
        assets=assets,
    )
    res = process_turn(
        session,
        "Avery Placeholder met me at an overseas summit hotel lounge.",
        assets=assets,
    )
    session_file = tmp_path / "paused_session.json"
    save_session_to_file(res["session"], session_file)

    reloaded = load_session_from_file(session_file)
    assert reloaded["session_id"] == res["session"]["session_id"]
    assert reloaded["turn_count"] == 1
    assert "Avery Placeholder" not in reloaded["turn_history"][0]["sanitized_excerpt"]

    with pytest.raises(SessionError):
        load_session_from_json("{not valid json")
    with pytest.raises(SessionError):
        load_session_from_json('{"partial": true}')
