"""Unit tests for the 32-indicator taxonomy loader, validator, and hybrid matcher."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import TaxonomyError, ValidationError
from scripts.taxonomy_engine import (
    EXPECTED_INDICATOR_COUNT,
    extract_indicators,
    load_and_validate_assets,
)


def test_load_and_validate_assets_has_exact_32_indicators() -> None:
    assets = load_and_validate_assets()
    assert len(assets.indicators_by_id) == EXPECTED_INDICATOR_COUNT
    assert len(assets.tiers_by_id) == 6
    assert set(assets.taxonomy["prior_profiles"].keys()) == {"standard", "high_exposure"}


def test_corrupted_taxonomy_missing_file_raises_taxonomy_error(tmp_path: Path) -> None:
    with pytest.raises(TaxonomyError):
        load_and_validate_assets(tmp_path)


def test_invalid_indicator_count_raises_taxonomy_error(tmp_path: Path) -> None:
    assets = load_and_validate_assets()
    bad_tax = json.loads(json.dumps(assets.taxonomy))
    bad_tax["indicators"] = bad_tax["indicators"][:10]
    (tmp_path / "indicators_taxonomy.json").write_text(
        json.dumps(bad_tax), encoding="utf-8"
    )
    (tmp_path / "probes_and_countermeasures.json").write_text(
        json.dumps(assets.probes_config), encoding="utf-8"
    )
    (tmp_path / "report_template.md").write_text("template", encoding="utf-8")

    with pytest.raises(TaxonomyError):
        load_and_validate_assets(tmp_path)


def test_extract_indicators_detects_positive_and_negation_patterns() -> None:
    assets = load_and_validate_assets()
    text = (
        "We met unexpectedly at a hotel bar during an overseas conference in Geneva. "
        "She asked to charge her phone on my laptop via USB. "
        "However, she has never asked for money or loans."
    )
    res = extract_indicators(text, assets)
    merged = res["merged_indicators"]

    assert merged["AV-01"]["status"] == "present"
    assert merged["TP-02"]["status"] == "present"
    assert merged["FF-03"]["status"] == "absent"
    assert any(r["rule_id"] == "RULE_TECHNICAL_EXPOSURE" for r in res["triggered_rules"])


def test_extract_indicators_flags_conflicts_and_rejects_bad_observations() -> None:
    assets = load_and_validate_assets()
    with pytest.raises(ValidationError):
        extract_indicators(
            "Met at an overseas hotel bar.",
            assets,
            structured_observations=[{"id": "NONEXISTENT-99", "status": "present"}],
        )
    with pytest.raises(ValidationError):
        extract_indicators(
            "Met at an overseas hotel bar.",
            assets,
            structured_observations=[
                {"id": "AV-01", "status": "present", "confidence": 1.5}
            ],
        )

    # Structured negation conflicting with regex hit sets conflict_flagged = True.
    res = extract_indicators(
        "We met at a hotel lounge during a summit abroad.",
        assets,
        structured_observations=[
            {"id": "AV-01", "status": "absent", "confidence": 0.90}
        ],
    )
    assert res["merged_indicators"]["AV-01"]["status"] == "absent"
    assert res["merged_indicators"]["AV-01"]["conflict_flagged"] is True
