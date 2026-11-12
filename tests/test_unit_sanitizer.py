"""Unit tests for OPSEC PII sanitization, validation, and secure purging."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts import SessionError, ValidationError
from scripts.sanitizer import (
    make_safe_excerpt,
    normalize_sensitive_terms,
    sanitize_text,
    secure_purge_file,
    validate_narrative,
    validate_safe_path,
)


def test_sanitize_text_redacts_all_synthetic_pii_categories() -> None:
    raw = (
        "Avery Placeholder from Apex Synthetic Corp sent synthetic.exec@example.invalid, "
        "called +1-202-555-0142 and 555-0199, logged IP 192.0.2.42, mentioned 000-00-0000, "
        "card 4000-1234-5678-9010, and https://portal.example.invalid/login?token=SYNTHETIC999."
    )
    res = sanitize_text(
        raw, sensitive_terms=["Avery Placeholder", "Apex Synthetic Corp"]
    )

    assert res.redaction_count >= 8
    for forbidden in (
        "Avery Placeholder",
        "Apex Synthetic Corp",
        "synthetic.exec@example.invalid",
        "555-0142",
        "555-0199",
        "192.0.2.42",
        "000-00-0000",
        "4000-1234-5678-9010",
        "SYNTHETIC999",
    ):
        assert forbidden not in res.sanitized_text

    assert "[REDACTED_ENTITY]" in res.sanitized_text
    assert "[REDACTED_EMAIL]" in res.sanitized_text
    assert "[REDACTED_PHONE]" in res.sanitized_text
    assert "[REDACTED_IP]" in res.sanitized_text
    assert "[REDACTED_SSN]" in res.sanitized_text
    assert "[REDACTED_CARD]" in res.sanitized_text
    assert "[REDACTED_URL]" in res.sanitized_text


def test_validate_narrative_rejects_empty_oversized_and_null_bytes() -> None:
    with pytest.raises(ValidationError):
        validate_narrative("")
    with pytest.raises(ValidationError):
        validate_narrative("   \n\t  ")
    with pytest.raises(ValidationError):
        validate_narrative("hello\x00world")
    with pytest.raises(ValidationError):
        validate_narrative("x" * 20001)
    assert validate_narrative("  valid executive statement  ") == "valid executive statement"


def test_normalize_sensitive_terms_deduplicates_and_orders_longest_first() -> None:
    terms = normalize_sensitive_terms(["Apex", "apex synthetic corp", "a", "APEX"])
    assert terms == ["apex synthetic corp", "Apex"]


def test_validate_safe_path_blocks_traversal_and_directories(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        validate_safe_path("../outside.json")
    with pytest.raises(ValidationError):
        validate_safe_path("sessions/../../secret.json")
    with pytest.raises(ValidationError):
        validate_safe_path(tmp_path)  # Directory, not file
    with pytest.raises(SessionError):
        validate_safe_path(tmp_path / "missing.json", must_exist=True)


def test_secure_purge_file_overwrites_and_deletes(tmp_path: Path) -> None:
    session_file = tmp_path / "ephemeral.json"
    session_file.write_text('{"session_id": "diag-test"}', encoding="utf-8")
    assert session_file.exists()

    details = secure_purge_file(session_file)
    assert details["purged"] is True
    assert details["bytes_overwritten"] > 0
    assert not session_file.exists()

    with pytest.raises(SessionError):
        secure_purge_file(session_file)


def test_make_safe_excerpt_truncates_cleanly() -> None:
    text = "word " * 100
    excerpt = make_safe_excerpt(text, max_chars=50)
    assert len(excerpt) <= 50
    assert excerpt.endswith("...")
