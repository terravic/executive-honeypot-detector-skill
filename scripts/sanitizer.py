"""OPSEC PII sanitization, defensive input validation, and secure file purging.

This module guarantees that sensitive contact details, numeric identifiers, and
caller-registered entity names are stripped prior to session storage, logging,
or report rendering.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from scripts import SessionError, ValidationError

logger = logging.getLogger("honeypot_skill.sanitizer")

MAX_NARRATIVE_LENGTH = 20000
MAX_EXCERPT_LENGTH = 280

# Precompiled patterns ordered from most specific to most general to avoid
# partial overlaps during deterministic redaction.
_REDACTION_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "[REDACTED_URL]",
        re.compile(
            r"https?://[^\s<>\"']+(?:token|key|secret|auth|session|sig)=[^\s<>\"']+",
            re.IGNORECASE,
        ),
    ),
    (
        "[REDACTED_EMAIL]",
        re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            re.IGNORECASE,
        ),
    ),
    (
        "[REDACTED_SSN]",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    ),
    (
        "[REDACTED_CARD]",
        re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    ),
    (
        "[REDACTED_IP]",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
        ),
    ),
    (
        "[REDACTED_PHONE]",
        re.compile(
            r"(?<!\w)(?:\+?\d{1,3}[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}(?!\w)"
            r"|(?<!\w)555[-\s]01\d{2}(?!\w)"
        ),
    ),
)


@dataclass(frozen=True)
class SanitizationResult:
    """Outcome of OPSEC sanitization over a single text payload."""

    sanitized_text: str
    redaction_count: int
    redacted_categories: dict[str, int]


def validate_narrative(text: object, max_length: int = MAX_NARRATIVE_LENGTH) -> str:
    """Validate that an incoming executive narrative is a safe, non-empty string."""
    if not isinstance(text, str):
        raise ValidationError("Narrative input must be a UTF-8 text string.")
    if "\x00" in text:
        raise ValidationError("Narrative input contains illegal null byte characters.")
    stripped = text.strip()
    if not stripped:
        raise ValidationError("Narrative input must not be empty or whitespace-only.")
    if len(stripped) > max_length:
        raise ValidationError(
            f"Narrative input exceeds maximum permitted length of {max_length} characters."
        )
    return stripped


def normalize_sensitive_terms(terms: Iterable[str] | None) -> list[str]:
    """Normalize and deduplicate caller-provided sensitive entity strings."""
    if not terms:
        return []
    cleaned: list[str] = []
    seen: set[str] = set()
    for term in terms:
        if not isinstance(term, str):
            raise ValidationError("All sensitive_terms entries must be strings.")
        candidate = term.strip()
        if len(candidate) < 2:
            continue
        key = candidate.lower()
        if key not in seen:
            seen.add(key)
            cleaned.append(candidate)
    # Longest-first ordering ensures multi-word names mask cleanly before tokens.
    cleaned.sort(key=len, reverse=True)
    return cleaned


def sanitize_text(
    text: str,
    sensitive_terms: Iterable[str] | None = None,
) -> SanitizationResult:
    """Redact PII tokens and configured entity terms from text deterministically."""
    if not isinstance(text, str):
        raise ValidationError("Text passed to sanitize_text must be a string.")

    current = text
    total_count = 0
    categories: dict[str, int] = {}

    for token, pattern in _REDACTION_RULES:
        current, count = pattern.subn(token, current)
        if count > 0:
            total_count += count
            categories[token] = categories.get(token, 0) + count

    normalized_terms = normalize_sensitive_terms(sensitive_terms)
    for term in normalized_terms:
        term_pattern = re.compile(
            r"(?<!\w)" + re.escape(term) + r"(?!\w)",
            re.IGNORECASE,
        )
        current, count = term_pattern.subn("[REDACTED_ENTITY]", current)
        if count > 0:
            total_count += count
            categories["[REDACTED_ENTITY]"] = (
                categories.get("[REDACTED_ENTITY]", 0) + count
            )

    if total_count > 0:
        logger.info("Redacted %d sensitive token(s) from text input.", total_count)

    return SanitizationResult(
        sanitized_text=current,
        redaction_count=total_count,
        redacted_categories=categories,
    )


def make_safe_excerpt(sanitized_text: str, max_chars: int = MAX_EXCERPT_LENGTH) -> str:
    """Truncate already-sanitized text into a concise, single-line excerpt."""
    compact = re.sub(r"\s+", " ", sanitized_text).strip()
    if len(compact) <= max_chars:
        return compact
    return compact[: max_chars - 3].rstrip() + "..."


def validate_safe_path(
    raw_path: str | Path,
    must_exist: bool = False,
    allowed_base: Path | None = None,
) -> Path:
    """Validate a filesystem path against null bytes, directory targets, and traversal."""
    if raw_path is None:
        raise ValidationError("File path cannot be None.")
    raw_str = str(raw_path).strip()
    if not raw_str:
        raise ValidationError("File path cannot be empty.")
    if "\x00" in raw_str:
        raise ValidationError("File path contains illegal null bytes.")

    candidate = Path(raw_str)
    if ".." in candidate.parts:
        raise ValidationError(
            "Relative parent traversal ('..') is prohibited in file paths."
        )

    resolved = candidate.resolve()

    if allowed_base is not None:
        base_resolved = Path(allowed_base).resolve()
        try:
            resolved.relative_to(base_resolved)
        except ValueError as exc:
            raise ValidationError(
                f"Path escapes permitted base directory: {base_resolved}"
            ) from exc

    if resolved.exists() and resolved.is_dir():
        raise ValidationError(f"Expected a file path, received directory: {resolved}")

    if must_exist and not resolved.exists():
        raise SessionError(f"Required file does not exist: {resolved}")

    return resolved


def secure_purge_file(raw_path: str | Path) -> dict[str, object]:
    """Overwrite an ephemeral session file with zero bytes and delete it."""
    target = validate_safe_path(raw_path, must_exist=True)
    if not target.is_file():
        raise SessionError(f"Target path is not a regular file: {target}")

    try:
        file_size = target.stat().st_size
        with target.open("r+b") as handle:
            if file_size > 0:
                handle.write(b"\x00" * file_size)
                handle.flush()
                os.fsync(handle.fileno())
        target.unlink()
    except OSError as exc:
        raise SessionError(f"Failed to securely purge session file: {exc}") from exc

    logger.info("Securely purged ephemeral session file (%d bytes).", file_size)
    return {
        "purged": True,
        "bytes_overwritten": file_size,
        "file_name": target.name,
    }
