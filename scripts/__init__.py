"""Core package initialization, path resolution, logging, and typed exceptions.

All file paths resolve relative to the skill root directory or configurable
environment variables so the skill runs cleanly across any agent harness without
hardcoded system paths.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
ENV_ASSETS_DIR = "HONEYPOT_SKILL_ASSETS_DIR"
ENV_LOG_LEVEL = "HONEYPOT_SKILL_LOG_LEVEL"


class SkillError(Exception):
    """Base exception for deterministic skill errors."""

    exit_code: int = 1


class TaxonomyError(SkillError):
    """Raised when declarative taxonomy or asset files are missing or invalid."""

    exit_code: int = 1


class ValidationError(SkillError):
    """Raised when user or caller input fails validation rules."""

    exit_code: int = 2


class SessionError(SkillError):
    """Raised when session state is missing, malformed, or cannot be loaded."""

    exit_code: int = 2


def get_assets_dir(override: str | Path | None = None) -> Path:
    """Resolve the declarative assets directory path.

    Resolution order:
    1. Explicit function argument override.
    2. Environment variable HONEYPOT_SKILL_ASSETS_DIR.
    3. Default <project_root>/assets directory.
    """
    if override is not None:
        return Path(override).resolve()
    env_val = os.environ.get(ENV_ASSETS_DIR)
    if env_val:
        return Path(env_val).resolve()
    return (PROJECT_ROOT / "assets").resolve()


def configure_logging(level_override: str | None = None) -> logging.Logger:
    """Configure package logging to stderr so stdout remains clean JSON."""
    raw_level = (level_override or os.environ.get(ENV_LOG_LEVEL) or "WARNING").upper()
    numeric_level = getattr(logging, raw_level, logging.WARNING)

    logger = logging.getLogger("honeypot_skill")
    logger.setLevel(numeric_level)
    if not logger.handlers:
        handler = logging.StreamHandler(stream=sys.stderr)
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
        logger.addHandler(handler)
    else:
        for handler in logger.handlers:
            handler.setLevel(numeric_level)
    logger.propagate = False
    return logger
