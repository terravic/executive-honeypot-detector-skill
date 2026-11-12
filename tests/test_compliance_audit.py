"""Repository structural integrity, skill metadata, and relative path checks."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent

_DISALLOWED_SYMBOL_RANGES = re.compile(
    "["
    "\U0001F300-\U0001F9FF"
    "\U0001FA00-\U0001FAFF"
    "\u2600-\u26FF"
    "\u2700-\u27BF"
    "\uFE0F"
    "]"
)

_ABSOLUTE_PATH_PATTERN = re.compile(
    r"(?:/usr/|/home/|/tmp/|file://|[A-Za-z]:\\\\)",
    re.IGNORECASE,
)

_REQUIRED_LAYOUT_PATHS = (
    "LICENSE",
    "SKILL.md",
    "README.md",
    "requirements.txt",
    "documents/prd.md",
    "assets/indicators_taxonomy.json",
    "assets/probes_and_countermeasures.json",
    "assets/report_template.md",
    "assets/schemas/session_schema.json",
    "assets/schemas/report_schema.json",
    "references/tradecraft_taxonomy.md",
    "references/interview_playbook.md",
    "references/defensive_protocols.md",
    "scripts/honeypot_cli.py",
    "tests/fixtures/synthetic_scenarios.json",
)


def _iter_project_text_files() -> list[Path]:
    extensions = {".md", ".py", ".json", ".txt"}
    results: list[Path] = []
    for path in PROJECT_ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(
            part in {".venv", "__pycache__", ".pytest_cache", ".git"}
            for part in path.parts
        ):
            continue
        if path.suffix in extensions:
            results.append(path)
    return sorted(results)


def test_required_skill_layout_files_exist() -> None:
    for rel in _REQUIRED_LAYOUT_PATHS:
        assert (PROJECT_ROOT / rel).is_file(), f"Missing required skill file: {rel}"


def test_skill_md_frontmatter_and_relative_links_are_valid() -> None:
    skill_text = (PROJECT_ROOT / "SKILL.md").read_text(encoding="utf-8")
    assert skill_text.startswith("---\n")
    parts = skill_text.split("---\n", 2)
    assert len(parts) == 3, "SKILL.md missing closing YAML frontmatter delimiter."
    frontmatter = yaml.safe_load(parts[1])
    assert isinstance(frontmatter, dict)
    assert frontmatter.get("name") == "executive-honeypot-detector"
    assert isinstance(frontmatter.get("description"), str)
    assert len(frontmatter["description"].strip()) >= 40

    # Verify every relative path reference in SKILL.md resolves cleanly.
    for rel_match in re.findall(
        r"`((?:scripts|references|assets|documents)/[A-Za-z0-9_./-]+)`", skill_text
    ):
        assert (PROJECT_ROOT / rel_match).exists(), (
            f"SKILL.md references missing relative path: {rel_match}"
        )


def test_plain_text_formatting_across_repository() -> None:
    for path in _iter_project_text_files():
        if path.resolve() == Path(__file__).resolve():
            continue
        content = path.read_text(encoding="utf-8")
        match = _DISALLOWED_SYMBOL_RANGES.search(content)
        assert match is None, (
            f"Unexpected decorative symbol in {path.relative_to(PROJECT_ROOT)}: {match.group(0)!r}"
        )


def test_relative_paths_only_in_documentation_and_assets() -> None:
    for path in _iter_project_text_files():
        if path.resolve() == Path(__file__).resolve():
            continue
        if path.suffix in {".md", ".json", ".txt"}:
            content = path.read_text(encoding="utf-8")
            match = _ABSOLUTE_PATH_PATTERN.search(content)
            assert match is None, (
                f"Absolute filesystem path detected in {path.relative_to(PROJECT_ROOT)}: {match.group(0)!r}"
            )
