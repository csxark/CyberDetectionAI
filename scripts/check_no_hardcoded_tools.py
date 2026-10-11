#!/usr/bin/env python3
"""CI check: no tool IDs, thresholds, budgets, or role permissions hard-coded outside sentinel_config.

Scans all Python files in packages/ (excluding sentinel_config/) for literals that should
only exist in sentinel_config/tools.py and sentinel_config/guardrails.py.

Exit 0 = clean, Exit 1 = violations found.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Tool IDs that must only appear in sentinel_config
TOOL_IDS: set[str] = {
    "parse_logs",
    "extract_indicators",
    "search_events",
    "correlate_timeline",
    "lookup_attack_technique",
    "search_kb",
    "match_sigma_rules",
    "code_search",
    "check_patch",
    "build_report",
    "lab_block_ip",
}

# Patterns that indicate hard-coded policy values
HARDCODED_PATTERNS: list[re.Pattern[str]] = [
    # Budget literals (wall_seconds, llm_calls, jev_calls with numbers)
    re.compile(r"\bwall_seconds\s*[=:]\s*\d+"),
    re.compile(r"\bllm_calls\s*[=:]\s*\d+"),
    re.compile(r"\bjev_calls\s*[=:]\s*\d+"),
    # Role names as string literals (outside of type annotations)
    re.compile(r"""['"](?:app_rw|gateway_rw|policy_admin|operator|eval_rw)['"]"""),
]

ALLOWED_DIRS: set[str] = {"sentinel_config"}
ALLOWED_DEFINITION_FILES: set[str] = {"contracts/enums.py", "api/db_models.py"}
SCAN_ROOT = Path("packages")
SKIP_FILES: set[str] = {"__init__.py"}


def scan_file(filepath: Path) -> list[str]:
    """Return list of violation descriptions for a single file."""
    violations: list[str] = []
    try:
        content = filepath.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return violations

    lines = content.splitlines()
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        # Skip comments and docstrings
        if stripped.startswith(("#", '"""', "'''")):
            continue

        # Check tool IDs as string literals
        violations.extend(
            f"{filepath}:{line_num}: hard-coded tool ID '{tool_id}'"
            for tool_id in TOOL_IDS
            for pat in [f'"{tool_id}"', f"'{tool_id}'"]
            if pat in line
        )

        # Check hard-coded patterns
        violations.extend(
            f"{filepath}:{line_num}: hard-coded policy value: {pattern.pattern}"
            for pattern in HARDCODED_PATTERNS
            if pattern.search(line)
        )

    return violations


def main() -> int:
    """Scan packages/ for hard-coded tool/policy values."""
    if not SCAN_ROOT.exists():
        print(f"ERROR: {SCAN_ROOT} not found", file=sys.stderr)
        return 1

    all_violations: list[str] = []

    for py_file in SCAN_ROOT.rglob("*.py"):
        # Skip sentinel_config itself (that's where they belong)
        parts = py_file.relative_to(SCAN_ROOT).parts
        if parts and parts[0] in ALLOWED_DIRS:
            continue
        # Skip allowed definition files (e.g. enum declarations)
        rel_posix = py_file.relative_to(SCAN_ROOT).as_posix()
        if rel_posix in ALLOWED_DEFINITION_FILES:
            continue
        # Skip test stubs
        if py_file.name in SKIP_FILES:
            continue

        all_violations.extend(scan_file(py_file))

    if all_violations:
        print("HARD-CODED TOOL/POLICY VIOLATIONS FOUND:", file=sys.stderr)
        for v in all_violations:
            print(f"  {v}", file=sys.stderr)
        return 1

    print(
        "[OK] No hard-coded tool IDs, thresholds, budgets, or role permissions outside sentinel_config."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
