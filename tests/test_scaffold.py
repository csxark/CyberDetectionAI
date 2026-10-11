"""Smoke test: scaffold structure is correct."""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGES = [
    "sentinel_config",
    "contracts",
    "policy",
    "gateway",
    "agent",
    "llm",
    "decision",
    "tools",
    "redaction",
    "audit",
    "api",
    "evidence",
]


class TestScaffold:
    """Verify monorepo directory structure."""

    @pytest.mark.parametrize("pkg", PACKAGES)
    def test_package_exists(self, pkg: str) -> None:
        init = REPO_ROOT / "packages" / pkg / "__init__.py"
        assert init.exists(), f"Missing {init}"

    def test_brain_files_exist(self) -> None:
        for num in (17, 18, 19):
            path = (
                REPO_ROOT
                / "brain"
                / f"{num}_{'MICRO_TASKS' if num == 17 else 'CHANGELOG' if num == 18 else 'DECISIONS'}.md"
            )
            assert path.exists(), f"Missing {path}"

    def test_gitignore_exists(self) -> None:
        assert (REPO_ROOT / ".gitignore").exists()

    def test_importlinter_exists(self) -> None:
        assert (REPO_ROOT / ".importlinter").exists()

    def test_env_example_exists(self) -> None:
        assert (REPO_ROOT / ".env.example").exists()

    def test_env_example_has_no_real_secrets(self) -> None:
        content = (REPO_ROOT / ".env.example").read_text()
        # Keys should be empty or contain placeholder
        for line in content.splitlines():
            if "=" in line and not line.startswith("#"):
                _key, _, value = line.partition("=")
                # Values must be empty, a placeholder, or a comment
                assert (
                    value == ""
                    or "changeme" in value
                    or value.startswith("#")
                    or "mock" in value
                    or "localhost" in value
                    or "false" in value
                    or "INFO" in value
                    or "HS256" in value
                    or value.isdigit()
                ), f"Possible real secret in .env.example: {line}"

    def test_scripts_dir_exists(self) -> None:
        assert (REPO_ROOT / "scripts" / "check_no_hardcoded_tools.py").exists()

    def test_docs_dir_exists(self) -> None:
        assert (REPO_ROOT / "docs" / "architecture" / "blueprint.md").exists()
