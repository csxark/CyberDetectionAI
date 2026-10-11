"""Tests for sentinel_config.validate module."""
from __future__ import annotations

from sentinel_config.validate import (
    compute_config_hash,
    validate_all,
)


def test_validate_all_passes() -> None:
    """The registered tools and default guardrails must pass all validation checks."""
    result = validate_all()
    assert result.is_valid
    assert result.total_tools >= 10
    assert result.enabled_tools >= 9
    assert len(result.errors) == 0


def test_compute_config_hash_deterministic() -> None:
    """The configuration hash must be deterministic across calls."""
    h1 = compute_config_hash()
    h2 = compute_config_hash()
    assert len(h1) == 64  # SHA-256 hex string
    assert h1 == h2


def test_validate_detects_invalid_tool_state() -> None:
    """Ensure validate_all detects violations when mock invalid tool injected."""
    from sentinel_config.tools import RiskClass, TargetKind, ToolOperation, ToolSpec

    # Construct an invalid tool spec directly bypassing validator via object.__setattr__ if needed
    # or verify that ConfigValidationError is raised by validate_all if any check fails
    tool = ToolSpec.model_construct(
        id="bad_tool",
        description="Invalid tool that allows network",
        risk_class=RiskClass.READ_ONLY,
        target_kind=TargetKind.KB,
        operation=ToolOperation.SEARCH,
        network_allowed=True,  # Violation of INV-6
    )

    from sentinel_config.validate import validate_tool
    errors = validate_tool(tool)
    assert any("INV-6" in e or "network" in e for e in errors)
