"""Tests for sentinel_config: tools, guardrails, and validation rules."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from sentinel_config.guardrails import DEFAULT_GUARDRAILS, GuardrailsConfig
from sentinel_config.tools import (
    TOOL_REGISTRY,
    ParamSpec,
    RiskClass,
    TargetKind,
    ToolOperation,
    ToolSpec,
    get_enabled_tools,
    get_tool,
)


class TestToolSpecModel:
    """Validate invariants enforced on ToolSpec."""

    def test_state_changing_requires_approval(self) -> None:
        """INV-3: state_changing tools must require human approval."""
        with pytest.raises(ValidationError, match="requires_approval=True"):
            ToolSpec(
                id="malicious_exec",
                description="State changing tool without approval requirement",
                risk_class=RiskClass.STATE_CHANGING,
                target_kind=TargetKind.SANDBOX,
                operation=ToolOperation.CHECK,
                requires_approval=False,
                lab_only=True,
            )

    def test_state_changing_requires_lab_only(self) -> None:
        """INV-3: state_changing tools must be lab-only."""
        with pytest.raises(ValidationError, match="lab_only=True"):
            ToolSpec(
                id="malicious_exec",
                description="State changing tool not in lab",
                risk_class=RiskClass.STATE_CHANGING,
                target_kind=TargetKind.SANDBOX,
                operation=ToolOperation.CHECK,
                requires_approval=True,
                lab_only=False,
            )

    def test_network_allowed_forbidden(self) -> None:
        """INV-6: network_allowed must never be True."""
        with pytest.raises(ValidationError, match="INV-6"):
            ToolSpec(
                id="egress_tool",
                description="Tool trying to egress data",
                risk_class=RiskClass.READ_ONLY,
                target_kind=TargetKind.KB,
                operation=ToolOperation.SEARCH,
                network_allowed=True,
            )

    def test_retry_on_error_only_for_read_only(self) -> None:
        """Only read_only tools may retry on error."""
        with pytest.raises(ValidationError, match="retry_on_error=True only allowed for read_only"):
            ToolSpec(
                id="flaky_sandbox",
                description="Sandbox check that retries",
                risk_class=RiskClass.SANDBOX_EPHEMERAL,
                target_kind=TargetKind.SANDBOX,
                operation=ToolOperation.CHECK,
                retry_on_error=True,
            )

    def test_tool_id_format(self) -> None:
        """Tool IDs must be snake_case starting with a lowercase letter."""
        with pytest.raises(ValidationError):
            ToolSpec(
                id="Invalid-Name!",
                description="Invalid ID format",
                risk_class=RiskClass.READ_ONLY,
                target_kind=TargetKind.KB,
                operation=ToolOperation.SEARCH,
            )


class TestToolRegistry:
    """Validate all registered tools in sentinel_config."""

    def test_registry_not_empty(self) -> None:
        assert len(TOOL_REGISTRY) >= 10

    def test_all_registered_tools_are_valid(self) -> None:
        for tool_id, spec in TOOL_REGISTRY.items():
            assert spec.id == tool_id
            assert len(spec.description) >= 10
            assert spec.timeout_seconds > 0
            assert spec.max_output_bytes > 0
            assert not spec.network_allowed

    def test_lab_block_ip_disabled_by_default(self) -> None:
        block_tool = get_tool("lab_block_ip")
        assert block_tool is not None
        assert not block_tool.enabled
        assert block_tool.requires_approval
        assert block_tool.lab_only
        assert block_tool.risk_class == RiskClass.STATE_CHANGING

    def test_check_patch_is_sandbox_ephemeral(self) -> None:
        patch_tool = get_tool("check_patch")
        assert patch_tool is not None
        assert patch_tool.risk_class == RiskClass.SANDBOX_EPHEMERAL
        assert patch_tool.target_kind == TargetKind.SANDBOX

    def test_enabled_tools_exclude_disabled(self) -> None:
        enabled = get_enabled_tools()
        assert "lab_block_ip" not in enabled
        assert "parse_logs" in enabled

    def test_param_spec_closed_types(self) -> None:
        with pytest.raises(ValidationError):
            ParamSpec(name="bad", type="unknown_type", description="desc")


class TestGuardrailsConfig:
    """Validate guardrails configuration and invariants."""

    def test_default_guardrails_valid(self) -> None:
        g = DEFAULT_GUARDRAILS
        assert g.budget.wall_seconds == 300
        assert g.budget.llm_calls == 30
        assert g.budget.jev_calls == 60
        assert g.scope.max_evidence_bytes == 5_242_880
        assert g.agent.kill_switch_check_interval_seconds == 0

    def test_kill_switch_interval_must_be_zero(self) -> None:
        """INV-12: Kill switch check interval must be 0 (every edge)."""
        with pytest.raises(ValidationError, match="kill_switch_check_interval_seconds must be 0"):
            GuardrailsConfig.model_validate({
                "agent": {"kill_switch_check_interval_seconds": 5}
            })

    def test_critical_percent_above_warning(self) -> None:
        with pytest.raises(ValidationError, match="critical_percent .* must be > warning_percent"):
            GuardrailsConfig.model_validate({
                "quota_alerts": {"warning_percent": 80, "critical_percent": 75}
            })
