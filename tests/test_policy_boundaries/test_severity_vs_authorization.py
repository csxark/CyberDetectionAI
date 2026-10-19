"""Tests proving that Incident Severity is strictly decoupled from Action Authorization."""
from __future__ import annotations

import uuid6

from contracts.enums import PolicyAction, Role
from contracts.models import ToolCallProposal
from policy.context import PolicyContext
from policy.engine import evaluate_policy
from sentinel_config.tools import TOOL_REGISTRY


def test_high_severity_does_not_authorize_state_changing_action() -> None:
    """A High/Critical incident severity finding NEVER bypasses policy to authorize state-changing tools."""
    # Even in a Critical incident, lab_block_ip requires human approval
    proposal = ToolCallProposal(
        id=uuid6.uuid7(),
        investigation_id=uuid6.uuid7(),
        tool_id="lab_block_ip",
        params={"ip_address": "192.168.1.100", "duration_minutes": 60, "reason": "CRITICAL INCIDENT RESPONSE"},
        reasoning="Critical severity incident detected; attempting to block IP",
    )
    # Analyst role without approved_calls
    context = PolicyContext(
        investigation_id=proposal.investigation_id,
        caller_role=Role.ANALYST,
        approved_calls=set(),
    )

    # 1. When tool is disabled in registry, high severity cannot force execution (DENY)
    default_decision = evaluate_policy(context, proposal, TOOL_REGISTRY)
    assert default_decision.action == PolicyAction.DENY
    assert default_decision.reason_code == "POLICY_TOOL_DISABLED"

    # 2. When enabled, state-changing tools require explicit human approval (REQUIRE_APPROVAL)
    custom_registry = dict(TOOL_REGISTRY)
    custom_registry["lab_block_ip"] = custom_registry["lab_block_ip"].model_copy(update={"enabled": True})
    enabled_decision = evaluate_policy(context, proposal, custom_registry)
    assert enabled_decision.action == PolicyAction.REQUIRE_APPROVAL
    assert enabled_decision.reason_code == "POLICY_APPROVAL_REQUIRED"


def test_low_severity_permits_authorized_read_only_tool() -> None:
    """A Low severity incident permits read-only analytical tool execution."""
    proposal = ToolCallProposal(
        id=uuid6.uuid7(),
        investigation_id=uuid6.uuid7(),
        tool_id="lookup_attack_technique",
        params={"technique_id": "T1078"},
        reasoning="Low severity triage: lookup technique description",
    )
    context = PolicyContext(
        investigation_id=proposal.investigation_id,
        caller_role=Role.ANALYST,
    )

    decision = evaluate_policy(context, proposal, TOOL_REGISTRY)
    assert decision.action == PolicyAction.ALLOW
    assert decision.reason_code == "POLICY_ALLOW_READ_ONLY"


def test_prohibited_action_denied_even_if_recommended() -> None:
    """An unregistered or prohibited tool proposal is always denied."""
    proposal = ToolCallProposal(
        id=uuid6.uuid7(),
        investigation_id=uuid6.uuid7(),
        tool_id="arbitrary_bash_command",
        params={"cmd": "iptables -F"},
        reasoning="Adversary response",
    )
    context = PolicyContext(investigation_id=proposal.investigation_id)

    decision = evaluate_policy(context, proposal, TOOL_REGISTRY)
    assert decision.action == PolicyAction.DENY
    assert decision.reason_code == "POLICY_TOOL_UNREGISTERED"


def test_kill_switch_blocks_all_actions() -> None:
    """When kill switch is active, even safe read-only queries are blocked."""
    proposal = ToolCallProposal(
        id=uuid6.uuid7(),
        investigation_id=uuid6.uuid7(),
        tool_id="lookup_attack_technique",
        params={"technique_id": "T1078"},
        reasoning="Safe read-only query",
    )
    context = PolicyContext(
        investigation_id=proposal.investigation_id,
        kill_switch_active=True,
    )

    decision = evaluate_policy(context, proposal, TOOL_REGISTRY)
    assert decision.action == PolicyAction.DENY
    assert decision.reason_code == "POLICY_KILL_SWITCH_ACTIVE"
