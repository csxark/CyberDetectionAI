"""Hypothesis property-based tests for Policy Engine invariants."""
from __future__ import annotations

from datetime import UTC, datetime

import uuid6
from hypothesis import given
from hypothesis import strategies as st

from contracts.enums import PolicyAction, Role
from contracts.models import ToolCallProposal
from policy.context import PolicyContext
from policy.engine import evaluate_policy


class TestPolicyProperties:
    """Mathematical invariants of the Policy Engine."""

    @given(
        tool_name=st.text(min_size=1, max_size=50).filter(
            lambda s: s not in {
                "parse_logs", "extract_indicators", "search_events",
                "correlate_timeline", "lookup_attack_technique", "search_kb",
                "match_sigma_rules", "code_search", "check_patch",
                "build_report", "lab_block_ip",
            }
        )
    )
    def test_unregistered_tools_never_allowed(self, tool_name: str) -> None:
        """Property: evaluate_policy NEVER returns ALLOW for any tool not in TOOL_REGISTRY."""
        ctx = PolicyContext(
            investigation_id=uuid6.uuid7(),
            caller_role=Role.ANALYST,
            kill_switch_active=False,
            wall_seconds_used=0,
            llm_calls_used=0,
            jev_calls_used=0,
            tool_calls_used=0,
        )
        proposal = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=ctx.investigation_id,
            tool_id=tool_name,
            params={},
            reasoning="Testing arbitrary tool name",
            created_at=datetime.now(UTC),
        )
        decision = evaluate_policy(ctx, proposal)
        assert decision.action != PolicyAction.ALLOW

    @given(wall_seconds=st.integers(min_value=301, max_value=10000))
    def test_budget_exhaustion_never_allowed(self, wall_seconds: int) -> None:
        """Property: evaluate_policy NEVER returns ALLOW when wall_seconds budget exceeded."""
        ctx = PolicyContext(
            investigation_id=uuid6.uuid7(),
            caller_role=Role.ANALYST,
            kill_switch_active=False,
            wall_seconds_used=wall_seconds,
            llm_calls_used=0,
            jev_calls_used=0,
            tool_calls_used=0,
        )
        proposal = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=ctx.investigation_id,
            tool_id="parse_logs",
            params={"evidence_id": "ev-01"},
            reasoning="Valid tool call",
            created_at=datetime.now(UTC),
        )
        decision = evaluate_policy(ctx, proposal)
        assert decision.action == PolicyAction.DENY
        assert decision.reason_code == "POLICY_BUDGET_EXHAUSTED"

    @given(tool_calls=st.integers(min_value=51, max_value=10000))
    def test_tool_call_budget_monotonicity(self, tool_calls: int) -> None:
        """Property: Once tool call budget is exceeded, it remains DENY."""
        ctx = PolicyContext(
            investigation_id=uuid6.uuid7(),
            caller_role=Role.ANALYST,
            kill_switch_active=False,
            wall_seconds_used=0,
            llm_calls_used=0,
            jev_calls_used=0,
            tool_calls_used=tool_calls,
        )
        proposal = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=ctx.investigation_id,
            tool_id="parse_logs",
            params={"evidence_id": "ev-01"},
            reasoning="Valid tool call",
            created_at=datetime.now(UTC),
        )
        decision = evaluate_policy(ctx, proposal)
        assert decision.action == PolicyAction.DENY
        assert decision.reason_code == "POLICY_BUDGET_EXHAUSTED"
