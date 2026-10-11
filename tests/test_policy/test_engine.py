"""Unit tests for the SentinelAI Policy Engine (pure authorization function)."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
import uuid6

from contracts.enums import PolicyAction, Role
from contracts.models import ToolCallProposal
from policy.context import PolicyContext
from policy.engine import evaluate_policy
from sentinel_config.tools import TOOL_REGISTRY


@pytest.fixture
def base_context() -> PolicyContext:
    """Create a healthy policy evaluation context."""
    return PolicyContext(
        investigation_id=uuid6.uuid7(),
        caller_role=Role.ANALYST,
        kill_switch_active=False,
        wall_seconds_used=10,
        llm_calls_used=2,
        jev_calls_used=3,
        tool_calls_used=4,
        denials_for_tool={"parse_logs": 0},
        investigation_scope_paths=["/data/evidence/"],
    )


class TestPolicyEngineOrder:
    """Verify strictly ordered evaluation: kill switch -> budget -> tool -> scope -> params -> role -> approval -> ALLOW."""

    def test_kill_switch_active_denies_all_tools(self, base_context: PolicyContext) -> None:
        """INV-12: Kill switch active must immediately halt/deny with POLICY_KILL_SWITCH_ACTIVE."""
        ctx = base_context.model_copy(update={"kill_switch_active": True})
        proposal = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=ctx.investigation_id,
            tool_id="parse_logs",
            params={"evidence_id": "ev-01"},
            reasoning="Valid reasoning",
            created_at=datetime.now(UTC),
        )
        dec = evaluate_policy(ctx, proposal)
        assert dec.action == PolicyAction.DENY
        assert dec.reason_code == "POLICY_KILL_SWITCH_ACTIVE"

    def test_wall_seconds_budget_exhaustion(self, base_context: PolicyContext) -> None:
        """Exceeded wall clock budget denies with POLICY_BUDGET_EXHAUSTED."""
        ctx = base_context.model_copy(update={"wall_seconds_used": 305})
        proposal = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=ctx.investigation_id,
            tool_id="parse_logs",
            params={"evidence_id": "ev-01"},
            reasoning="Valid reasoning",
            created_at=datetime.now(UTC),
        )
        dec = evaluate_policy(ctx, proposal)
        assert dec.action == PolicyAction.DENY
        assert dec.reason_code == "POLICY_BUDGET_EXHAUSTED"

    def test_tool_calls_budget_exhaustion(self, base_context: PolicyContext) -> None:
        """Exceeded tool call budget denies with POLICY_BUDGET_EXHAUSTED."""
        ctx = base_context.model_copy(update={"tool_calls_used": 51})
        proposal = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=ctx.investigation_id,
            tool_id="parse_logs",
            params={"evidence_id": "ev-01"},
            reasoning="Valid reasoning",
            created_at=datetime.now(UTC),
        )
        dec = evaluate_policy(ctx, proposal)
        assert dec.action == PolicyAction.DENY
        assert dec.reason_code == "POLICY_BUDGET_EXHAUSTED"

    def test_three_denials_per_tool_stop(self, base_context: PolicyContext) -> None:
        """Guardrail: 3 denials for a specific tool blocks further attempts for that tool."""
        ctx = base_context.model_copy(update={"denials_for_tool": {"parse_logs": 3}})
        proposal = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=ctx.investigation_id,
            tool_id="parse_logs",
            params={"evidence_id": "ev-01"},
            reasoning="Retrying after 3 denials",
            created_at=datetime.now(UTC),
        )
        dec = evaluate_policy(ctx, proposal)
        assert dec.action == PolicyAction.DENY
        assert dec.reason_code == "POLICY_TOOL_MAX_DENIALS_EXCEEDED"

    def test_unregistered_tool_denied(self, base_context: PolicyContext) -> None:
        """Unregistered tools are denied with POLICY_TOOL_UNREGISTERED."""
        proposal = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=base_context.investigation_id,
            tool_id="nmap_scan_network",
            params={"target": "10.0.0.1"},
            reasoning="Offensive port scanning",
            created_at=datetime.now(UTC),
        )
        dec = evaluate_policy(base_context, proposal)
        assert dec.action == PolicyAction.DENY
        assert dec.reason_code == "POLICY_TOOL_UNREGISTERED"

    def test_disabled_tool_denied(self, base_context: PolicyContext) -> None:
        """Disabled tools (like lab_block_ip by default) denied with POLICY_TOOL_DISABLED."""
        proposal = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=base_context.investigation_id,
            tool_id="lab_block_ip",
            params={"ip_address": "198.51.100.42", "reason": "Testing block"},
            reasoning="Blocking IP",
            created_at=datetime.now(UTC),
        )
        dec = evaluate_policy(base_context, proposal)
        assert dec.action == PolicyAction.DENY
        assert dec.reason_code == "POLICY_TOOL_DISABLED"

    def test_missing_required_params_denied(self, base_context: PolicyContext) -> None:
        """Missing required parameter rejected with POLICY_PARAM_INVALID."""
        proposal = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=base_context.investigation_id,
            tool_id="parse_logs",
            params={},  # missing required 'evidence_id'
            reasoning="Parsing without id",
            created_at=datetime.now(UTC),
        )
        dec = evaluate_policy(base_context, proposal)
        assert dec.action == PolicyAction.DENY
        assert dec.reason_code == "POLICY_PARAM_INVALID"

    def test_path_traversal_in_params_denied(self, base_context: PolicyContext) -> None:
        """Path traversal characters ('..', absolute paths) rejected with POLICY_PARAM_TRAVERSAL."""
        proposal = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=base_context.investigation_id,
            tool_id="code_search",
            params={
                "investigation_id": str(base_context.investigation_id),
                "pattern": "secret",
                "file_glob": "../../../etc/passwd",
            },
            reasoning="Searching outside repo",
            created_at=datetime.now(UTC),
        )
        dec = evaluate_policy(base_context, proposal)
        assert dec.action == PolicyAction.DENY
        assert dec.reason_code == "POLICY_PARAM_TRAVERSAL"

    def test_param_regex_pattern_mismatch_denied(self, base_context: PolicyContext) -> None:
        """Parameter failing regex pattern rejected with POLICY_PARAM_INVALID."""
        proposal = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=base_context.investigation_id,
            tool_id="lookup_attack_technique",
            params={"technique_id": "NOT_AN_ATTACK_ID"},
            reasoning="Invalid technique lookup",
            created_at=datetime.now(UTC),
        )
        dec = evaluate_policy(base_context, proposal)
        assert dec.action == PolicyAction.DENY
        assert dec.reason_code == "POLICY_PARAM_INVALID"

    def test_state_changing_tool_requires_approval(self, base_context: PolicyContext) -> None:
        """INV-3: Enabled state_changing tool must return REQUIRE_APPROVAL."""
        # Enable lab_block_ip in custom registry for this test
        custom_registry = dict(TOOL_REGISTRY)
        block_tool = custom_registry["lab_block_ip"].model_copy(update={"enabled": True})
        custom_registry["lab_block_ip"] = block_tool

        ctx = base_context.model_copy(update={"approved_calls": set()})
        proposal = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=ctx.investigation_id,
            tool_id="lab_block_ip",
            params={"ip_address": "198.51.100.42", "reason": "Simulated attacker"},
            reasoning="Blocking attacker in lab",
            created_at=datetime.now(UTC),
        )
        dec = evaluate_policy(ctx, proposal, registry=custom_registry)
        assert dec.action == PolicyAction.REQUIRE_APPROVAL
        assert dec.reason_code == "POLICY_APPROVAL_REQUIRED"

    def test_approved_state_changing_tool_allows_with_controls(self, base_context: PolicyContext) -> None:
        """Once approved, state_changing tool returns ALLOW with sandbox/timeout controls."""
        call_id = uuid6.uuid7()
        custom_registry = dict(TOOL_REGISTRY)
        block_tool = custom_registry["lab_block_ip"].model_copy(update={"enabled": True})
        custom_registry["lab_block_ip"] = block_tool

        ctx = base_context.model_copy(update={"approved_calls": {call_id}})
        proposal = ToolCallProposal(
            id=call_id,
            investigation_id=ctx.investigation_id,
            tool_id="lab_block_ip",
            params={"ip_address": "198.51.100.42", "reason": "Simulated attacker"},
            reasoning="Blocking attacker in lab",
            created_at=datetime.now(UTC),
        )
        dec = evaluate_policy(ctx, proposal, registry=custom_registry)
        assert dec.action == PolicyAction.ALLOW
        assert dec.reason_code == "POLICY_ALLOW_APPROVED"
        assert dec.controls["network_allowed"] is False
        assert dec.controls["timeout_seconds"] == 10

    def test_valid_read_only_tool_returns_allow(self, base_context: PolicyContext) -> None:
        """Valid read-only tool call returns ALLOW with exact execution controls."""
        proposal = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=base_context.investigation_id,
            tool_id="parse_logs",
            params={"evidence_id": "ev-01"},
            reasoning="Parsing uploaded logs",
            created_at=datetime.now(UTC),
        )
        dec = evaluate_policy(base_context, proposal)
        assert dec.action == PolicyAction.ALLOW
        assert dec.reason_code == "POLICY_ALLOW_READ_ONLY"
        assert dec.controls["timeout_seconds"] == 30
        assert dec.controls["max_output_bytes"] == 65536
        assert dec.controls["network_allowed"] is False

    def test_param_type_mismatches_denied(self, base_context: PolicyContext) -> None:
        """Integer, string, boolean, list, dict type checks."""
        # Non-string for evidence_id
        prop1 = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=base_context.investigation_id,
            tool_id="parse_logs",
            params={"evidence_id": 12345},
            reasoning="Wrong type",
            created_at=datetime.now(UTC),
        )
        assert evaluate_policy(base_context, prop1).action == PolicyAction.DENY

        # Non-integer for limit in search_events
        prop2 = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=base_context.investigation_id,
            tool_id="search_events",
            params={
                "investigation_id": str(base_context.investigation_id),
                "query": {"field": "val"},
                "limit": "not_an_int",
            },
            reasoning="Wrong type",
            created_at=datetime.now(UTC),
        )
        assert evaluate_policy(base_context, prop2).action == PolicyAction.DENY

        # Non-object for query in search_events
        prop3 = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=base_context.investigation_id,
            tool_id="search_events",
            params={
                "investigation_id": str(base_context.investigation_id),
                "query": "string_not_dict",
            },
            reasoning="Wrong type",
            created_at=datetime.now(UTC),
        )
        assert evaluate_policy(base_context, prop3).action == PolicyAction.DENY

        # Non-boolean for include_timeline in build_report
        prop4 = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=base_context.investigation_id,
            tool_id="build_report",
            params={
                "investigation_id": str(base_context.investigation_id),
                "include_timeline": "not_a_bool",
            },
            reasoning="Wrong type",
            created_at=datetime.now(UTC),
        )
        assert evaluate_policy(base_context, prop4).action == PolicyAction.DENY

        # Non-list for indicator_types in extract_indicators
        prop5 = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=base_context.investigation_id,
            tool_id="extract_indicators",
            params={"evidence_id": "ev-01", "indicator_types": "not_a_list"},
            reasoning="Wrong type",
            created_at=datetime.now(UTC),
        )
        assert evaluate_policy(base_context, prop5).action == PolicyAction.DENY

    def test_integer_min_max_bounds_denied(self, base_context: PolicyContext) -> None:
        """Integer exceeding max_value or below min_value rejected."""
        # limit < min_value (1)
        prop_min = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=base_context.investigation_id,
            tool_id="search_events",
            params={
                "investigation_id": str(base_context.investigation_id),
                "query": {"field": "val"},
                "limit": 0,
            },
            reasoning="Below min",
            created_at=datetime.now(UTC),
        )
        assert evaluate_policy(base_context, prop_min).action == PolicyAction.DENY

        # limit > max_value (1000)
        prop_max = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=base_context.investigation_id,
            tool_id="search_events",
            params={
                "investigation_id": str(base_context.investigation_id),
                "query": {"field": "val"},
                "limit": 5000,
            },
            reasoning="Above max",
            created_at=datetime.now(UTC),
        )
        assert evaluate_policy(base_context, prop_max).action == PolicyAction.DENY

    def test_enum_values_validation(self, base_context: PolicyContext) -> None:
        """String param with enum_values rejects disallowed values and allows valid ones."""
        # Disallowed enum value
        prop_invalid = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=base_context.investigation_id,
            tool_id="parse_logs",
            params={
                "evidence_id": "ev-01",
                "format_hint": "invalid_unsupported_format",
            },
            reasoning="Invalid format",
            created_at=datetime.now(UTC),
        )
        dec_invalid = evaluate_policy(base_context, prop_invalid)
        assert dec_invalid.action == PolicyAction.DENY
        assert dec_invalid.reason_code == "POLICY_PARAM_INVALID"
        assert "not in allowed values" in dec_invalid.explanation_template

        # Allowed enum value
        prop_valid = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=base_context.investigation_id,
            tool_id="parse_logs",
            params={
                "evidence_id": "ev-01",
                "format_hint": "jsonl",
            },
            reasoning="Valid format",
            created_at=datetime.now(UTC),
        )
        dec_valid = evaluate_policy(base_context, prop_valid)
        assert dec_valid.action == PolicyAction.ALLOW

    def test_valid_bounded_integer_allowed(self, base_context: PolicyContext) -> None:
        """Valid integer within min/max bounds is permitted."""
        prop = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=base_context.investigation_id,
            tool_id="search_events",
            params={
                "investigation_id": str(base_context.investigation_id),
                "query": {"field": "val"},
                "limit": 50,
            },
            reasoning="Valid limit within bounds",
            created_at=datetime.now(UTC),
        )
        dec = evaluate_policy(base_context, prop)
        assert dec.action == PolicyAction.ALLOW


    def test_string_max_length_denied(self, base_context: PolicyContext) -> None:
        """String exceeding max_length rejected."""
        prop = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=base_context.investigation_id,
            tool_id="search_kb",
            params={"query": "A" * 501},  # max_length is 500
            reasoning="Query too long",
            created_at=datetime.now(UTC),
        )
        dec = evaluate_policy(base_context, prop)
        assert dec.action == PolicyAction.DENY
        assert dec.reason_code == "POLICY_PARAM_INVALID"

    def test_exception_safety_returns_internal_error(self, base_context: PolicyContext) -> None:
        """Any unexpected runtime exception produces DENY POLICY_INTERNAL_ERROR without crashing."""
        # Malformed proposal causing exception during lookup
        class ExplodingProposal:
            id = uuid6.uuid7()
            tool_id = property(lambda _self: (_ for _ in ()).throw(RuntimeError("Boom!")))

        dec = evaluate_policy(base_context, ExplodingProposal())  # type: ignore[arg-type]
        assert dec.action == PolicyAction.DENY
        assert dec.reason_code == "POLICY_INTERNAL_ERROR"
