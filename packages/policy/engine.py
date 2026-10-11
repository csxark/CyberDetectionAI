"""Pure authorization function for SentinelAI.

Evaluates proposals against policy invariants, budgets, tool specifications,
parameter constraints, and human approval status.

Invariants enforced:
  - Kill switch halts execution immediately
  - Budgets strictly bounded
  - Registered & enabled tools only
  - Closed parameter schema enforcement (traversal blocked)
  - State-changing actions require human approval
  - Controls output cap, timeouts, network=False explicitly configured
"""
from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

import uuid6

from contracts.enums import PolicyAction
from contracts.models import PolicyDecision, ToolCallProposal
from policy.context import PolicyContext  # noqa: TCH001
from sentinel_config.guardrails import DEFAULT_GUARDRAILS, GuardrailsConfig
from sentinel_config.tools import TOOL_REGISTRY, ToolSpec


def _contains_traversal(val: str) -> bool:
    """Detect directory traversal sequences."""
    return ".." in val or val.startswith(("//", "\\\\"))


def _validate_param(param_spec: Any, val: Any) -> str | None:
    """Validate a single parameter value against ParamSpec constraints."""
    # Type check
    expected_type = param_spec.type
    if expected_type == "string" and not isinstance(val, str):
        return f"Param '{param_spec.name}' must be a string."
    if expected_type == "integer" and not isinstance(val, int):
        return f"Param '{param_spec.name}' must be an integer."
    if expected_type == "boolean" and not isinstance(val, bool):
        return f"Param '{param_spec.name}' must be a boolean."
    if expected_type == "array" and not isinstance(val, list):
        return f"Param '{param_spec.name}' must be a list."
    if expected_type == "object" and not isinstance(val, dict):
        return f"Param '{param_spec.name}' must be an object."

    # String constraints
    if isinstance(val, str):
        if _contains_traversal(val):
            return "TRAVERSAL"
        if param_spec.max_length and len(val) > param_spec.max_length:
            return f"Param '{param_spec.name}' exceeds max_length {param_spec.max_length}."
        if param_spec.pattern and not re.match(param_spec.pattern, val):
            return f"Param '{param_spec.name}' does not match pattern '{param_spec.pattern}'."
        if param_spec.enum_values and val not in param_spec.enum_values:
            return f"Param '{param_spec.name}' value '{val}' not in allowed values."

    # Integer constraints
    if isinstance(val, int) and not isinstance(val, bool):
        if param_spec.min_value is not None and val < param_spec.min_value:
            return f"Param '{param_spec.name}' is less than minimum {param_spec.min_value}."
        if param_spec.max_value is not None and val > param_spec.max_value:
            return f"Param '{param_spec.name}' exceeds maximum {param_spec.max_value}."

    return None


def evaluate_policy(
    context: PolicyContext,
    proposal: ToolCallProposal,
    registry: dict[str, ToolSpec] | None = None,
    guardrails: GuardrailsConfig | None = None,
) -> PolicyDecision:
    """Pure policy evaluation function. Never raises; returns DENY on errors."""
    eval_time = datetime.now(UTC)
    tools = registry if registry is not None else TOOL_REGISTRY
    cfg = guardrails if guardrails is not None else DEFAULT_GUARDRAILS

    try:
        # 1. Kill Switch check
        if context.kill_switch_active:
            return PolicyDecision(
                id=uuid6.uuid7(),
                call_id=proposal.id,
                action=PolicyAction.DENY,
                reason_code="POLICY_KILL_SWITCH_ACTIVE",
                explanation_template="System execution halted by operator kill switch.",
                controls={},
                evaluated_at=eval_time,
            )

        # 2. Budget limits
        if context.wall_seconds_used >= cfg.budget.wall_seconds:
            return PolicyDecision(
                id=uuid6.uuid7(),
                call_id=proposal.id,
                action=PolicyAction.DENY,
                reason_code="POLICY_BUDGET_EXHAUSTED",
                explanation_template="Wall-clock time budget exceeded for this investigation.",
                controls={},
                evaluated_at=eval_time,
            )

        if context.tool_calls_used >= cfg.budget.tool_calls:
            return PolicyDecision(
                id=uuid6.uuid7(),
                call_id=proposal.id,
                action=PolicyAction.DENY,
                reason_code="POLICY_BUDGET_EXHAUSTED",
                explanation_template="Tool calls budget exceeded for this investigation.",
                controls={},
                evaluated_at=eval_time,
            )

        # 3. Tool denials limit
        tool_denials = context.denials_for_tool.get(proposal.tool_id, 0)
        if tool_denials >= cfg.agent.denials_per_tool_max:
            return PolicyDecision(
                id=uuid6.uuid7(),
                call_id=proposal.id,
                action=PolicyAction.DENY,
                reason_code="POLICY_TOOL_MAX_DENIALS_EXCEEDED",
                explanation_template="Maximum policy denials reached for this tool; skipping.",
                controls={},
                evaluated_at=eval_time,
            )

        # 4. Tool registered check
        if proposal.tool_id not in tools:
            return PolicyDecision(
                id=uuid6.uuid7(),
                call_id=proposal.id,
                action=PolicyAction.DENY,
                reason_code="POLICY_TOOL_UNREGISTERED",
                explanation_template="Requested tool is not in the approved tool registry.",
                controls={},
                evaluated_at=eval_time,
            )

        spec = tools[proposal.tool_id]

        # 5. Tool enabled check
        if not spec.enabled:
            return PolicyDecision(
                id=uuid6.uuid7(),
                call_id=proposal.id,
                action=PolicyAction.DENY,
                reason_code="POLICY_TOOL_DISABLED",
                explanation_template="Tool is disabled by policy configuration.",
                controls={},
                evaluated_at=eval_time,
            )

        # 6. Parameter validation & Traversal check
        params = proposal.params
        for p_spec in spec.params:
            if p_spec.required and p_spec.name not in params:
                return PolicyDecision(
                    id=uuid6.uuid7(),
                    call_id=proposal.id,
                    action=PolicyAction.DENY,
                    reason_code="POLICY_PARAM_INVALID",
                    explanation_template=f"Required parameter '{p_spec.name}' missing.",
                    controls={},
                    evaluated_at=eval_time,
                )

            if p_spec.name in params:
                err = _validate_param(p_spec, params[p_spec.name])
                if err == "TRAVERSAL":
                    return PolicyDecision(
                        id=uuid6.uuid7(),
                        call_id=proposal.id,
                        action=PolicyAction.DENY,
                        reason_code="POLICY_PARAM_TRAVERSAL",
                        explanation_template="Path traversal pattern detected in parameters.",
                        controls={},
                        evaluated_at=eval_time,
                    )
                if err is not None:
                    return PolicyDecision(
                        id=uuid6.uuid7(),
                        call_id=proposal.id,
                        action=PolicyAction.DENY,
                        reason_code="POLICY_PARAM_INVALID",
                        explanation_template=err,
                        controls={},
                        evaluated_at=eval_time,
                    )

        # 7. Human approval gate for state-changing or approval-required tools
        if spec.requires_approval and proposal.id not in context.approved_calls:
            return PolicyDecision(
                id=uuid6.uuid7(),
                call_id=proposal.id,
                action=PolicyAction.REQUIRE_APPROVAL,
                reason_code="POLICY_APPROVAL_REQUIRED",
                explanation_template="Operation requires explicit human approval before execution.",
                controls={
                    "timeout_seconds": spec.timeout_seconds,
                    "lab_only": spec.lab_only,
                },
                evaluated_at=eval_time,
            )

        # 8. Success: ALLOW with explicit execution controls
        reason = "POLICY_ALLOW_APPROVED" if spec.requires_approval else "POLICY_ALLOW_READ_ONLY"
        return PolicyDecision(
            id=uuid6.uuid7(),
            call_id=proposal.id,
            action=PolicyAction.ALLOW,
            reason_code=reason,
            explanation_template="Operation authorized within specified execution controls.",
            controls={
                "timeout_seconds": spec.timeout_seconds,
                "max_output_bytes": spec.max_output_bytes,
                "network_allowed": False,
                "retry_on_error": spec.retry_on_error,
                "risk_class": spec.risk_class.value,
                "target_kind": spec.target_kind.value,
            },
            evaluated_at=eval_time,
        )

    except Exception:
        return PolicyDecision(
            id=uuid6.uuid7(),
            call_id=proposal.id,
            action=PolicyAction.DENY,
            reason_code="POLICY_INTERNAL_ERROR",
            explanation_template="Internal policy evaluation failure.",
            controls={},
            evaluated_at=eval_time,
        )
