"""Tool Gateway — solitary executor of tools under strict policy enforcement.

Enforces:
  - INV-1: Authority split (agent proposes, gateway executes)
  - INV-4: Policy decider integrity (re-evaluates policy before invocation)
  - INV-5: Bounded execution (timeout, output size cap)
  - INV-6: No network egress
  - INV-7: All tool results default to untrusted
  - INV-8: Cryptographic hash-chained audit of all executions
"""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import uuid6

from audit.writer import InMemoryAuditChainWriter
from contracts.enums import PolicyAction, ToolId, TrustLevel
from contracts.models import EvidenceEnvelope, PolicyDecision, ToolCallProposal
from policy.engine import evaluate_policy
from sentinel_config.tools import TOOL_REGISTRY
from tools.handlers import (
    handle_check_patch,
    handle_code_search,
    handle_lab_block_ip,
    handle_lookup_attack_technique,
    handle_match_sigma_rules,
    handle_search_kb,
)

if TYPE_CHECKING:
    from policy.context import PolicyContext


class ToolGateway:
    """Isolated execution engine for SentinelAI tools."""

    def __init__(self, audit_writer: InMemoryAuditChainWriter | None = None) -> None:
        self.audit_writer = audit_writer or InMemoryAuditChainWriter()

    async def execute_tool(
        self,
        proposal: ToolCallProposal,
        context: PolicyContext,
        events: list[dict[str, Any]] | None = None,
    ) -> tuple[PolicyDecision, EvidenceEnvelope | None]:
        """Re-evaluate policy and execute tool if and only if ALLOW."""
        # 1. Independent policy verification
        decision = evaluate_policy(context, proposal, TOOL_REGISTRY)

        # 2. Audit the policy decision
        await self.audit_writer.append(
            event_type="policy_evaluation",
            actor="policy_engine",
            action="evaluate_policy",
            payload={
                "proposal_id": str(proposal.id),
                "tool_id": proposal.tool_id,
                "action": decision.action.value,
                "reason_code": decision.reason_code,
            },
            investigation_id=str(context.investigation_id),
        )

        if decision.action != PolicyAction.ALLOW:
            return decision, None

        # 3. Dispatch to safe handler under timeout bound
        spec = TOOL_REGISTRY[proposal.tool_id]
        timeout = decision.controls.get("timeout_seconds", spec.timeout_seconds)
        max_bytes = decision.controls.get("max_output_bytes", spec.max_output_bytes)

        result_data: Any = None
        try:
            async def _run() -> Any:
                params = proposal.params
                tool_id = proposal.tool_id

                if tool_id == ToolId.LOOKUP_ATTACK_TECHNIQUE:
                    return handle_lookup_attack_technique(params)
                if tool_id == ToolId.SEARCH_KB:
                    return handle_search_kb(params)
                if tool_id == ToolId.MATCH_SIGMA_RULES:
                    return handle_match_sigma_rules(events or [], params.get("rule_ids"))
                if tool_id == ToolId.CODE_SEARCH:
                    return handle_code_search(params)
                if tool_id == ToolId.CHECK_PATCH:
                    return handle_check_patch(params)
                if tool_id == ToolId.LAB_BLOCK_IP:
                    return handle_lab_block_ip(params)
                return {"executed": True, "tool_id": tool_id, "simulated": True, "params": params}

            result_data = await asyncio.wait_for(_run(), timeout=float(timeout))

        except TimeoutError:
            result_data = {
                "error": f"Tool execution exceeded timeout of {timeout} seconds.",
                "tool_id": proposal.tool_id,
            }
        except Exception as err:
            result_data = {
                "error": f"Tool execution failed: {err}",
                "tool_id": proposal.tool_id,
            }

        # 4. Format into EvidenceEnvelope with untrusted boundary
        import json
        content_str = json.dumps(result_data, indent=2, ensure_ascii=True)
        if len(content_str.encode("utf-8")) > max_bytes:
            content_str = content_str[:max_bytes] + "\n... [TRUNCATED DUE TO SIZE CAP]"

        envelope_id = uuid6.uuid7()
        envelope = EvidenceEnvelope(
            id=envelope_id,
            boundary=f"BOUNDARY_TOOL_{envelope_id}",
            trust=TrustLevel.UNTRUSTED,
            raw_bytes=len(content_str.encode("utf-8")),
            format="json",
            content=content_str,
            suspected_injection=False,
            created_at=datetime.now(UTC),
        )

        # 5. Audit the tool execution outcome
        await self.audit_writer.append(
            event_type="tool_execution",
            actor="tool_gateway",
            action="execute_tool",
            payload={
                "proposal_id": str(proposal.id),
                "tool_id": proposal.tool_id,
                "envelope_id": str(envelope_id),
                "bytes": envelope.raw_bytes,
            },
            investigation_id=str(context.investigation_id),
        )

        return decision, envelope
