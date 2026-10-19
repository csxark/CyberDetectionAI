"""FastAPI router for SentinelAI investigations, artifacts, approvals, and health."""
from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, File, Form, HTTPException, Response, UploadFile
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from agent.orchestrator import InvestigationOrchestrator
from api.store import GLOBAL_STORE
from contracts.enums import ErrorCodePrefix, InvestigationStatus, PolicyAction, Role
from contracts.models import ProblemDetail, ToolCallProposal
from gateway.executor import ToolGateway
from policy.context import PolicyContext
from sentinel_config.validate import compute_config_hash

router = APIRouter()
orchestrator = InvestigationOrchestrator()
gateway = ToolGateway(audit_writer=GLOBAL_STORE.audit_writer)

PERMITTED_ARTIFACTS: set[str] = {
    "response_report.md",
    "suggested_changes.md",
    "agent_prompt.md",
    "findings.json",
    "response_plan.md",
}


class ApprovalRequest(BaseModel):
    """Payload for operator approval or rejection of a pending tool action."""

    decision: str = Field(pattern=r"^(approved|rejected)$")
    reason: str = Field(min_length=1, max_length=500, default="Operator reviewed action")
    operator: str = Field(min_length=1, max_length=128, default="human_operator")


class KillSwitchRequest(BaseModel):
    """Payload to engage or disengage the central execution kill switch."""

    active: bool
    operator: str = Field(min_length=1, max_length=128, default="admin")


def _raise_problem(status_code: int, code: ErrorCodePrefix | str, title: str, detail: str) -> None:
    """Raise RFC 7807 compliant ProblemDetail exception."""
    code_str = code.value if isinstance(code, ErrorCodePrefix) else code
    problem = ProblemDetail(
        type=f"https://sentinel.ai/errors/{code_str.lower()}",
        title=title,
        status=status_code,
        code=code_str,
        detail_template=detail,
        next_step_template="Inspect request parameters or verify server policy status.",
    )
    raise HTTPException(status_code=status_code, detail=problem.model_dump())


@router.get("/health")
async def health_check() -> dict[str, Any]:
    """Backend readiness and health status."""
    demo_mode = os.getenv("LLM_BACKEND", "mock").lower() == "mock" or not os.getenv("MISTRAL_API_KEY")
    return {
        "status": "healthy",
        "service": "SentinelAI Investigation Engine",
        "version": "0.1.0",
        "config_sha256": compute_config_hash(),
        "demo_mode": demo_mode,
        "kill_switch_active": GLOBAL_STORE.kill_switch_active,
        "active_investigations": len(GLOBAL_STORE.list_all()),
    }


@router.post("/api/v1/investigations")
async def create_investigation(
    file: UploadFile = File(...),
    force_approval: bool = Form(False),
) -> dict[str, Any]:
    """Upload log evidence and execute safety-governed investigation."""
    if GLOBAL_STORE.kill_switch_active:
        _raise_problem(
            503,
            ErrorCodePrefix.POLICY + "KILL_SWITCH_ACTIVE",
            "Execution Halted by Kill Switch",
            "System execution halted by operator kill switch.",
        )

    filename = file.filename or "uploaded.log"
    content = await file.read()

    try:
        record = orchestrator.run_investigation(
            file_content=content,
            filename=filename,
            investigator="local_operator",
            force_approval_scenario=force_approval,
        )
    except ValueError as val_err:
        _raise_problem(
            400,
            ErrorCodePrefix.VAL + "INVALID_EVIDENCE",
            "Evidence Ingestion Error",
            str(val_err),
        )
    except Exception as exc:
        _raise_problem(
            500,
            ErrorCodePrefix.SYS + "INTERNAL_ERROR",
            "Investigation Failure",
            f"Failed to process investigation: {exc}",
        )

    # Save to store and append audit record
    GLOBAL_STORE.save(record)
    await GLOBAL_STORE.audit_writer.append(
        event_type="investigation_created",
        actor="local_operator",
        action="ingest_and_analyze",
        payload={
            "investigation_id": str(record.investigation.id),
            "filename": filename,
            "bytes": record.envelope.raw_bytes,
            "severity": record.llm_analysis.proposed_severity.value,
            "policy_outcome": record.policy_outcome,
        },
        investigation_id=str(record.investigation.id),
    )

    return _serialize_record(record)


@router.get("/api/v1/investigations/{investigation_id}")
async def get_investigation(investigation_id: str) -> dict[str, Any]:
    """Retrieve full structured results for an investigation."""
    record = GLOBAL_STORE.get(investigation_id)
    if not record:
        _raise_problem(
            404,
            ErrorCodePrefix.VAL + "NOT_FOUND",
            "Investigation Not Found",
            f"No investigation exists with ID '{investigation_id}'.",
        )
        return {}  # Unreachable

    return _serialize_record(record)


@router.get("/api/v1/investigations/{investigation_id}/artifacts/{artifact_name:path}")
async def get_investigation_artifact(
    investigation_id: str,
    artifact_name: str,
) -> Response:
    """Download an authorized response artifact (path traversal strictly blocked)."""
    if ".." in artifact_name or "/" in artifact_name or "\\" in artifact_name:
        _raise_problem(
            400,
            ErrorCodePrefix.POLICY + "PARAM_TRAVERSAL",
            "Invalid Artifact Name",
            "Path traversal patterns detected in artifact request.",
        )

    if artifact_name not in PERMITTED_ARTIFACTS:
        _raise_problem(
            400,
            ErrorCodePrefix.POLICY + "FORBIDDEN_ARTIFACT",
            "Unauthorized Artifact",
            f"Artifact '{artifact_name}' is not in the permitted artifact catalog.",
        )

    record = GLOBAL_STORE.get(investigation_id)
    if not record:
        _raise_problem(
            404,
            ErrorCodePrefix.VAL + "NOT_FOUND",
            "Investigation Not Found",
            f"No investigation exists with ID '{investigation_id}'.",
        )
        return Response(status_code=404)

    content = record.artifacts.get(artifact_name)
    if content is None:
        _raise_problem(
            404,
            ErrorCodePrefix.VAL + "NOT_FOUND",
            "Artifact Not Available",
            f"Artifact '{artifact_name}' was not generated for this investigation.",
        )
        return Response(status_code=404)

    media_type = "application/json" if artifact_name.endswith(".json") else "text/markdown; charset=utf-8"
    return PlainTextResponse(content=content, media_type=media_type)


@router.post("/api/v1/investigations/{investigation_id}/approval")
async def handle_approval(
    investigation_id: str,
    body: ApprovalRequest,
) -> dict[str, Any]:
    """Record an operator approval or rejection and execute lab action if authorized."""
    record = GLOBAL_STORE.get(investigation_id)
    if not record:
        _raise_problem(
            404,
            ErrorCodePrefix.VAL + "NOT_FOUND",
            "Investigation Not Found",
            f"No investigation exists with ID '{investigation_id}'.",
        )
        return {}

    if not record.approval_required or not record.approval_action_detail:
        _raise_problem(
            400,
            ErrorCodePrefix.POLICY + "NO_APPROVAL_PENDING",
            "No Action Pending Approval",
            "This investigation does not have any actions awaiting operator approval.",
        )
        return {}

    proposal_id_str = record.approval_action_detail.get("proposal_id", "")
    tool_id = record.approval_action_detail.get("tool_id", "")
    params = record.approval_action_detail.get("params", {})

    # Audit the operator decision
    await GLOBAL_STORE.audit_writer.append(
        event_type="human_approval_decision",
        actor=body.operator,
        action=body.decision,
        payload={
            "investigation_id": investigation_id,
            "proposal_id": proposal_id_str,
            "tool_id": tool_id,
            "reason": body.reason,
        },
        investigation_id=investigation_id,
    )

    if body.decision == "rejected":
        updated_detail = {**record.approval_action_detail, "status": "rejected", "operator_reason": body.reason}
        updated_record = record.model_copy(
            update={
                "approval_action_detail": updated_detail,
                "policy_outcome": "denied_by_operator",
                "action_risk_summary": "Proposed action explicitly rejected by human operator.",
            }
        )
        GLOBAL_STORE.save(updated_record)
        return {
            "status": "rejected",
            "message": "Action rejected by operator. No tools executed.",
            "investigation_id": investigation_id,
        }

    # If APPROVED: re-evaluate through Tool Gateway with operator role
    proposal = ToolCallProposal(
        id=record.findings[0].id if not proposal_id_str else record.tool_proposals[-1].id,
        investigation_id=record.investigation.id,
        tool_id=tool_id,
        params=params,
        reasoning=body.reason,
    )

    context = PolicyContext(
        investigation_id=record.investigation.id,
        caller_role=Role.OPERATOR,
        kill_switch_active=GLOBAL_STORE.kill_switch_active,
        approved_calls={proposal.id},
    )

    events_dicts = [e.model_dump() for e in record.events]
    decision, envelope = await gateway.execute_tool(proposal, context, events=events_dicts)

    execution_msg = envelope.content if envelope else "Execution blocked by policy engine."
    updated_detail = {
        **record.approval_action_detail,
        "status": "approved",
        "policy_decision": decision.action.value,
        "execution_output": execution_msg,
    }

    updated_inv = record.investigation.model_copy(update={"status": InvestigationStatus.CONCLUDED})
    updated_record = record.model_copy(
        update={
            "investigation": updated_inv,
            "approval_action_detail": updated_detail,
            "policy_outcome": "allow" if decision.action == PolicyAction.ALLOW else "denied",
            "action_risk_summary": f"Approved lab action completed via Tool Gateway: {decision.action.value}",
        }
    )
    GLOBAL_STORE.save(updated_record)

    return {
        "status": "approved",
        "policy_decision": decision.action.value,
        "execution_result": execution_msg,
        "investigation_id": investigation_id,
    }


@router.post("/api/v1/kill-switch")
async def toggle_kill_switch(body: KillSwitchRequest) -> dict[str, Any]:
    """Operator toggle for global execution kill switch."""
    GLOBAL_STORE.set_kill_switch(body.active)
    await GLOBAL_STORE.audit_writer.append(
        event_type="kill_switch_toggled",
        actor=body.operator,
        action="engage" if body.active else "disengage",
        payload={"kill_switch_active": body.active},
    )
    return {
        "kill_switch_active": body.active,
        "message": f"Kill switch {'engaged (all executions blocked)' if body.active else 'disengaged (normal policy operation)'}.",
    }


def _serialize_record(record: Any) -> dict[str, Any]:
    """Format an InvestigationRecord for the API contract."""
    return {
        "investigation_id": str(record.investigation.id),
        "title": record.investigation.title,
        "status": record.investigation.status.value,
        "created_at": record.investigation.created_at.isoformat(),
        "created_by": record.investigation.created_by,
        "filename": record.filename,
        "file_bytes": record.envelope.raw_bytes,
        "is_demo_mode": record.llm_analysis.is_demo_mode,
        "model_name": record.llm_analysis.model_name,
        "proposed_severity": record.llm_analysis.proposed_severity.value,
        "severity_rationale": record.llm_analysis.severity_rationale,
        "executive_summary": record.llm_analysis.executive_summary,
        "policy_outcome": record.policy_outcome,
        "action_risk_summary": record.action_risk_summary,
        "suspected_injection": record.envelope.suspected_injection,
        "findings_count": len(record.findings),
        "findings": [
            {
                "id": str(f.id),
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value,
                "evidence_ids": [str(eid) for eid in f.evidence_ids],
                "attack_technique_id": f.attack_technique_id,
                "cwe_id": f.cwe_id,
                "created_at": f.created_at.isoformat(),
            }
            for f in record.findings
        ],
        "events_count": len(record.events),
        "events_sample": [
            {
                "line_number": e.line_number,
                "timestamp": e.timestamp.isoformat(),
                "source": e.source,
                "event_type": e.event_type,
                "raw_line": e.raw_line[:150],
            }
            for e in record.events[:25]
        ],
        "candidate_indicators": record.summary.candidate_indicators,
        "unique_sources": record.summary.unique_sources,
        "unique_ips": record.summary.unique_ips,
        "unique_users": record.summary.unique_users,
        "unique_hosts": record.summary.unique_hosts,
        "uncertainties": record.llm_analysis.uncertainties,
        "defensive_actions": record.llm_analysis.recommended_defensive_actions,
        "approval_required": record.approval_required,
        "approval_action_detail": record.approval_action_detail,
        "available_artifacts": sorted(record.artifacts.keys()),
    }
