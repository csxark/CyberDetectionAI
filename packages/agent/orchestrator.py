"""Investigation orchestrator coordinating evidence analysis, findings synthesis, and artifact generation."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import uuid6
from pydantic import BaseModel, ConfigDict, Field

from agent.artifacts import (
    generate_agent_prompt,
    generate_findings_json,
    generate_response_plan,
    generate_response_report,
    generate_suggested_changes,
)
from contracts.enums import InvestigationStatus, Severity, ToolId
from contracts.models import (
    EvidenceEnvelope,
    Finding,
    Investigation,
    RemediationProposal,
    ToolCallProposal,
)
from decision.provider import DecisionProvider, RulesDecisionProvider
from evidence.extractor import CandidateExtractor
from evidence.models import ExtractionSummary, NormalizedEvent  # noqa: TCH001
from evidence.parser import LogParser
from llm.client import LLMClient, LLMInvestigationResponse


class InvestigationRecord(BaseModel):
    """Complete in-memory model of an active or concluded investigation."""

    model_config = ConfigDict(frozen=True)

    investigation: Investigation
    filename: str
    envelope: EvidenceEnvelope
    events: list[NormalizedEvent]
    summary: ExtractionSummary
    llm_analysis: LLMInvestigationResponse
    findings: list[Finding]
    tool_proposals: list[ToolCallProposal] = Field(default_factory=list)
    remediation_proposal: RemediationProposal | None = None
    policy_outcome: str = "allow"
    action_risk_summary: str = "Read-only analysis complete"
    approval_required: bool = False
    approval_action_detail: dict[str, Any] | None = None
    artifacts: dict[str, str] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class InvestigationOrchestrator:
    """Coordinates log analysis, finding generation, and artifact synthesis."""

    def __init__(
        self,
        parser: LogParser | None = None,
        extractor: CandidateExtractor | None = None,
        llm_client: LLMClient | None = None,
        decision_provider: DecisionProvider | None = None,
    ) -> None:
        self.parser = parser or LogParser()
        self.extractor = extractor or CandidateExtractor()
        self.llm_client = llm_client or LLMClient()
        self.decision_provider = decision_provider or RulesDecisionProvider()

    def run_investigation(
        self,
        file_content: str | bytes,
        filename: str,
        investigator: str = "local_analyst",
        force_approval_scenario: bool = False,
    ) -> InvestigationRecord:
        """Execute end-to-end investigation workflow on uploaded log evidence."""
        investigation_id = uuid6.uuid7()
        now = datetime.now(UTC)

        # 1. Parse log evidence into envelope and normalized events
        envelope, events = self.parser.parse(file_content, filename, investigation_id=investigation_id)

        # 2. Extract statistical baseline and candidate indicators
        summary = self.extractor.extract(envelope.id, events)

        # 3. Consult decision provider for tool recommendations
        decisions = self.decision_provider.recommend_actions(
            summary.candidate_indicators,
            summary.event_types,
        )

        tool_proposals: list[ToolCallProposal] = [
            ToolCallProposal(
                id=uuid6.uuid7(),
                investigation_id=investigation_id,
                tool_id=d.tool_id,
                params=d.params,
                reasoning=d.rationale,
                created_at=now,
            )
            for d in decisions
        ]

        # 4. Synthesize findings using LLM client (with local demo fallback)
        llm_resp = self.llm_client.analyze(events, summary, sigma_matches=None)

        # 5. Convert LLM findings to validated contracts.models.Finding
        findings: list[Finding] = [
            Finding(
                id=uuid6.uuid7(),
                investigation_id=investigation_id,
                title=raw_f.title,
                description=raw_f.description,
                severity=raw_f.severity,
                evidence_ids=[envelope.id],
                attack_technique_id=raw_f.attack_technique_id,
                cwe_id=raw_f.cwe_id,
                created_at=now,
            )
            for raw_f in llm_resp.findings
        ]

        # 6. Remediation proposal if supported (INV-14: applied MUST be False)
        remediation: RemediationProposal | None = None
        if llm_resp.candidate_remediation_diff:
            remediation = RemediationProposal(
                id=uuid6.uuid7(),
                investigation_id=investigation_id,
                description=llm_resp.remediation_rationale or "Defensive configuration hardening",
                diff_content=llm_resp.candidate_remediation_diff,
                applied=False,  # Enforced by INV-14
                created_at=now,
            )

        # 7. Evaluate response path: Path A (Recommendations), Path B (Approval Required), or Path C (Deny)
        artifacts: dict[str, str] = {}
        approval_required = False
        approval_detail: dict[str, Any] | None = None
        policy_outcome = "allow"
        action_risk = "Read-only analytical investigation authorized"

        # Determine if a candidate state-changing action is relevant
        target_ip = summary.unique_ips[0] if summary.unique_ips else None
        has_high_or_crit = any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)

        if (force_approval_scenario or has_high_or_crit) and target_ip:
            approval_required = True
            policy_outcome = "require_approval"
            action_risk = f"Proposed state-changing action ({ToolId.LAB_BLOCK_IP.value}) requires explicit human operator approval"

            approval_proposal = ToolCallProposal(
                id=uuid6.uuid7(),
                investigation_id=investigation_id,
                tool_id=ToolId.LAB_BLOCK_IP.value,
                params={"ip_address": target_ip, "duration_minutes": 60, "reason": "Containment for brute-force / anomalous activity"},
                reasoning=f"Block malicious traffic from {target_ip} in lab environment.",
                created_at=now,
            )
            tool_proposals.append(approval_proposal)

            approval_detail = {
                "proposal_id": str(approval_proposal.id),
                "tool_id": ToolId.LAB_BLOCK_IP.value,
                "target": target_ip,
                "params": approval_proposal.params,
                "risk_class": "state_changing",
                "lab_only": True,
                "reason": approval_proposal.reasoning,
                "evidence_rationale": f"Associated with findings: {', '.join(f.title for f in findings[:2])}",
                "status": "pending",
            }

            artifacts["response_plan.md"] = generate_response_plan(
                investigation_id=str(investigation_id),
                proposed_action=ToolId.LAB_BLOCK_IP.value,
                target_system=f"Lab Network Perimeter (Target IP: {target_ip})",
                params=approval_proposal.params,
                reason=approval_proposal.reasoning,
                supporting_evidence=[f"Finding: {f.title}" for f in findings[:3]],
                impact_risks="Blocks inbound and outbound traffic for simulated host in lab environment. Does not affect production.",
                reversibility="Reversible immediately by unblocking IP in simulator or waiting for 60-minute expiry.",
            )

        # Always generate response_report.md and findings.json
        artifacts["response_report.md"] = generate_response_report(
            investigation_id=str(investigation_id),
            created_at=now,
            filename=filename,
            file_bytes=envelope.raw_bytes,
            executive_summary=llm_resp.executive_summary,
            severity=llm_resp.proposed_severity.value,
            severity_rationale=llm_resp.severity_rationale,
            findings=findings,
            uncertainties=llm_resp.uncertainties,
            defensive_actions=llm_resp.recommended_defensive_actions,
            policy_outcome=policy_outcome,
            affected_hosts=summary.unique_hosts,
            affected_accounts=summary.unique_users,
        )

        artifacts["findings.json"] = generate_findings_json(
            investigation_id=str(investigation_id),
            severity=llm_resp.proposed_severity.value,
            executive_summary=llm_resp.executive_summary,
            findings=findings,
            uncertainties=llm_resp.uncertainties,
            defensive_actions=llm_resp.recommended_defensive_actions,
            remediation=remediation,
            policy_outcome=policy_outcome,
        )

        if llm_resp.suggested_detection_rule or llm_resp.candidate_remediation_diff:
            suggested_md = generate_suggested_changes(
                investigation_id=str(investigation_id),
                detection_rule=llm_resp.suggested_detection_rule,
                config_change=llm_resp.suggested_configuration_change,
                diff_content=llm_resp.candidate_remediation_diff,
                rationale=llm_resp.remediation_rationale,
            )
            artifacts["suggested_changes.md"] = suggested_md
            artifacts["agent_prompt.md"] = generate_agent_prompt(
                investigation_id=str(investigation_id),
                findings=findings,
                suggested_changes=suggested_md,
            )

        inv_obj = Investigation(
            id=investigation_id,
            title=f"Log Investigation: {filename}",
            status=InvestigationStatus.CONCLUDED if not approval_required else InvestigationStatus.ACTIVE,
            created_at=now,
            updated_at=now,
            created_by=investigator,
        )

        return InvestigationRecord(
            investigation=inv_obj,
            filename=filename,
            envelope=envelope,
            events=events,
            summary=summary,
            llm_analysis=llm_resp,
            findings=findings,
            tool_proposals=tool_proposals,
            remediation_proposal=remediation,
            policy_outcome=policy_outcome,
            action_risk_summary=action_risk,
            approval_required=approval_required,
            approval_action_detail=approval_detail,
            artifacts=artifacts,
            created_at=now,
        )
