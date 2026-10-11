"""Tests for SentinelAI Pydantic contracts and invariants."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
import uuid6
from pydantic import ValidationError

from contracts.enums import (
    PolicyAction,
    Severity,
    SSEEventType,
    TrustLevel,
)
from contracts.models import (
    EvidenceEnvelope,
    Finding,
    PolicyDecision,
    ProblemDetail,
    RemediationProposal,
    SSEEvent,
    ToolCallProposal,
)


class TestContractsInvariants:
    """Test safety invariants embedded in data models."""

    def test_remediation_proposal_applied_must_be_false(self) -> None:
        """INV-14: Remediation proposals are never applied by the agent (applied=False)."""
        inv_id = uuid6.uuid7()
        # Valid when applied=False
        proposal = RemediationProposal(
            id=uuid6.uuid7(),
            investigation_id=inv_id,
            description="Proposed patch for CVE-2024-0001",
            diff_content="--- a/fix.py\n+++ b/fix.py\n@@ -1 +1 @@\n-vulnerable\n+patched",
            applied=False,
            created_at=datetime.now(UTC),
        )
        assert proposal.applied is False

        # Attempting applied=True must raise ValidationError
        with pytest.raises(ValidationError, match="applied must be False"):
            RemediationProposal(
                id=uuid6.uuid7(),
                investigation_id=inv_id,
                description="Malicious auto-apply patch",
                diff_content="diff",
                applied=True,
                created_at=datetime.now(UTC),
            )

    def test_evidence_envelope_untrusted_by_default(self) -> None:
        """Raw evidence and tool outputs must default to trust='untrusted' (INV-7)."""
        env = EvidenceEnvelope(
            id=uuid6.uuid7(),
            boundary="boundary-token-12345",
            raw_bytes=1024,
            format="syslog",
            content="sample log",
            created_at=datetime.now(UTC),
        )
        assert env.trust == TrustLevel.UNTRUSTED

    def test_datetime_must_be_timezone_aware_utc(self) -> None:
        """All timestamps in contracts must be UTC and timezone-aware."""
        # Naive datetime should be rejected
        with pytest.raises(ValidationError, match="timezone-aware UTC"):
            Finding(
                id=uuid6.uuid7(),
                investigation_id=uuid6.uuid7(),
                title="Unauthorized Access",
                description="Repeated failed logins detected",
                severity=Severity.HIGH,
                evidence_ids=[uuid6.uuid7()],
                created_at=datetime.now(),  # naive  # noqa: DTZ005
            )

    def test_problem_detail_error_code_prefix(self) -> None:
        """Error codes must strictly adhere to prefix taxonomy."""
        # Valid code with POLICY_ prefix
        prob = ProblemDetail(
            type="https://api.sentinel.security/errors/policy-denied",
            title="Policy Denied",
            status=403,
            code="POLICY_TARGET_OUT_OF_SCOPE",
            detail_template="Access to target is outside permitted investigation scope.",
            next_step_template="Verify target parameters or request scope escalation.",
        )
        assert prob.code.startswith("POLICY_")

        # Invalid prefix should raise ValidationError
        with pytest.raises(ValidationError, match="Invalid error code prefix"):
            ProblemDetail(
                type="https://api.sentinel.security/errors/bad",
                title="Bad Error",
                status=400,
                code="RANDOM_ERROR",
                detail_template="Detail",
                next_step_template="Next",
            )

    def test_problem_detail_forbids_sensitive_leakage(self) -> None:
        """Problem details templates must never leak stack traces or raw model names."""
        with pytest.raises(ValidationError, match="forbidden keywords"):
            ProblemDetail(
                type="https://api.sentinel.security/errors/internal",
                title="Internal Error",
                status=500,
                code="SYS_INTERNAL_ERROR",
                detail_template="Traceback (most recent call last): File app.py line 42",
                next_step_template="Retry later.",
            )

    def test_tool_call_proposal_requires_investigation_id(self) -> None:
        call = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=uuid6.uuid7(),
            tool_id="search_events",
            params={"limit": 50},
            reasoning="Checking for SSH brute force pattern",
            created_at=datetime.now(UTC),
        )
        assert call.tool_id == "search_events"

    def test_policy_decision_model(self) -> None:
        dec = PolicyDecision(
            id=uuid6.uuid7(),
            call_id=uuid6.uuid7(),
            action=PolicyAction.ALLOW,
            reason_code="POLICY_ALLOW_READ_ONLY",
            explanation_template="Read-only operation allowed within configured limits.",
            controls={"timeout_seconds": 30, "max_output_bytes": 65536},
            evaluated_at=datetime.now(UTC),
        )
        assert dec.action == PolicyAction.ALLOW

    def test_sse_event_serialization(self) -> None:
        event = SSEEvent(
            id="evt-12345",
            event=SSEEventType.FINDING,
            data={"finding_id": str(uuid6.uuid7()), "title": "Suspicious login"},
        )
        assert event.event == SSEEventType.FINDING
        assert event.retry == 15000
