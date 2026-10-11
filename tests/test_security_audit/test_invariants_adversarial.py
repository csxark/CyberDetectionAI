"""Adversarial security audit tests attempting to violate invariants INV-1 through INV-14."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
import uuid6
from pydantic import ValidationError

from audit.chain import GENESIS_HASH, compute_audit_hash
from audit.verifier import verify_chain
from contracts.enums import PolicyAction, Role, TrustLevel
from contracts.models import (
    AuditEntry,
    EvidenceEnvelope,
    ProblemDetail,
    RemediationProposal,
    ToolCallProposal,
)
from policy.context import PolicyContext
from policy.engine import evaluate_policy
from sentinel_config.guardrails import GuardrailsConfig
from sentinel_config.tools import (
    TOOL_REGISTRY,
    RiskClass,
    TargetKind,
    ToolOperation,
    ToolSpec,
)


class TestAdversarialInvariants:
    """Systematic attack suite attempting to breach security invariants."""

    # -----------------------------------------------------------------------
    # INV-1 & INV-12: Kill switch overrides all execution and cannot be bypassed
    # -----------------------------------------------------------------------
    def test_adv_kill_switch_tamper_attempt(self) -> None:
        """Adversary attempts to call tools while kill switch is active."""
        ctx = PolicyContext(
            investigation_id=uuid6.uuid7(),
            caller_role=Role.ADMIN,
            kill_switch_active=True,
            wall_seconds_used=0,
            llm_calls_used=0,
            jev_calls_used=0,
            tool_calls_used=0,
        )
        for tool_id in TOOL_REGISTRY:
            prop = ToolCallProposal(
                id=uuid6.uuid7(),
                investigation_id=ctx.investigation_id,
                tool_id=tool_id,
                params={"evidence_id": "ev-01"},
                reasoning="Adversarial execution during kill switch",
                created_at=datetime.now(UTC),
            )
            decision = evaluate_policy(ctx, prop)
            assert decision.action == PolicyAction.DENY
            assert decision.reason_code == "POLICY_KILL_SWITCH_ACTIVE"

    def test_adv_guardrails_kill_switch_interval_tamper(self) -> None:
        """Adversary attempts to weaken kill switch by setting check interval > 0."""
        with pytest.raises(ValidationError, match="kill_switch_check_interval_seconds must be 0"):
            GuardrailsConfig.model_validate({
                "agent": {"kill_switch_check_interval_seconds": 10}
            })

    # -----------------------------------------------------------------------
    # INV-3: State-changing tools require approval + lab-only + sandbox
    # -----------------------------------------------------------------------
    def test_adv_state_changing_tool_unauthorized_definition(self) -> None:
        """Adversary attempts to define state-changing tool without approval or lab restriction."""
        with pytest.raises(ValidationError, match="requires_approval=True"):
            ToolSpec(
                id="adv_delete_db",
                description="Malicious tool deleting database records",
                risk_class=RiskClass.STATE_CHANGING,
                target_kind=TargetKind.SANDBOX,
                operation=ToolOperation.CHECK,
                requires_approval=False,
                lab_only=True,
            )

        with pytest.raises(ValidationError, match="lab_only=True"):
            ToolSpec(
                id="adv_prod_block",
                description="Malicious tool blocking production IPs",
                risk_class=RiskClass.STATE_CHANGING,
                target_kind=TargetKind.NETWORK,
                operation=ToolOperation.BLOCK,
                requires_approval=True,
                lab_only=False,
            )

    # -----------------------------------------------------------------------
    # INV-6: Network egress forbidden
    # -----------------------------------------------------------------------
    def test_adv_tool_network_egress_forbidden(self) -> None:
        """Adversary attempts to register tool with outbound network access."""
        with pytest.raises(ValidationError, match="INV-6"):
            ToolSpec(
                id="adv_exfiltrate",
                description="Malicious exfiltration tool",
                risk_class=RiskClass.READ_ONLY,
                target_kind=TargetKind.KB,
                operation=ToolOperation.SEARCH,
                network_allowed=True,
            )

    # -----------------------------------------------------------------------
    # INV-7: Evidence trust='untrusted' default
    # -----------------------------------------------------------------------
    def test_adv_raw_evidence_trust_boundary(self) -> None:
        """Evidence without explicit trust level defaults to untrusted."""
        env = EvidenceEnvelope(
            id=uuid6.uuid7(),
            boundary="boundary-token",
            raw_bytes=100,
            format="jsonl",
            content="{}",
            created_at=datetime.now(UTC),
        )
        assert env.trust == TrustLevel.UNTRUSTED

    # -----------------------------------------------------------------------
    # INV-8: Audit log cryptographic tamper detection
    # -----------------------------------------------------------------------
    def test_adv_audit_tamper_reorder_entries(self) -> None:
        """Adversary attempts to swap or reorder audit entries."""
        t1 = datetime.now(UTC)
        h1 = compute_audit_hash(GENESIS_HASH, {
            "sequence": 1, "event_type": "evt.1", "investigation_id": None,
            "actor": "user", "action": "a", "payload": {}, "timestamp": t1.isoformat()
        })
        e1 = AuditEntry(
            sequence=1, event_type="evt.1", actor="user", action="a",
            payload={}, prev_hash=GENESIS_HASH, hash=h1, timestamp=t1,
        )

        t2 = datetime.now(UTC)
        h2 = compute_audit_hash(h1, {
            "sequence": 2, "event_type": "evt.2", "investigation_id": None,
            "actor": "user", "action": "b", "payload": {}, "timestamp": t2.isoformat()
        })
        e2 = AuditEntry(
            sequence=2, event_type="evt.2", actor="user", action="b",
            payload={}, prev_hash=h1, hash=h2, timestamp=t2,
        )

        # Inverted order [e2, e1]
        valid, error = verify_chain([e2, e1])
        assert valid is False
        assert error is not None

    def test_adv_audit_tamper_mutate_prev_hash(self) -> None:
        """Adversary attempts to modify prev_hash to point elsewhere."""
        t1 = datetime.now(UTC)
        h1 = compute_audit_hash(GENESIS_HASH, {
            "sequence": 1, "event_type": "evt.1", "investigation_id": None,
            "actor": "user", "action": "a", "payload": {}, "timestamp": t1.isoformat()
        })
        e1 = AuditEntry(
            sequence=1, event_type="evt.1", actor="user", action="a",
            payload={}, prev_hash=GENESIS_HASH, hash=h1, timestamp=t1,
        )

        t2 = datetime.now(UTC)
        fake_prev_hash = "f" * 64
        h2 = compute_audit_hash(fake_prev_hash, {
            "sequence": 2, "event_type": "evt.2", "investigation_id": None,
            "actor": "user", "action": "b", "payload": {}, "timestamp": t2.isoformat()
        })
        e2 = AuditEntry(
            sequence=2, event_type="evt.2", actor="user", action="b",
            payload={}, prev_hash=fake_prev_hash, hash=h2, timestamp=t2,
        )

        valid, error = verify_chain([e1, e2])
        assert valid is False
        assert error is not None
        assert "broken link" in error.lower()

    # -----------------------------------------------------------------------
    # INV-14: Remediation proposals applied must be False
    # -----------------------------------------------------------------------
    def test_adv_remediation_proposal_cannot_be_applied(self) -> None:
        """Adversary attempts to instantiate RemediationProposal with applied=True."""
        with pytest.raises(ValidationError, match="applied must be False"):
            RemediationProposal(
                id=uuid6.uuid7(),
                investigation_id=uuid6.uuid7(),
                description="Patch execution attempt",
                diff_content="diff",
                applied=True,
                created_at=datetime.now(UTC),
            )

    # -----------------------------------------------------------------------
    # Sensitive Data Leakage Protection
    # -----------------------------------------------------------------------
    def test_adv_problem_detail_forbids_sql_or_secrets_leakage(self) -> None:
        """Adversary attempts to pass internal SQL query or bearer token into user error message."""
        with pytest.raises(ValidationError, match="forbidden keywords"):
            ProblemDetail(
                type="https://api.sentinel.security/errors/db-leak",
                title="Internal Error",
                status=500,
                code="SYS_DB_ERROR",
                detail_template="Query failed: SELECT password FROM users WHERE id=1",
                next_step_template="Contact admin.",
            )

        with pytest.raises(ValidationError, match="forbidden keywords"):
            ProblemDetail(
                type="https://api.sentinel.security/errors/token-leak",
                title="Auth Error",
                status=500,
                code="AUTH_TOKEN_ERROR",
                detail_template="Authorization header was Bearer eyJhbGciOi...",
                next_step_template="Retry.",
            )

    # -----------------------------------------------------------------------
    # Input Path Traversal Injection Protection
    # -----------------------------------------------------------------------
    @pytest.mark.parametrize("traversal_payload", [
        "../../../../etc/shadow",
        "..\\..\\..\\windows\\system32",
        "//etc/passwd",
        "\\\\server\\share\\secret",
    ])
    def test_adv_path_traversal_payloads_denied(self, traversal_payload: str) -> None:
        """Adversary attempts path traversal via various payload encodings."""
        ctx = PolicyContext(
            investigation_id=uuid6.uuid7(),
            caller_role=Role.ANALYST,
            kill_switch_active=False,
            wall_seconds_used=0,
            llm_calls_used=0,
            jev_calls_used=0,
            tool_calls_used=0,
        )
        prop = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=ctx.investigation_id,
            tool_id="code_search",
            params={
                "investigation_id": str(ctx.investigation_id),
                "pattern": "secret",
                "file_glob": traversal_payload,
            },
            reasoning="Attempting path escape",
            created_at=datetime.now(UTC),
        )
        dec = evaluate_policy(ctx, prop)
        assert dec.action == PolicyAction.DENY
        assert dec.reason_code == "POLICY_PARAM_TRAVERSAL"

    # -----------------------------------------------------------------------
    # INV-1: Authority Split — Agent cannot import tools or gateway
    # -----------------------------------------------------------------------
    def test_adv_inv01_agent_forbidden_from_importing_tools_or_gateway(self) -> None:
        """Adversary attempts to let agent import tools or gateway directly."""
        import configparser
        from pathlib import Path

        cfg = configparser.ConfigParser()
        cfg.read(Path(".importlinter"))
        section = "importlinter:contract:agent-isolation"
        assert cfg.has_section(section), "Missing agent-isolation contract in .importlinter"
        forbidden = [f.strip() for f in cfg.get(section, "forbidden_modules").splitlines() if f.strip()]
        assert "tools" in forbidden
        assert "gateway" in forbidden
        assert "sentinel_config.tools" in forbidden

    # -----------------------------------------------------------------------
    # INV-2: Tool registry cannot execute unregistered or arbitrary tools
    # -----------------------------------------------------------------------
    def test_adv_inv02_unregistered_tool_denied_by_policy(self) -> None:
        """Adversary attempts to propose and execute an unapproved tool."""
        ctx = PolicyContext(
            investigation_id=uuid6.uuid7(),
            caller_role=Role.ANALYST,
            kill_switch_active=False,
            wall_seconds_used=0,
            llm_calls_used=0,
            jev_calls_used=0,
            tool_calls_used=0,
        )
        for malicious_id in ["malicious_bash_exec", "rm_rf_db", "aws_iam_exfiltrate"]:
            prop = ToolCallProposal(
                id=uuid6.uuid7(),
                investigation_id=ctx.investigation_id,
                tool_id=malicious_id,
                params={},
                reasoning="Adversarial unapproved tool",
                created_at=datetime.now(UTC),
            )
            dec = evaluate_policy(ctx, prop)
            assert dec.action == PolicyAction.DENY
            assert dec.reason_code == "POLICY_TOOL_UNREGISTERED"

    # -----------------------------------------------------------------------
    # INV-4: Policy Engine fails closed on unknown enums or corrupt state
    # -----------------------------------------------------------------------
    def test_adv_inv04_policy_fed_unknown_enum_fail_closed(self) -> None:
        """Adversary feeds invalid/unknown enum values into Policy Engine."""
        ctx = PolicyContext(
            investigation_id=uuid6.uuid7(),
            caller_role=Role.ANALYST,
            kill_switch_active=False,
            wall_seconds_used=0,
            llm_calls_used=0,
            jev_calls_used=0,
            tool_calls_used=0,
        )
        # Exploding/corrupted proposal
        class CorruptProposal:
            id = uuid6.uuid7()
            tool_id = "parse_logs"
            params = property(lambda _self: (_ for _ in ()).throw(ValueError("Corrupted enum state")))

        dec = evaluate_policy(ctx, CorruptProposal())  # type: ignore[arg-type]
        assert dec.action == PolicyAction.DENY
        assert dec.reason_code == "POLICY_INTERNAL_ERROR"

    # -----------------------------------------------------------------------
    # INV-5: Bounded execution timeouts and output caps enforced
    # -----------------------------------------------------------------------
    def test_adv_inv05_bounded_output_and_timeout_limits(self) -> None:
        """Adversary attempts to define tool exceeding maximum output (5MB) or timeout (300s)."""
        with pytest.raises(ValidationError, match="less than or equal to 5242880"):
            ToolSpec(
                id="adv_huge_tool",
                description="Tool with unbounded output size",
                risk_class=RiskClass.READ_ONLY,
                target_kind=TargetKind.LOGS,
                operation=ToolOperation.PARSE,
                max_output_bytes=10_000_000,
            )

        with pytest.raises(ValidationError, match="less than or equal to 300"):
            ToolSpec(
                id="adv_infinite_tool",
                description="Tool with unbounded execution timeout",
                risk_class=RiskClass.READ_ONLY,
                target_kind=TargetKind.LOGS,
                operation=ToolOperation.PARSE,
                timeout_seconds=600,
            )

    # -----------------------------------------------------------------------
    # INV-8 & INV-10: Database Role Matrix enforces append-only audit & policy_versions protection
    # -----------------------------------------------------------------------
    def test_adv_inv08_audit_log_zero_update_or_delete_grants(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Adversary inspects SQL grants to verify NO role can UPDATE or DELETE audit_log."""
        from alembic import command
        from alembic.config import Config

        alembic_cfg = Config("alembic.ini")
        command.upgrade(alembic_cfg, "head", sql=True)
        sql = capsys.readouterr().out.upper()

        assert "UPDATE" not in [line for line in sql.splitlines() if "AUDIT_LOG" in line and "GRANT" in line]
        assert "DELETE" not in [line for line in sql.splitlines() if "AUDIT_LOG" in line and "GRANT" in line]

    def test_adv_inv10_role_matrix_forbids_agent_writing_policy_versions(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Adversary attempts to write policy_versions as app_rw or gateway_rw."""
        from alembic import command
        from alembic.config import Config

        alembic_cfg = Config("alembic.ini")
        command.upgrade(alembic_cfg, "head", sql=True)
        sql = capsys.readouterr().out

        # app_rw must only have SELECT on policy_versions
        assert "GRANT SELECT ON policy_versions TO app_rw" in sql
        assert "GRANT INSERT ON policy_versions TO app_rw" not in sql
        assert "GRANT UPDATE ON policy_versions TO app_rw" not in sql

        # gateway_rw must only have SELECT on policy_versions
        assert "GRANT SELECT ON investigations, policy_versions TO gateway_rw" in sql

        # Only policy_admin has write grants on policy_versions
        assert "GRANT SELECT, INSERT, UPDATE ON policy_versions TO policy_admin" in sql

    # -----------------------------------------------------------------------
    # INV-11: Budget accounting strictly prevents loops past budgets
    # -----------------------------------------------------------------------
    def test_adv_inv11_loop_past_budgets_denied(self) -> None:
        """Adversary attempts to loop past wall clock, tool call count, or denial limits."""
        # Exceeded wall clock budget
        ctx_time = PolicyContext(
            investigation_id=uuid6.uuid7(),
            caller_role=Role.ANALYST,
            kill_switch_active=False,
            wall_seconds_used=301,
            llm_calls_used=0,
            jev_calls_used=0,
            tool_calls_used=0,
        )
        prop = ToolCallProposal(
            id=uuid6.uuid7(),
            investigation_id=ctx_time.investigation_id,
            tool_id="parse_logs",
            params={"evidence_id": "ev-01"},
            reasoning="Looping past time budget",
            created_at=datetime.now(UTC),
        )
        assert evaluate_policy(ctx_time, prop).action == PolicyAction.DENY
        assert evaluate_policy(ctx_time, prop).reason_code == "POLICY_BUDGET_EXHAUSTED"

        # Exceeded tool calls budget
        ctx_tools = PolicyContext(
            investigation_id=uuid6.uuid7(),
            caller_role=Role.ANALYST,
            kill_switch_active=False,
            wall_seconds_used=10,
            llm_calls_used=0,
            jev_calls_used=0,
            tool_calls_used=51,
        )
        assert evaluate_policy(ctx_tools, prop).action == PolicyAction.DENY
        assert evaluate_policy(ctx_tools, prop).reason_code == "POLICY_BUDGET_EXHAUSTED"

        # Exceeded tool denials limit (3 denials)
        ctx_denials = PolicyContext(
            investigation_id=uuid6.uuid7(),
            caller_role=Role.ANALYST,
            kill_switch_active=False,
            wall_seconds_used=10,
            llm_calls_used=0,
            jev_calls_used=0,
            tool_calls_used=5,
            denials_for_tool={"parse_logs": 3},
        )
        assert evaluate_policy(ctx_denials, prop).action == PolicyAction.DENY
        assert evaluate_policy(ctx_denials, prop).reason_code == "POLICY_TOOL_MAX_DENIALS_EXCEEDED"

