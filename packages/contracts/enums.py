"""Canonical enums shared across all SentinelAI components."""
from __future__ import annotations

from enum import StrEnum, unique


@unique
class TrustLevel(StrEnum):
    """Trust domain for evidence and inputs. Raw evidence is always untrusted."""

    UNTRUSTED = "untrusted"
    SYSTEM = "system"
    OPERATOR = "operator"


@unique
class InvestigationStatus(StrEnum):
    """Lifecycle status of an investigation."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    CONCLUDED = "concluded"
    FAILED = "failed"


@unique
class Severity(StrEnum):
    """Severity ratings for findings."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@unique
class PolicyAction(StrEnum):
    """Policy engine evaluation result."""

    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"
    SUSPEND = "suspend"


@unique
class ApprovalStatus(StrEnum):
    """Status of a human approval request."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@unique
class Role(StrEnum):
    """Database and application authentication roles."""

    APP_RW = "app_rw"
    GATEWAY_RW = "gateway_rw"
    POLICY_ADMIN = "policy_admin"
    OPERATOR = "operator"
    EVAL_RW = "eval_rw"
    ANALYST = "analyst"
    ADMIN = "admin"


@unique
class ErrorCodePrefix(StrEnum):
    """Standard prefixes for problem+json error codes."""

    VAL = "VAL_"
    AUTH = "AUTH_"
    POLICY = "POLICY_"
    DEC = "DEC_"
    LLM = "LLM_"
    TOOL = "TOOL_"
    EVID = "EVID_"
    INTEG = "INTEG_"
    SYS = "SYS_"


@unique
class SSEEventType(StrEnum):
    """Server-Sent Events event types for frontend console streams."""

    INVESTIGATION_STATUS = "investigation_status"
    EVIDENCE_RECEIVED = "evidence_received"
    LOOK_FOR_TERMS = "look_for_terms"
    STEP_TIMELINE = "step_timeline"
    FINDING = "finding"
    POLICY_NOTICE = "policy_notice"
    APPROVAL_REQUIRED = "approval_required"
    REMEDIATION_PROPOSAL = "remediation_proposal"
    NEED_INPUT = "need_input"
    REPORT_READY = "report_ready"
    ERROR = "error"
