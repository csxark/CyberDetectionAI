"""Canonical Pydantic v2 data models for SentinelAI contracts."""
from __future__ import annotations

import uuid  # noqa: TCH003
from datetime import UTC, datetime
from typing import Any

import uuid6
from pydantic import BaseModel, ConfigDict, Field, field_validator

from contracts.enums import (
    ErrorCodePrefix,
    InvestigationStatus,
    PolicyAction,
    Severity,
    SSEEventType,
    TrustLevel,
)


def _validate_utc_datetime(v: datetime) -> datetime:
    """Ensure datetime is timezone-aware and set to UTC."""
    if v.tzinfo is None or v.utcoffset() != UTC.utcoffset(v):
        msg = "Timestamp must be timezone-aware UTC."
        raise ValueError(msg)
    return v


# ---------------------------------------------------------------------------
# Investigation & Evidence
# ---------------------------------------------------------------------------

class Investigation(BaseModel):
    """Investigation lifecycle object."""

    model_config = ConfigDict(frozen=True)

    id: uuid.UUID = Field(default_factory=uuid6.uuid7)
    title: str = Field(min_length=1, max_length=256)
    status: InvestigationStatus = InvestigationStatus.ACTIVE
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    created_by: str = Field(min_length=1, max_length=128)

    @field_validator("created_at", "updated_at")
    @classmethod
    def _check_utc(cls, v: datetime) -> datetime:
        return _validate_utc_datetime(v)


class EvidenceEnvelope(BaseModel):
    """Encapsulates raw evidence or tool output with trust boundary."""

    model_config = ConfigDict(frozen=True)

    id: uuid.UUID = Field(default_factory=uuid6.uuid7)
    boundary: str = Field(min_length=8, max_length=128)
    trust: TrustLevel = TrustLevel.UNTRUSTED
    raw_bytes: int = Field(ge=0, le=52_428_800)
    format: str = Field(min_length=1, max_length=64)
    content: str = Field(max_length=10_000_000)
    suspected_injection: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("created_at")
    @classmethod
    def _check_utc(cls, v: datetime) -> datetime:
        return _validate_utc_datetime(v)


# ---------------------------------------------------------------------------
# Findings & Remediation Proposals
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    """Investigation finding verified against code facts."""

    model_config = ConfigDict(frozen=True)

    id: uuid.UUID = Field(default_factory=uuid6.uuid7)
    investigation_id: uuid.UUID
    title: str = Field(min_length=1, max_length=256)
    description: str = Field(min_length=1, max_length=4096)
    severity: Severity = Severity.MEDIUM
    evidence_ids: list[uuid.UUID] = Field(default_factory=list)
    attack_technique_id: str | None = Field(default=None, pattern=r"^T\d{4}(\.\d{3})?$")
    cwe_id: str | None = Field(default=None, pattern=r"^CWE-\d+$")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("created_at")
    @classmethod
    def _check_utc(cls, v: datetime) -> datetime:
        return _validate_utc_datetime(v)


class RemediationProposal(BaseModel):
    """Remediation proposal generated for analyst review.

    INV-14: Remediation proposals are never applied automatically by the agent.
    The applied attribute MUST be False.
    """

    model_config = ConfigDict(frozen=True)

    id: uuid.UUID = Field(default_factory=uuid6.uuid7)
    investigation_id: uuid.UUID
    description: str = Field(min_length=1, max_length=2048)
    diff_content: str = Field(min_length=1, max_length=500_000)
    applied: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("applied")
    @classmethod
    def _forbid_applied(cls, v: bool) -> bool:
        if v:
            msg = "applied must be False. The agent cannot apply remediation proposals (INV-14)."
            raise ValueError(msg)
        return v

    @field_validator("created_at")
    @classmethod
    def _check_utc(cls, v: datetime) -> datetime:
        return _validate_utc_datetime(v)


# ---------------------------------------------------------------------------
# Tool Execution & Policy Decisions
# ---------------------------------------------------------------------------

class ToolCallProposal(BaseModel):
    """Agent proposal to execute a tool, pending policy evaluation."""

    model_config = ConfigDict(frozen=True)

    id: uuid.UUID = Field(default_factory=uuid6.uuid7)
    investigation_id: uuid.UUID
    tool_id: str = Field(min_length=1, max_length=64)
    params: dict[str, Any] = Field(default_factory=dict)
    reasoning: str = Field(min_length=1, max_length=2048)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("created_at")
    @classmethod
    def _check_utc(cls, v: datetime) -> datetime:
        return _validate_utc_datetime(v)


class PolicyDecision(BaseModel):
    """Result of policy evaluation for a proposed tool call."""

    model_config = ConfigDict(frozen=True)

    id: uuid.UUID = Field(default_factory=uuid6.uuid7)
    call_id: uuid.UUID
    action: PolicyAction
    reason_code: str = Field(min_length=1, max_length=64)
    explanation_template: str = Field(min_length=1, max_length=1024)
    controls: dict[str, Any] = Field(default_factory=dict)
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("evaluated_at")
    @classmethod
    def _check_utc(cls, v: datetime) -> datetime:
        return _validate_utc_datetime(v)


# ---------------------------------------------------------------------------
# Audit Entry
# ---------------------------------------------------------------------------

class AuditEntry(BaseModel):
    """Immutable hash-chained entry in the audit trail."""

    model_config = ConfigDict(frozen=True)

    sequence: int = Field(ge=1)
    event_type: str = Field(min_length=1, max_length=64)
    investigation_id: uuid.UUID | None = None
    actor: str = Field(min_length=1, max_length=128)
    action: str = Field(min_length=1, max_length=128)
    payload: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str = Field(min_length=64, max_length=64)
    hash: str = Field(min_length=64, max_length=64)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("timestamp")
    @classmethod
    def _check_utc(cls, v: datetime) -> datetime:
        return _validate_utc_datetime(v)


# ---------------------------------------------------------------------------
# Errors (RFC 7807 problem+json) & SSE Streaming
# ---------------------------------------------------------------------------

FORBIDDEN_ERROR_KEYWORDS: tuple[str, ...] = (
    "traceback",
    "stack trace",
    "file \"",
    "line ",
    "select ",
    "insert into",
    "password",
    "secret",
    "bearer ",
)


class ProblemDetail(BaseModel):
    """RFC 7807 Problem Details object with template fields and strict sanitization."""

    model_config = ConfigDict(frozen=True)

    type: str = Field(min_length=1, max_length=256)
    title: str = Field(min_length=1, max_length=128)
    status: int = Field(ge=400, le=599)
    code: str = Field(min_length=4, max_length=64)
    detail_template: str = Field(min_length=1, max_length=1024)
    next_step_template: str = Field(min_length=1, max_length=512)
    instance: str | None = Field(default=None, max_length=256)

    @field_validator("code")
    @classmethod
    def _check_prefix(cls, v: str) -> str:
        valid_prefixes = tuple(p.value for p in ErrorCodePrefix)
        if not any(v.startswith(prefix) for prefix in valid_prefixes):
            msg = f"Invalid error code prefix in '{v}'. Must start with one of: {valid_prefixes}"
            raise ValueError(msg)
        return v

    @field_validator("detail_template", "next_step_template")
    @classmethod
    def _forbid_sensitive_leaks(cls, v: str) -> str:
        lower_v = v.lower()
        for kw in FORBIDDEN_ERROR_KEYWORDS:
            if kw in lower_v:
                msg = f"detail/next_step template contains forbidden keywords: '{kw}'"
                raise ValueError(msg)
        return v


class SSEEvent(BaseModel):
    """Server-Sent Event formatted for stream delivery to frontend console."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(min_length=1, max_length=64)
    event: SSEEventType
    data: dict[str, Any] = Field(default_factory=dict)
    retry: int = Field(default=15000, ge=1000, le=60000)
