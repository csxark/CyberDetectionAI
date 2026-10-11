"""Guardrails configuration — budgets, rate limits, and scope constraints.

Pure data, no side effects. The single source of truth for all budget values,
rate limits, and scope boundaries used by the Policy Engine and Gateway.

No budget, threshold, or limit value may be hard-coded outside this file
(enforced by scripts/check_no_hardcoded_tools.py).
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Budget configuration
# ---------------------------------------------------------------------------


class BudgetConfig(BaseModel, frozen=True):
    """Per-investigation budget limits.

    Budget math (worst-case per cycle):
      - 1 LLM call (reason) + 1 LLM call (fill args) + 1 LLM call (grounding repair) = 3 LLM calls
      - 1 Jev call (triage) + 1 Jev call (tool choice) + 1 Jev call (reversed re-ask) = 3 Jev calls
      - At 1 rps LLM limiter: 3 LLM calls = ~3s + network latency ~= 5s per cycle
      - wall_seconds=300 / 5s per cycle = ~60 cycles theoretical max
      - But Jev + tool execution adds time: realistic ~20-30 cycles
      - llm_calls=30 limits to 10 full cycles (3 LLM per cycle)
      - jev_calls=60 limits to 20 full cycles (3 Jev per cycle)
      - Conservative defaults: enough for thorough investigation, not infinite loops
    """

    wall_seconds: int = Field(
        default=300, ge=30, le=3600, description="Max wall-clock time per investigation"
    )
    llm_calls: int = Field(
        default=30, ge=1, le=200, description="Max LLM API calls per investigation"
    )
    jev_calls: int = Field(
        default=60, ge=1, le=200, description="Max Jev API calls per investigation"
    )
    tool_calls: int = Field(
        default=50, ge=1, le=200, description="Max tool executions per investigation"
    )
    total_input_tokens: int = Field(
        default=500_000, ge=1000, le=10_000_000, description="Max input tokens to LLM"
    )
    total_output_tokens: int = Field(
        default=100_000, ge=1000, le=2_000_000, description="Max output tokens from LLM"
    )


# ---------------------------------------------------------------------------
# Rate limiter configuration
# ---------------------------------------------------------------------------


class RateLimitConfig(BaseModel, frozen=True):
    """Token-bucket rate limiter for LLM and Jev APIs.

    Queue wait time counts toward wall_seconds budget.
    """

    llm_requests_per_second: float = Field(
        default=1.0, ge=0.1, le=100.0, description="LLM API rate limit (token bucket)"
    )
    llm_burst_size: int = Field(default=2, ge=1, le=20, description="LLM burst capacity")
    jev_requests_per_second: float = Field(
        default=2.0, ge=0.1, le=100.0, description="Jev API rate limit"
    )
    jev_burst_size: int = Field(default=3, ge=1, le=20, description="Jev burst capacity")
    retry_429_max_wait_seconds: int = Field(
        default=30, ge=1, le=120, description="Max wait on 429 before failing"
    )
    retry_429_jitter_seconds: float = Field(
        default=1.0, ge=0.0, le=5.0, description="Jitter range for 429 backoff"
    )


# ---------------------------------------------------------------------------
# Scope configuration
# ---------------------------------------------------------------------------


class ScopeConfig(BaseModel, frozen=True):
    """Investigation scope boundaries enforced by the Policy Engine."""

    max_evidence_bytes: int = Field(
        default=5_242_880, ge=1024, le=52_428_800, description="Max upload size (5 MB default)"
    )
    decompression_ratio_limit: int = Field(
        default=10, ge=2, le=100, description="Max decompression ratio to prevent zip bombs"
    )
    max_events_per_evidence: int = Field(
        default=100_000, ge=100, le=10_000_000, description="Max parsed events per evidence file"
    )
    max_findings_per_investigation: int = Field(
        default=200, ge=1, le=1000, description="Max findings before forced conclusion"
    )
    max_candidates_per_extraction: int = Field(
        default=5000, ge=10, le=100_000, description="Max candidate indicators per extraction"
    )
    max_look_for_terms: int = Field(
        default=50, ge=1, le=200, description="Max look-for terms per investigation"
    )


# ---------------------------------------------------------------------------
# Agent behavior guardrails
# ---------------------------------------------------------------------------


class AgentGuardrails(BaseModel, frozen=True):
    """Agent behavior constraints enforced at graph edges."""

    no_progress_max_cycles: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Max cycles with no new findings before forced conclusion",
    )
    repeat_call_skip: bool = Field(
        default=True, description="Skip duplicate tool calls with same args"
    )
    denials_per_tool_max: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Max policy denials per tool before stopping requests for it",
    )
    approval_expiry_seconds: int = Field(
        default=900, ge=60, le=3600, description="Human approval timeout (15 min default)"
    )
    kill_switch_check_interval_seconds: int = Field(
        default=0, ge=0, le=60, description="0 = check every edge (required by invariants)"
    )

    @field_validator("kill_switch_check_interval_seconds")
    @classmethod
    def _must_check_every_edge(cls, v: int) -> int:
        """Kill switch must be checked on every edge (INV-12)."""
        if v != 0:
            msg = "kill_switch_check_interval_seconds must be 0 (check every edge, INV-12)"
            raise ValueError(msg)
        return v


# ---------------------------------------------------------------------------
# Quota alerting thresholds
# ---------------------------------------------------------------------------


class QuotaAlertConfig(BaseModel, frozen=True):
    """Threshold percentages for budget exhaustion alerts."""

    warning_percent: int = Field(
        default=70, ge=10, le=90, description="Warning alert at this % of budget"
    )
    critical_percent: int = Field(
        default=90, ge=50, le=99, description="Critical alert at this % of budget"
    )

    @field_validator("critical_percent")
    @classmethod
    def _critical_above_warning(cls, v: int, info: object) -> int:
        """Critical threshold must be above warning."""
        data = getattr(info, "data", {})
        warning = data.get("warning_percent", 70)
        if v <= warning:
            msg = f"critical_percent ({v}) must be > warning_percent ({warning})"
            raise ValueError(msg)
        return v


# ---------------------------------------------------------------------------
# Redaction profile
# ---------------------------------------------------------------------------


class RedactionConfig(BaseModel, frozen=True):
    """Redaction profile — what to strip before LLM/Jev/log/SSE/telemetry."""

    profile: str = Field(default="strict", pattern=r"^(strict|standard)$")
    redact_api_keys: bool = True
    redact_jwts: bool = True
    redact_private_keys: bool = True
    redact_passwords_in_urls: bool = True
    redact_emails: bool = True
    redact_phone_numbers: bool = True
    redact_credit_cards: bool = True
    redact_high_entropy_strings: bool = True
    high_entropy_threshold: float = Field(
        default=4.5, ge=3.0, le=6.0, description="Shannon entropy threshold for redaction"
    )
    pseudonym_consistency: bool = Field(
        default=True, description="Same value always maps to same pseudonym within investigation"
    )


# ---------------------------------------------------------------------------
# Aggregate configuration
# ---------------------------------------------------------------------------


class GuardrailsConfig(BaseModel, frozen=True):
    """Complete guardrails configuration — one object for the whole system."""

    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    agent: AgentGuardrails = Field(default_factory=AgentGuardrails)
    quota_alerts: QuotaAlertConfig = Field(default_factory=QuotaAlertConfig)
    redaction: RedactionConfig = Field(default_factory=RedactionConfig)


# ---------------------------------------------------------------------------
# Default instance
# ---------------------------------------------------------------------------

DEFAULT_GUARDRAILS = GuardrailsConfig()
