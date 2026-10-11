"""Tool specifications — pure frozen data.

This is the single source of truth for all tool definitions in SentinelAI.
No tool IDs, risk classes, parameter schemas, or target kinds may be defined
anywhere else in the codebase (enforced by scripts/check_no_hardcoded_tools.py).

Invariants enforced:
  - INV-3: state_changing tools require approval + lab-only + sandbox
  - INV-5: tools run only in the gateway process
  - INV-7: all tool output treated as untrusted
"""

from __future__ import annotations

from enum import StrEnum, unique
from typing import Any

from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


@unique
class RiskClass(StrEnum):
    """Risk classification for tools, determining policy requirements."""

    READ_ONLY = "read_only"
    """Idempotent reads — retry once on transient error, no approval needed."""

    SANDBOX_EPHEMERAL = "sandbox_ephemeral"
    """Executes in ephemeral sandbox, read-only mounts, no state change."""

    STATE_CHANGING = "state_changing"
    """Modifies state — requires human approval, lab-only, sandbox execution."""


@unique
class TargetKind(StrEnum):
    """What the tool operates on, for scope checking."""

    LOGS = "logs"
    EVENTS = "events"
    REPO = "repo"
    KB = "kb"
    REPORT = "report"
    NETWORK = "network"
    SANDBOX = "sandbox"


@unique
class ToolOperation(StrEnum):
    """High-level operation category for policy grouping."""

    PARSE = "parse"
    EXTRACT = "extract"
    SEARCH = "search"
    CORRELATE = "correlate"
    LOOKUP = "lookup"
    MATCH = "match"
    CHECK = "check"
    BUILD = "build"
    BLOCK = "block"


# ---------------------------------------------------------------------------
# Parameter schema (closed JSON Schema subset)
# ---------------------------------------------------------------------------


class ParamSpec(BaseModel, frozen=True):
    """Single parameter specification for a tool."""

    name: str = Field(min_length=1, max_length=64)
    type: str = Field(pattern=r"^(string|integer|boolean|array|object)$")
    required: bool = True
    description: str = Field(min_length=1, max_length=256)
    max_length: int | None = Field(default=None, ge=1, le=1_000_000)
    min_value: int | None = Field(default=None)
    max_value: int | None = Field(default=None)
    pattern: str | None = Field(default=None, max_length=256)
    enum_values: list[str] | None = Field(default=None)
    default: Any = None


# ---------------------------------------------------------------------------
# ToolSpec
# ---------------------------------------------------------------------------


class ToolSpec(BaseModel, frozen=True):
    """Immutable specification for a single tool.

    All fields here are the canonical definition. The Policy Engine and
    Gateway read from this; the agent sees only the catalog summary.
    """

    id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    description: str = Field(min_length=10, max_length=512)
    risk_class: RiskClass
    target_kind: TargetKind
    operation: ToolOperation
    enabled: bool = True
    params: list[ParamSpec] = Field(default_factory=list)

    # --- Sandbox / execution constraints ---
    timeout_seconds: int = Field(default=30, ge=1, le=300)
    max_output_bytes: int = Field(default=65_536, ge=1, le=5_242_880)
    network_allowed: bool = False
    retry_on_error: bool = False  # only True for read_only

    # --- Approval / lab ---
    requires_approval: bool = False
    lab_only: bool = False

    @field_validator("retry_on_error")
    @classmethod
    def _read_only_retry(cls, v: bool, info: Any) -> bool:
        """Only read_only tools may set retry_on_error=True."""
        data = info.data
        if v and data.get("risk_class") != RiskClass.READ_ONLY:
            msg = "retry_on_error=True only allowed for read_only tools"
            raise ValueError(msg)
        return v

    @field_validator("requires_approval")
    @classmethod
    def _state_changing_approval(cls, v: bool, info: Any) -> bool:
        """State-changing tools MUST require approval (INV-3)."""
        data = info.data
        if data.get("risk_class") == RiskClass.STATE_CHANGING and not v:
            msg = "state_changing tools must set requires_approval=True (INV-3)"
            raise ValueError(msg)
        return v

    @field_validator("lab_only")
    @classmethod
    def _state_changing_lab(cls, v: bool, info: Any) -> bool:
        """State-changing tools MUST be lab-only (INV-3)."""
        data = info.data
        if data.get("risk_class") == RiskClass.STATE_CHANGING and not v:
            msg = "state_changing tools must set lab_only=True (INV-3)"
            raise ValueError(msg)
        return v

    @field_validator("network_allowed")
    @classmethod
    def _no_network(cls, v: bool) -> bool:
        """Tools must not have network access (INV-6)."""
        if v:
            msg = "Tools must not have network access (INV-6). Use lab_block_ip for lab-only network ops."
            raise ValueError(msg)
        return v


# ---------------------------------------------------------------------------
# Tool Registry — the canonical list
# ---------------------------------------------------------------------------

TOOL_REGISTRY: dict[str, ToolSpec] = {}


def _register(spec: ToolSpec) -> ToolSpec:
    """Add a tool to the registry. Raises on duplicate ID."""
    if spec.id in TOOL_REGISTRY:
        msg = f"Duplicate tool ID: {spec.id}"
        raise ValueError(msg)
    TOOL_REGISTRY[spec.id] = spec
    return spec


# --- Read-only analysis tools ---

_register(
    ToolSpec(
        id="parse_logs",
        description="Parse uploaded log file into structured events with timestamps, sources, and fields.",
        risk_class=RiskClass.READ_ONLY,
        target_kind=TargetKind.LOGS,
        operation=ToolOperation.PARSE,
        retry_on_error=True,
        params=[
            ParamSpec(
                name="evidence_id",
                type="string",
                required=True,
                description="ID of the uploaded evidence to parse",
            ),
            ParamSpec(
                name="format_hint",
                type="string",
                required=False,
                description="Optional format hint: syslog, nginx, jsonl, kv, windows_event, sysmon, cloudtrail",
                enum_values=[
                    "syslog",
                    "nginx",
                    "apache",
                    "jsonl",
                    "kv",
                    "windows_event",
                    "sysmon",
                    "cloudtrail",
                ],
            ),
        ],
    )
)

_register(
    ToolSpec(
        id="extract_indicators",
        description="Extract candidate indicators (IPs, domains, hashes, emails, URLs) from parsed events.",
        risk_class=RiskClass.READ_ONLY,
        target_kind=TargetKind.EVENTS,
        operation=ToolOperation.EXTRACT,
        retry_on_error=True,
        params=[
            ParamSpec(
                name="evidence_id",
                type="string",
                required=True,
                description="ID of the parsed evidence",
            ),
            ParamSpec(
                name="indicator_types",
                type="array",
                required=False,
                description="Filter by indicator type",
                enum_values=[
                    "ip",
                    "domain",
                    "hash_md5",
                    "hash_sha1",
                    "hash_sha256",
                    "email",
                    "url",
                ],
            ),
        ],
    )
)

_register(
    ToolSpec(
        id="search_events",
        description="Search parsed events by field values, time range, and source. Uses GIN index for efficiency.",
        risk_class=RiskClass.READ_ONLY,
        target_kind=TargetKind.EVENTS,
        operation=ToolOperation.SEARCH,
        retry_on_error=True,
        params=[
            ParamSpec(
                name="investigation_id",
                type="string",
                required=True,
                description="Investigation context",
            ),
            ParamSpec(
                name="query",
                type="object",
                required=True,
                description="Search filter object with field/value pairs",
            ),
            ParamSpec(
                name="time_start", type="string", required=False, description="ISO 8601 start time"
            ),
            ParamSpec(
                name="time_end", type="string", required=False, description="ISO 8601 end time"
            ),
            ParamSpec(
                name="limit",
                type="integer",
                required=False,
                description="Max results",
                default=100,
                min_value=1,
                max_value=1000,
            ),
        ],
    )
)

_register(
    ToolSpec(
        id="correlate_timeline",
        description="Build a timeline correlating events across sources within a time window.",
        risk_class=RiskClass.READ_ONLY,
        target_kind=TargetKind.EVENTS,
        operation=ToolOperation.CORRELATE,
        retry_on_error=True,
        params=[
            ParamSpec(
                name="investigation_id",
                type="string",
                required=True,
                description="Investigation context",
            ),
            ParamSpec(
                name="pivot_value",
                type="string",
                required=True,
                description="Value to pivot on (IP, user, etc.)",
            ),
            ParamSpec(
                name="window_minutes",
                type="integer",
                required=False,
                description="Time window in minutes",
                default=60,
                min_value=1,
                max_value=1440,
            ),
        ],
    )
)

_register(
    ToolSpec(
        id="lookup_attack_technique",
        description="Look up ATT&CK technique details from the local knowledge base. Never invents IDs.",
        risk_class=RiskClass.READ_ONLY,
        target_kind=TargetKind.KB,
        operation=ToolOperation.LOOKUP,
        retry_on_error=True,
        params=[
            ParamSpec(
                name="technique_id",
                type="string",
                required=True,
                description="MITRE ATT&CK technique ID (e.g., T1078)",
                pattern=r"^T\d{4}(\.\d{3})?$",
            ),
        ],
    )
)

_register(
    ToolSpec(
        id="search_kb",
        description="Search the local knowledge base for techniques, procedures, or indicators.",
        risk_class=RiskClass.READ_ONLY,
        target_kind=TargetKind.KB,
        operation=ToolOperation.SEARCH,
        retry_on_error=True,
        params=[
            ParamSpec(
                name="query",
                type="string",
                required=True,
                description="Search query text",
                max_length=500,
            ),
            ParamSpec(
                name="categories",
                type="array",
                required=False,
                description="Filter by KB category",
                enum_values=["attack", "cwe", "sigma", "indicator"],
            ),
            ParamSpec(
                name="limit",
                type="integer",
                required=False,
                description="Max results",
                default=20,
                min_value=1,
                max_value=100,
            ),
        ],
    )
)

_register(
    ToolSpec(
        id="match_sigma_rules",
        description="Match parsed events against Sigma detection rules from the local rule set.",
        risk_class=RiskClass.READ_ONLY,
        target_kind=TargetKind.EVENTS,
        operation=ToolOperation.MATCH,
        retry_on_error=True,
        params=[
            ParamSpec(
                name="evidence_id",
                type="string",
                required=True,
                description="ID of parsed evidence to match against",
            ),
            ParamSpec(
                name="rule_ids",
                type="array",
                required=False,
                description="Optional list of specific Sigma rule IDs to check",
            ),
        ],
    )
)

_register(
    ToolSpec(
        id="code_search",
        description="Search repository code for patterns, file paths, or function names relevant to the investigation.",
        risk_class=RiskClass.READ_ONLY,
        target_kind=TargetKind.REPO,
        operation=ToolOperation.SEARCH,
        retry_on_error=True,
        params=[
            ParamSpec(
                name="investigation_id",
                type="string",
                required=True,
                description="Investigation context",
            ),
            ParamSpec(
                name="pattern",
                type="string",
                required=True,
                description="Search pattern (regex supported)",
                max_length=500,
            ),
            ParamSpec(
                name="file_glob",
                type="string",
                required=False,
                description="File glob filter (e.g., *.py)",
                max_length=100,
            ),
            ParamSpec(
                name="limit",
                type="integer",
                required=False,
                description="Max results",
                default=50,
                min_value=1,
                max_value=200,
            ),
        ],
    )
)

# --- Sandbox-ephemeral tools ---

_register(
    ToolSpec(
        id="check_patch",
        description="Validate a proposed patch using git apply --check on an ephemeral sandbox copy. Never applies the patch.",
        risk_class=RiskClass.SANDBOX_EPHEMERAL,
        target_kind=TargetKind.SANDBOX,
        operation=ToolOperation.CHECK,
        timeout_seconds=60,
        params=[
            ParamSpec(
                name="investigation_id",
                type="string",
                required=True,
                description="Investigation context",
            ),
            ParamSpec(
                name="patch_content",
                type="string",
                required=True,
                description="Unified diff content to validate",
                max_length=100_000,
            ),
            ParamSpec(
                name="target_ref",
                type="string",
                required=False,
                description="Git ref to apply against",
                default="HEAD",
                max_length=256,
            ),
        ],
    )
)

# --- Report building ---

_register(
    ToolSpec(
        id="build_report",
        description="Compile investigation findings, timeline, and recommendations into a structured report.",
        risk_class=RiskClass.READ_ONLY,
        target_kind=TargetKind.REPORT,
        operation=ToolOperation.BUILD,
        retry_on_error=True,
        timeout_seconds=60,
        max_output_bytes=1_048_576,
        params=[
            ParamSpec(
                name="investigation_id",
                type="string",
                required=True,
                description="Investigation to report on",
            ),
            ParamSpec(
                name="include_timeline",
                type="boolean",
                required=False,
                description="Include event timeline",
                default=True,
            ),
            ParamSpec(
                name="include_indicators",
                type="boolean",
                required=False,
                description="Include extracted indicators",
                default=True,
            ),
        ],
    )
)

# --- State-changing tools (lab-only, approval required) ---

_register(
    ToolSpec(
        id="lab_block_ip",
        description="Block an IP address in the lab network simulator. Lab environment only — never touches production.",
        risk_class=RiskClass.STATE_CHANGING,
        target_kind=TargetKind.NETWORK,
        operation=ToolOperation.BLOCK,
        enabled=False,  # Disabled by default
        requires_approval=True,
        lab_only=True,
        timeout_seconds=10,
        params=[
            ParamSpec(
                name="ip_address",
                type="string",
                required=True,
                description="IP to block in lab simulator",
                pattern=r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
            ),
            ParamSpec(
                name="duration_minutes",
                type="integer",
                required=False,
                description="Block duration in minutes",
                default=60,
                min_value=1,
                max_value=1440,
            ),
            ParamSpec(
                name="reason",
                type="string",
                required=True,
                description="Justification for the block action",
                max_length=500,
            ),
        ],
    )
)


def get_enabled_tools() -> dict[str, ToolSpec]:
    """Return only enabled tools."""
    return {k: v for k, v in TOOL_REGISTRY.items() if v.enabled}


def get_tool(tool_id: str) -> ToolSpec | None:
    """Look up a tool by ID. Returns None if not found."""
    return TOOL_REGISTRY.get(tool_id)
