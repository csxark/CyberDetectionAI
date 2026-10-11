"""Configuration validation and hash generation.

Validates:
  1. Closed schemas on all ToolSpec and ParamSpec fields
  2. Invariants:
     - INV-3: state_changing => requires_approval + lab_only
     - INV-5: tool output bounded
     - INV-6: network_allowed is False across all tools
     - INV-12: kill_switch_check_interval_seconds == 0
  3. Enabled tool list sanity
  4. Generates canonical SHA-256 hash for policy_versions immutability and sync check.

CLI usage:
  python -m sentinel_config.validate
"""
from __future__ import annotations

import hashlib
import json
import sys
from typing import Any

from pydantic import BaseModel, Field

from sentinel_config.guardrails import DEFAULT_GUARDRAILS, GuardrailsConfig
from sentinel_config.tools import TOOL_REGISTRY, RiskClass, ToolSpec


class ConfigValidationError(Exception):
    """Raised when configuration fails invariant or schema checks."""


class ValidationReport(BaseModel, frozen=True):
    """Report detailing configuration validation results."""

    is_valid: bool
    total_tools: int
    enabled_tools: int
    disabled_tools: int
    config_hash: str
    errors: list[str] = Field(default_factory=list)


def validate_tool(tool: ToolSpec) -> list[str]:
    """Validate a single tool against all security and operational invariants."""
    errors: list[str] = []

    # INV-6: No network access
    if tool.network_allowed:
        errors.append(f"Tool '{tool.id}': network_allowed=True violates INV-6.")

    # INV-3: State-changing tools must require approval and be lab-only
    if tool.risk_class == RiskClass.STATE_CHANGING:
        if not tool.requires_approval:
            errors.append(f"Tool '{tool.id}': state_changing must require approval (INV-3).")
        if not tool.lab_only:
            errors.append(f"Tool '{tool.id}': state_changing must be lab-only (INV-3).")

    # Output bounding
    if tool.max_output_bytes <= 0 or tool.max_output_bytes > 5_242_880:
        errors.append(f"Tool '{tool.id}': max_output_bytes must be in range 1..5242880.")

    # Timeout bounding
    if tool.timeout_seconds <= 0 or tool.timeout_seconds > 300:
        errors.append(f"Tool '{tool.id}': timeout_seconds must be in range 1..300.")

    # Retry only on read_only
    if tool.retry_on_error and tool.risk_class != RiskClass.READ_ONLY:
        errors.append(f"Tool '{tool.id}': retry_on_error allowed only for read_only tools.")

    # Validate parameters closed schemas
    errors.extend(
        f"Tool '{tool.id}' param '{param.name}': invalid type '{param.type}'."
        for param in tool.params
        if param.type not in {"string", "integer", "boolean", "array", "object"}
    )

    return errors


def validate_guardrails(guardrails: GuardrailsConfig) -> list[str]:
    """Validate guardrails configuration against invariants."""
    errors: list[str] = []

    # INV-12: Kill switch check on every edge
    if guardrails.agent.kill_switch_check_interval_seconds != 0:
        errors.append("kill_switch_check_interval_seconds must be 0 (INV-12).")

    # Budget validity
    if guardrails.budget.wall_seconds <= 0:
        errors.append("budget.wall_seconds must be > 0.")
    if guardrails.budget.llm_calls <= 0:
        errors.append("budget.llm_calls must be > 0.")
    if guardrails.budget.jev_calls <= 0:
        errors.append("budget.jev_calls must be > 0.")

    # Scope limits
    if guardrails.scope.max_evidence_bytes <= 0 or guardrails.scope.max_evidence_bytes > 52_428_800:
        errors.append("scope.max_evidence_bytes must be in range 1..52428800.")

    # Quota alert ordering
    if guardrails.quota_alerts.warning_percent >= guardrails.quota_alerts.critical_percent:
        errors.append("quota_alerts warning_percent must be < critical_percent.")

    return errors


def compute_config_hash(
    registry: dict[str, ToolSpec] | None = None,
    guardrails: GuardrailsConfig | None = None,
) -> str:
    """Compute a deterministic SHA-256 hash over canonical serialized config."""
    tools_dict = registry if registry is not None else TOOL_REGISTRY
    g_config = guardrails if guardrails is not None else DEFAULT_GUARDRAILS

    canonical_data: dict[str, Any] = {
        "tools": {
            k: tools_dict[k].model_dump(mode="json")
            for k in sorted(tools_dict.keys())
        },
        "guardrails": g_config.model_dump(mode="json"),
    }

    serialized = json.dumps(canonical_data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def validate_all(
    registry: dict[str, ToolSpec] | None = None,
    guardrails: GuardrailsConfig | None = None,
) -> ValidationReport:
    """Perform full system configuration validation and return report."""
    tools_dict = registry if registry is not None else TOOL_REGISTRY
    g_config = guardrails if guardrails is not None else DEFAULT_GUARDRAILS

    errors: list[str] = []

    if not tools_dict:
        errors.append("TOOL_REGISTRY is empty.")

    for tool in tools_dict.values():
        errors.extend(validate_tool(tool))

    errors.extend(validate_guardrails(g_config))

    total = len(tools_dict)
    enabled = sum(1 for t in tools_dict.values() if t.enabled)
    disabled = total - enabled
    config_hash = compute_config_hash(tools_dict, g_config)

    return ValidationReport(
        is_valid=len(errors) == 0,
        total_tools=total,
        enabled_tools=enabled,
        disabled_tools=disabled,
        config_hash=config_hash,
        errors=errors,
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint: validates config, prints status and config hash."""
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Validate SentinelAI tool and guardrail configurations.")
    parser.add_argument("--check-files", action="store_true", help="Verify presence of config files and prompt directory.")
    parser.add_argument("--check-impl", action="store_true", help="Verify tool operation contracts and parameter completeness.")
    args = parser.parse_args(argv)

    report = validate_all()

    extra_errors: list[str] = []

    if args.check_files:
        prompts_dir = Path("packages/llm/prompts")
        if not prompts_dir.exists():
            extra_errors.append(f"Prompts directory {prompts_dir} not found.")

    if args.check_impl:
        extra_errors.extend(
            f"Tool '{tool.id}' lacks parameter implementations."
            for tool in TOOL_REGISTRY.values()
            if not tool.params and tool.risk_class != RiskClass.READ_ONLY
        )

    all_errors = list(report.errors) + extra_errors

    if not report.is_valid or extra_errors:
        print("[FAIL] Configuration validation failed:", file=sys.stderr)
        for err in all_errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("[OK] Configuration validation successful.")
    print(f"  - Total tools:    {report.total_tools}")
    print(f"  - Enabled tools:  {report.enabled_tools}")
    print(f"  - Disabled tools: {report.disabled_tools}")
    print(f"  - Config SHA-256: {report.config_hash}")
    if args.check_files:
        print("  - File checks:    PASSED")
    if args.check_impl:
        print("  - Impl checks:    PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
