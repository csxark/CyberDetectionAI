"""Artifact generators for SentinelAI investigations.

Produces:
  - response_report.md
  - suggested_changes.md
  - agent_prompt.md
  - findings.json
  - response_plan.md
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from contracts.models import Finding, RemediationProposal


def generate_response_report(
    investigation_id: str,
    created_at: datetime,
    filename: str,
    file_bytes: int,
    executive_summary: str,
    severity: str,
    severity_rationale: str,
    findings: list[Finding],
    uncertainties: list[str],
    defensive_actions: list[str],
    policy_outcome: str,
    affected_hosts: list[str] | None = None,
    affected_accounts: list[str] | None = None,
) -> str:
    """Generate response_report.md artifact."""
    now_str = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    created_str = created_at.strftime("%Y-%m-%d %H:%M:%S UTC")

    findings_md = ""
    for idx, f in enumerate(findings, start=1):
        attack_str = f" (`{f.attack_technique_id}`)" if f.attack_technique_id else ""
        cwe_str = f" (`{f.cwe_id}`)" if f.cwe_id else ""
        findings_md += (
            f"### Finding {idx}: {f.title}\n"
            f"- **Severity:** `{f.severity.value.upper()}`\n"
            f"- **Technique / CWE:** {attack_str or 'N/A'}{cwe_str or ''}\n"
            f"- **Evidence References:** {', '.join(str(eid) for eid in f.evidence_ids) or 'Evidence Envelopes'}\n"
            f"- **Details:** {f.description}\n\n"
        )

    uncertainties_md = "\n".join(f"- {u}" for u in uncertainties) if uncertainties else "- None noted."
    actions_md = "\n".join(f"- {a}" for a in defensive_actions) if defensive_actions else "- Monitor logs for recurrence."

    hosts_str = ", ".join(affected_hosts) if affected_hosts else "None established"
    accounts_str = ", ".join(affected_accounts) if affected_accounts else "None established"

    return f"""# SentinelAI Investigation Report

## Metadata
- **Investigation ID:** `{investigation_id}`
- **Generated At:** {now_str}
- **Initiated At:** {created_str}
- **Source File:** `{filename}` ({file_bytes:,} bytes)
- **Policy Authorization Outcome:** `{policy_outcome.upper()}`

---

## Executive Summary
{executive_summary}

---

## Incident Severity & Rationale
- **Proposed Severity:** `{severity.upper()}`
- **Rationale:** {severity_rationale}

---

## Affected Scope
- **Hosts / Endpoints:** {hosts_str}
- **Accounts / Identities:** {accounts_str}

---

## Suspicious Findings & Evidence
{findings_md}

---

## Limitations & Uncertainties
{uncertainties_md}

---

## Recommended Defensive Next Steps
{actions_md}

---
*Notice: SentinelAI is human-supervised and operates on an independent policy boundary. This report does not authorize live system modification without explicit operator consent.*
"""


def generate_suggested_changes(
    investigation_id: str,
    detection_rule: str | None,
    config_change: str | None,
    diff_content: str | None,
    rationale: str | None,
) -> str:
    """Generate suggested_changes.md artifact."""
    now_str = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    rule_sec = f"### Proposed Detection Rule\n```yaml\n{detection_rule}\n```\n" if detection_rule else ""
    cfg_sec = f"### Configuration Adjustment\n{config_change}\n" if config_change else ""
    diff_sec = f"### Proposed Code / Patch Remediation\n```diff\n{diff_content}\n```\n" if diff_content else ""

    return f"""# SentinelAI Suggested Changes

- **Investigation ID:** `{investigation_id}`
- **Generated At:** {now_str}
- **Rationale:** {rationale or 'Hardening based on observed attack telemetry.'}

---

{rule_sec}
{cfg_sec}
{diff_sec}

## Validation Steps
1. Verify rule against historic benign log samples to ensure false-positive rate < 0.1%.
2. Apply configuration adjustment in staging environment and run integration tests.
3. Validate patch syntax using `git apply --check`.

*Note: Proposed changes must be reviewed and tested in a non-production environment before deployment.*
"""


def generate_agent_prompt(
    investigation_id: str,
    findings: list[Finding],
    suggested_changes: str | None,
) -> str:
    """Generate agent_prompt.md artifact for secondary remediation agent."""
    findings_summary = "\n".join(f"- [{f.severity.value.upper()}] {f.title}: {f.description}" for f in findings)
    return f"""# Remediation Agent Instruction Prompt

> **CRITICAL POLICY BOUNDARY:**
> This prompt is a PROPOSAL FOR REVIEW ONLY. It does NOT constitute authorization to modify live systems or production databases. All proposed modifications must be validated in an isolated staging environment.

## Context
- **Investigation ID:** `{investigation_id}`
- **Security Findings:**
{findings_summary}

## Instructions for Remediation Agent
1. Review the security findings and proposed adjustments documented below.
2. Inspect the repository configuration files or infrastructure code corresponding to the affected services.
3. Propose minimal, non-disruptive patches to mitigate the observed vulnerabilities.
4. Execute test suites and linters to verify that no regressions are introduced.
5. Provide an explanation of changes and rollback procedures for human operator review.

## Suggested Changes Reference
```
{suggested_changes or 'No specific diff provided; implement defensive configuration according to findings.'}
```
"""


def generate_response_plan(
    investigation_id: str,
    proposed_action: str,
    target_system: str,
    params: dict[str, Any],
    reason: str,
    supporting_evidence: list[str],
    impact_risks: str,
    reversibility: str,
) -> str:
    """Generate response_plan.md artifact for human approval gate."""
    now_str = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    params_json = json.dumps(params, indent=2)
    evidence_str = "\n".join(f"- {e}" for e in supporting_evidence) if supporting_evidence else "- Log correlation telemetry"

    return f"""# SentinelAI Response Action Plan (Approval Required)

- **Investigation ID:** `{investigation_id}`
- **Generated At:** {now_str}
- **Status:** `AWAITING_OPERATOR_APPROVAL`

---

## 1. Proposed Action
- **Tool / Operation:** `{proposed_action}`
- **Target Resource:** `{target_system}`
- **Proposed Parameters:**
```json
{params_json}
```

## 2. Justification & Evidence
- **Reason:** {reason}
- **Supporting Evidence:**
{evidence_str}

## 3. Risk Assessment & Reversibility
- **Potential Impact:** {impact_risks}
- **Reversibility / Rollback:** {reversibility}

## 4. Policy & Authorization Requirements
- **Required Authorization:** Explicit Operator Approval (Role: `OPERATOR` or `ADMIN`)
- **Execution Mode:** Isolated Lab Sandbox (`lab_only=True`)

*Action will NOT execute until explicit human approval is received via the SentinelAI Console.*
"""


def generate_findings_json(
    investigation_id: str,
    severity: str,
    executive_summary: str,
    findings: list[Finding],
    uncertainties: list[str],
    defensive_actions: list[str],
    remediation: RemediationProposal | None,
    policy_outcome: str,
) -> str:
    """Generate findings.json machine-readable artifact."""
    payload = {
        "investigation_id": investigation_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "severity": severity,
        "executive_summary": executive_summary,
        "policy_outcome": policy_outcome,
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
            for f in findings
        ],
        "uncertainties": uncertainties,
        "defensive_actions": defensive_actions,
        "remediation_proposal": (
            {
                "id": str(remediation.id),
                "description": remediation.description,
                "applied": False,  # INV-14
                "diff_content": remediation.diff_content,
            }
            if remediation
            else None
        ),
    }
    return json.dumps(payload, indent=2)
