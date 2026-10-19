# SentinelAI

> **Safety-first agentic AI layer for defensive cybersecurity investigations.**

SentinelAI is an adversarial-resilient investigation platform designed strictly for defensive cybersecurity triage, log correlation, indicator extraction, and remediation planning. It enforces strict separation of duties and verifiable architectural boundaries to ensure that untrusted external inputs and non-deterministic models can never compromise execution safety.

The core architectural principle is:
> **AI may investigate and propose actions, but an independent policy boundary controls what the system is authorized to execute. Incident severity is NOT action authorization.**

---

## 1. Project Overview

SentinelAI ingests security logs (syslog, web server access logs, auth logs, JSON events, and CSV reports), sanitizes and extracts indicators of compromise (IOCs), correlates multi-host evidence, identifies MITRE ATT&CK techniques, and generates structured security reports.

When remediation or analytical actions are proposed, they are evaluated by a deterministic, server-side Policy Engine before any tool execution occurs. State-changing or disruptive actions require explicit human operator review and approval, and the system fails closed to `DENY` whenever authorization cannot be established.

---

## 2. P1 Scope and Limitations

The **P1 Prototype** provides a fully functional local development implementation:

- **Report-First & Human-Supervised**: P1 generates evidence-backed findings and structured response plans. It never automatically executes actions on production systems.
- **Local Persistence & In-Memory Fallback**: Runs out of the box without requiring external cloud infrastructure or live PostgreSQL (in-memory store with SHA-256 hash-chained audit logging is provided).
- **Simulated & Bounded Tools**: Read-only tools (e.g., Sigma rule matching, patch verification, CVE lookups) execute within safe server boundaries. Disruptive actions (such as `lab_block_ip`) are restricted to lab environments and disabled by default.
- **Zero Hallucinated Approvals**: Client-side approval states or model-generated authorizations are ignored; approvals are cryptographically and contextually bound server-side to the specific action, target, parameters, and investigation ID.
- **Not for Public Multi-Tenant Deployment**: P1 is designed for single-operator local evaluation. It does not implement multi-tenant enterprise RBAC or OAuth2/SAML.

---

## 3. Architecture & Request Flow

```
┌─────────────────────────────────────────────────────────────┐
│                       React Frontend                        │
│            (Log Upload, Findings Viewer, Artifacts)         │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP /api/v1/...
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                      FastAPI Backend                        │
│    - File Validation & Redaction Engine                     │
│    - Multi-Format Parser (Syslog, Apache, JSON, CSV)        │
│    - Deterministic Candidate Indicator Extractor            │
└──────────────────────────────┬──────────────────────────────┘
                               │ Normalized Events
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 Investigation Orchestrator                  │
│    - Synthesizes findings, MITRE tactics, confidence        │
│    - Evaluates uncertain evidence & causal links            │
│    - Formulates tool proposals                              │
└──────────────────────────────┬──────────────────────────────┘
                               │ ToolCallProposal
                               ▼
┌─────────────────────────────────────────────────────────────┐
│             Stateless Policy Engine (9 Gates)               │
│    - Evaluates: Target scope, tool status, risk, role       │
│    - Output: ALLOW | REQUIRE_APPROVAL | DENY | DEFER        │
└──────────────┬──────────────────────────────┬───────────────┘
               │ ALLOW                        │ REQUIRE_APPROVAL
               ▼                              ▼
┌──────────────────────────────┐ ┌────────────────────────────┐
│         Tool Gateway         │ │     Human Operator Gate    │
│  - Bounded CPU, RAM, timeout │ │  - Explicit Approve/Reject │
│  - Read-only analysis tools  │ │  - Bound to Action+Target  │
└──────────────┬───────────────┘ └────────────┬───────────────┘
               │ Execution Result             │ Approved
               └───────────────┬──────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────┐
│           Cryptographic Hash-Chained Audit Log              │
│                 SHA-256(prev_hash ‖ event)                  │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Prerequisites

- **Python**: Version 3.12 or newer.
- **Node.js**: Version 20 or newer (tested on Node v24).
- **npm**: Version 10+ (bundled with Node.js).
- **Git**: For version control.

---

## 5. Repository Structure

```
CyberDetectionAI/
├── frontend/                # React 19 + TypeScript + Vite UI
│   ├── src/
│   │   ├── api/client.ts    # Typed API client with ProblemDetail error handling
│   │   ├── types.ts         # TypeScript domain contracts
│   │   ├── App.tsx          # 3-screen investigation workflow
│   │   └── index.css        # Cybersecurity dark design system
│   ├── .env.example         # Frontend environment template
│   └── package.json
├── packages/                # 12 isolated Python packages
│   ├── agent/               # Orchestrator and markdown artifact generators
│   ├── api/                 # FastAPI routes, local store, and server factory
│   ├── audit/               # SHA-256 hash-chained tamper-evident audit logger
│   ├── contracts/           # Pydantic v2 domain schemas, ToolId enums
│   ├── decision/            # Decision providers (Rules, Jev, Mock)
│   ├── evidence/            # Parsers (Syslog, Apache, JSON, CSV) & IOC extractor
│   ├── gateway/             # Subprocess tool executor with policy enforcement
│   ├── llm/                 # Mistral Large client & deterministic demo engine
│   ├── policy/              # 9-gate stateless policy authorization engine
│   ├── redaction/           # Sensitive data scanner and reversible pseudonyms
│   ├── sentinel_config/     # Immutable tool registry, guardrails, schema validation
│   └── tools/               # Handlers (Sigma rules, patch checker, lab blocker)
├── tests/                   # 118+ automated tests (unit, integration, adversarial)
├── scripts/                 # Invariant check scripts (check_no_hardcoded_tools.py)
├── .env.example             # Backend environment template
├── .importlinter            # Monorepo boundary rules
└── pyproject.toml           # Monorepo dependencies and tool configs
```

---

## 6. Environment Configuration

### Backend Configuration

Copy `.env.example` to `.env` in the root directory:
```bash
cp .env.example .env
```

| Variable | Default (Local P1) | Description |
| :--- | :--- | :--- |
| `API_HOST` | `0.0.0.0` | Host interface for FastAPI backend |
| `API_PORT` | `8000` | Port for FastAPI backend |
| `CORS_ORIGINS` | `http://localhost:5173,http://localhost:3000` | Allowed origins for frontend requests |
| `MAX_UPLOAD_BYTES` | `5242880` | Maximum log upload size (5 MB default) |
| `KILL_SWITCH_ACTIVE` | `false` | Emergency kill switch disabling all tool executions |
| `MISTRAL_API_KEY` | *(empty)* | Optional Mistral Large API key; enables live LLM |
| `LLM_BACKEND` | `mock` | `live`, `mock`, or `replay` |
| `DECISION_PROVIDER`| `mock` | `rules`, `jev`, or `mock` |

### Frontend Configuration

Copy `frontend/.env.example` to `frontend/.env`:
```bash
cp frontend/.env.example frontend/.env
```

```env
VITE_API_BASE_URL=http://localhost:8000
```

---

## 7. Frontend Setup

From the repository root:

```bash
cd frontend
npm install
```

To run linter and build:
```bash
npm run lint
npm run build
```

---

## 8. Backend Setup

From the repository root:

```bash
# Set up Python virtual environment
python -m venv .venv

# Activate environment (Windows PowerShell)
.venv\Scripts\Activate.ps1

# Activate environment (Linux / macOS)
# source .venv/bin/activate

# Install in editable mode with development dependencies
pip install --upgrade pip
pip install -e ".[dev]"
```

---

## 9. Running Both Services Locally

Open two terminal windows:

### Terminal 1 — Backend (FastAPI)
```bash
# From repository root with .venv activated:
uvicorn api.app:app --host 0.0.0.0 --port 8000 --reload
```
*Health check URL*: `http://localhost:8000/health`  
*Interactive Swagger UI*: `http://localhost:8000/docs`

### Terminal 2 — Frontend (Vite + React)
```bash
# From repository root:
cd frontend
npm run dev
```
*Web Console*: `http://localhost:5173`

---

## 10. Configuring the LLM Provider

SentinelAI supports both live and offline LLM inference:

- **Live Mistral Large**: Provide your key in `.env`:
  ```env
  MISTRAL_API_KEY=your_key_here
  LLM_BACKEND=live
  ```
- **Fallback / Replay**: For offline evaluation without consuming API tokens, set:
  ```env
  LLM_BACKEND=mock
  ```

---

## 11. Demo Mode Without External Inference

If no `MISTRAL_API_KEY` is provided, SentinelAI automatically activates **Deterministic Demo Mode**:

- **Model Identifier**: Displays clearly as `sentinel-local-demo (Offline Deterministic Engine)`.
- **Honest Labeling**: The UI and reports explicitly flag that analysis is generated using deterministic correlation rules rather than a live cloud LLM.
- **Full Functionality**: Indicator extraction, Sigma matching, ATT&CK mapping, policy evaluation, artifact generation, and approval workflows are 100% active in demo mode.

---

## 12. Supported Log Formats and Upload Limits

| Format | Extensions | Sample Log Source |
| :--- | :--- | :--- |
| **Syslog / RFC 3164** | `.log`, `.txt` | Linux auth logs (`sshd`, `sudo`, `systemd`) |
| **Apache Combined** | `.log`, `.txt` | Apache HTTPD, Nginx web access logs |
| **ISO 8601 Timestamps** | `.log`, `.txt` | Application logs with standard timestamps |
| **Structured JSON** | `.json` | Array of log objects or cloud audit events |
| **JSON Lines** | `.jsonl` | Streaming audit trails (AWS CloudTrail, Suricata) |
| **CSV Reports** | `.csv` | Exported firewall, SIEM, or endpoint telemetry |

- **Default Upload Limit**: 5 MB (configured via `MAX_UPLOAD_BYTES`).
- **Prompt Injection Defense**: Input lines containing prompt override patterns (e.g., `IGNORE ALL PRIOR INSTRUCTIONS`, `SYSTEM PROMPT OVERRIDE`) are flagged with `SUSPICIOUS_CONTENT` and sanitized before synthesis.

---

## 13. Understanding Findings, Uncertainty, Severity, and Action Risk

### Incident Severity
Incident severity represents the defensive assessment of the threat:
- `CRITICAL`: High-impact active exploitation or ransomware activity.
- `HIGH`: Confirmed compromise or unauthorized access sequence.
- `MEDIUM`: Suspicious activity with multiple indicators (e.g., brute-force).
- `LOW`: Anomalous single event or benign scanner noise.
- `INFORMATIONAL`: Routine system telemetry.

### Evidence References & Uncertainty
- Every finding includes direct references to the normalized log event ID and line number.
- When causal connection cannot be verified with certainty (e.g., unrelated multi-host scans), findings are explicitly labelled `UNCERTAIN` or `INCONCLUSIVE`.

### Action Risk vs. Incident Severity
Action risk is measured strictly by the potential impact of the proposed remediation:
- `READ_ONLY`: Zero system side-effects (e.g., querying CVE databases or Sigma rule matching).
- `LOW_RISK`: Minor informational or telemetry collection.
- `HIGH_RISK` / `STATE_CHANGING`: System changes (e.g., blocking an IP, modifying firewall rules).

---

## 14. Understanding Allow, Approval-Required, Deny, and Defer Outcomes

The Policy Engine produces one of four explicit authorization decisions:

1. **`ALLOW`**:
   - The proposed tool is registered, active, read-only, and permitted for the operator's role.
   - Executes automatically via the bounded Tool Gateway.
2. **`REQUIRE_APPROVAL`**:
   - The proposed tool is state-changing, disrupts services, or is designated for lab verification.
   - Pauses execution until a human operator submits an explicit approval.
3. **`DENY`**:
   - The tool is disabled in configuration, target is outside permitted scope, tool ID is unknown, or kill switch is active.
   - The action is completely blocked; reason is recorded in the hash-chained audit log.
4. **`DEFER`**:
   - Insufficient evidence to justify action or required parameters are incomplete.

### The Golden Rule: Severity is NOT Authorization
A `CRITICAL` severity incident does **NOT** grant permission to execute high-risk or disabled tools. Conversely, a `LOW` severity incident still permits read-only analytical queries without requiring human sign-off.

---

## 15. Downloading Investigation Artifacts

Every completed investigation generates a full response bundle:

- `response_report.md`: Executive summary, incident severity rationale, evidence table, ATT&CK techniques, and recommended next steps.
- `findings.json`: Machine-readable JSON payload containing all normalized findings, IOCs, and policy evaluation results.
- `suggested_changes.md`: Defensive configurations (e.g., custom Sigma detection rules, fail2ban configuration).
- `agent_prompt.md`: Structured instructions for an offline remediation agent (explicitly marked as a proposal requiring review).
- `response_plan.md`: (Generated when an action requires approval) Detailed operational risk breakdown, rollback steps, and target parameters.

Artifacts can be viewed directly in the web console or downloaded via `GET /api/v1/investigations/{id}/artifacts/{artifact_name}`.

---

## 16. Running Tests & Quality Gates

SentinelAI enforces strict static analysis and testing:

```bash
# 1. Run all unit and integration tests (118 tests)
pytest

# 2. Run Ruff linter
ruff check .

# 3. Check architectural package boundaries
lint-imports

# 4. Strict MyPy type checking
mypy --strict packages/

# 5. Check for hardcoded tool string leakages
python scripts/check_no_hardcoded_tools.py

# 6. Validate sentinel tool specifications
python -m sentinel_config.validate --check-files --check-impl

# 7. Frontend lint & production build
cd frontend
npm run lint
npm run build
```

---

## 17. Troubleshooting Common Errors

### Backend fails with `Address already in use`
Change the port in command line:
```bash
uvicorn api.app:app --host 0.0.0.0 --port 8001
```
And update `VITE_API_BASE_URL=http://localhost:8001` in `frontend/.env`.

### Upload fails with `HTTP 413: File too large`
By default, uploads are capped at 5 MB. Increase `MAX_UPLOAD_BYTES` in `.env` if investigating large captures.

### Tool Execution Denied: `POLICY_TOOL_DISABLED`
The `lab_block_ip` tool is disabled by default in `sentinel_config/tools.py` (`enabled=False`). This is an intentional security guardrail. To test approval workflows, use the **Force Approval Required** checkbox in the frontend or test with registered analytical tools.

### Starlette/FastAPI Path Traversal Rejections
If testing artifact downloads with encoded traversal strings (e.g. `..%2F`), FastAPI rejects these with `400 Bad Request` or `404 Not Found` before reaching the filesystem.

---

## 18. Security Limitations and Safe-Use Guidance

- **No Live Production Remediation**: SentinelAI P1 does not alter production firewalls, DNS records, or Active Directory forests.
- **Untrusted Input Invariant**: All uploaded log files, packet captures, and tool outputs are treated as untrusted strings. The system uses deterministic regex and grammar parsers to prevent log injection from poisoning downstream execution.
- **Kill Switch Enforcement**: If suspicious behavior occurs, toggling the **Kill Switch** in the UI or via `POST /api/v1/kill-switch` immediately halts all tool invocations across the system.
