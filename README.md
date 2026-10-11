# SentinelAI

> **Safety-first agentic AI layer for defensive cybersecurity investigations.**

SentinelAI is an adversarial-resilient investigation platform designed strictly for defensive cybersecurity triage, log correlation, indicator extraction, and remediation planning. It enforces strict separation of duties and verifiable architectural boundaries to ensure that untrusted external inputs and non-deterministic models can never compromise execution safety.

---

## Architecture & Authority Split

SentinelAI operates on a non-negotiable authority split:

```
                  ┌──────────────────────────────┐
                  │    Untrusted Evidence        │
                  │   (Logs, Alerts, Artifacts)  │
                  └──────────────┬───────────────┘
                                 │
                                 ▼
                  ┌──────────────────────────────┐
                  │   Agent (LangGraph) + LLM    │
                  │   Proposes actions ONLY      │
                  └──────────────┬───────────────┘
                                 │ ToolCallProposal
                                 ▼
┌─────────────────┐       ┌──────────────────────┐
│  Kill Switch    │ ────▶ │    Policy Engine     │
│ (Outside Agent) │       │   Pure authorization │
└─────────────────┘       │    decider (9 gates) │
                          └──────────┬───────────┘
                                     │ PolicyDecision (ALLOW / REQUIRE_APPROVAL / DENY)
                                     ▼
                          ┌──────────────────────┐       ┌────────────────────────┐
                          │   Human Operator     │ ────▶ │      Tool Gateway      │
                          │   (Mandatory for     │       │     Sole executor of   │
                          │   state-changing)    │       │     isolated tools     │
                          └──────────────────────┘       └───────────┬────────────┘
                                                                     │
                                                                     ▼
                                                         ┌────────────────────────┐
                                                         │   Hash-Chained Audit   │
                                                         │   Append-only SHA-256  │
                                                         └────────────────────────┘
```

1. **Exact Facts**: Deterministic code and database constraints define facts; LLMs (Mistral Large) and decision providers (Jev) generate **proposals only**.
2. **Policy Engine as Sole Decider**: A pure, stateless authorization function ([packages/policy/engine.py](file:///c:/Codes/CyberDetectionAI/packages/policy/engine.py)) evaluates all tool proposals through a 9-stage ladder.
3. **Tool Gateway as Sole Executor**: Tools execute exclusively within the isolated Gateway process under bounded CPU, memory, timeout (≤300s), and output size (≤5MB) caps.
4. **Human in the Loop**: State-changing and lab actions require explicit operator approval; the agent cannot approve or apply actions.
5. **Kill Switch Outside Agent Control**: Operators can synchronously halt all agent graph nodes within ≤2 seconds; the check interval is enforced at `0` (evaluated on every graph edge).
6. **Cryptographic Hash-Chained Audit**: Every proposal, policy decision, approval, and tool execution is recorded in an append-only, SHA-256 hash-chained log serialized under PostgreSQL advisory locks.

---

## Core Security Invariants (INV-1 through INV-14)

| Invariant | Description | Enforcing Mechanism |
| :--- | :--- | :--- |
| **INV-1** | Authority Split | Agent cannot import tools or execute them directly; proposals only. |
| **INV-2** | Closed Tool Registry | Tools defined exclusively in [packages/sentinel_config/tools.py](file:///c:/Codes/CyberDetectionAI/packages/sentinel_config/tools.py). |
| **INV-3** | State-Changing Approval | State-changing tools require approval, are `lab_only=True`, and sandbox-isolated. |
| **INV-4** | Decider Integrity | Policy Engine is pure, deterministic, and fails closed to `DENY` on any error. |
| **INV-5** | Bounded Gateway Execution | Tools execute only via Tool Gateway with strict output and timeout bounds. |
| **INV-6** | No Network Egress | Direct tool outbound internet access is strictly forbidden (`network_allowed=False`). |
| **INV-7** | Untrusted Evidence | All evidence and tool outputs default to `trust='untrusted'`. |
| **INV-8** | Tamper-Evident Audit | SHA-256 hash chaining `SHA-256(prev_hash ‖ canonical_json(row))`; zero UPDATE/DELETE grants. |
| **INV-9** | Egress Redaction | Sensitive credentials and tokens are redacted before transmission to external services. |
| **INV-10** | Separation of Duties | RBAC role matrix: `app_rw`, `gateway_rw`, `policy_admin`, `operator`, `eval_rw`. |
| **INV-11** | Monotonic Budgets | Strict caps on wall-clock time, tool calls, and per-tool denial limits. |
| **INV-12** | Continuous Kill Switch | Checked synchronously on every graph step (`kill_switch_check_interval_seconds == 0`). |
| **INV-13** | Input Hardening | Path traversal, zip bombs, and shell executions are rejected by schema validators. |
| **INV-14** | Remediation Never Applied | Proposals enforce `applied=False` via domain validators and database CHECK constraints. |

---

## Monorepo Layout

The repository is organized into 12 isolated packages with import boundaries enforced by `import-linter`:

```
CyberDetectionAI/
├── alembic/                 # Database migrations (PostgreSQL 16 + pgvector)
├── brain/                   # Architecture context, micro-tasks, changelog, ADRs
│   ├── 17_MICRO_TASKS.md    # Phase task checklist (P0 through P7)
│   ├── 18_CHANGELOG.md      # Detailed task changelog
│   └── 19_DECISIONS.md      # Architecture Decision Records (ADR-001..009)
├── docs/                    # Architecture blueprints and design specs
├── packages/
│   ├── agent/               # LangGraph state graph and investigation workflow
│   ├── api/                 # FastAPI routes and SQLAlchemy ORM models
│   ├── audit/               # Cryptographic SHA-256 hash chain and verifier
│   ├── contracts/           # Pydantic v2 domain schemas and invariant validators
│   ├── decision/            # Decision provider framework (Jev, fallback, mock)
│   ├── evidence/            # Evidence ingest, parsers, and candidate extractor
│   ├── gateway/             # Tool Gateway server and subprocess execution
│   ├── llm/                 # LLM client (Mistral Large), prompt templates
│   ├── policy/              # Pure Policy Engine decider ladder
│   ├── redaction/           # Sensitive data scanner and reversible pseudonyms
│   ├── sentinel_config/     # Immutable ToolSpec registry, guardrails, validate
│   └── tools/               # Typed tool implementations (bounded, no network)
├── scripts/                 # CI check scripts (e.g. check_no_hardcoded_tools.py)
├── tests/                   # Pytest test suites (unit, property, adversarial)
├── .env.example             # Template environment variables
├── .importlinter            # Architectural import boundary rules
└── pyproject.toml           # Monorepo dependencies, tools, and build configuration
```

---

## Prerequisites

- **Python**: Version 3.12 or newer.
- **PostgreSQL**: Version 16+ with `pgvector` extension (for production/staging).
- **Node.js**: Version 20+ with `pnpm` (required for Phase 6 web console).
- **Docker**: For running containerized sandbox tool execution (optional in local development).

---

## Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/csxark/CyberDetectionAI.git
cd CyberDetectionAI
```

### 2. Set Up Python Virtual Environment
```bash
# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate

# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install Monorepo in Editable Mode
```bash
pip install --upgrade pip
pip install -e ".[dev]"
```

### 4. Configure Environment Variables
Copy [.env.example](file:///c:/Codes/CyberDetectionAI/.env.example) to `.env` and configure your local settings:
```bash
cp .env.example .env
```

Key environment configurations:
- `DATABASE_URL`: Application connection string for PostgreSQL (`app_rw` role).
- `GATEWAY_DATABASE_URL`: Tool Gateway connection string (`gateway_rw` role).
- `KILL_SWITCH_DB_URL`: Isolated connection string for operator kill switch (`operator` role).
- `MISTRAL_API_KEY`: API key for Mistral Large (set `LLM_BACKEND=mock` for offline testing).
- `TYPESAFE_API_KEY`: API key for Jev decision provider (set `DECISION_PROVIDER=mock` for offline testing).
- `JWT_SECRET`: Secret for signing and validating session tokens.

---

## Database Migrations

SentinelAI enforces least-privilege role separation across 5 database roles:
- `app_rw`: Application API worker (cannot modify `policy_versions` or mutate `audit_log`).
- `gateway_rw`: Tool execution gateway (inserts `evidence`, `tool_executions`, `audit_log`).
- `policy_admin`: Exclusive write access to `policy_versions`.
- `operator`: Reads investigations/audit log; updates investigation status.
- `eval_rw`: Automated eval harness runner.

### Run Migrations Against a Running Database
```bash
alembic upgrade head
```

### Generate Offline SQL DDL
To inspect the generated DDL, role grants, and CHECK constraints without connecting to a database:
```bash
alembic upgrade head --sql
```

---

## Verification & Quality Gates

SentinelAI maintains strict continuous integration quality gates. Run all checks locally before submitting changes:

### 1. Code Linting & Style
```bash
ruff check .
```

### 2. Strict Static Type Checking
```bash
mypy --strict packages/
```

### 3. Architectural Boundary Verification
Ensures modules do not import forbidden dependencies (e.g. agent cannot import tools or config internals):
```bash
lint-imports
```

### 4. Test Suite & Coverage
Executes unit tests, Hypothesis property-based tests, and adversarial security suites:
```bash
pytest --cov=packages --cov-report=term-missing
```
*Requirement: Policy engine must maintain 100% branch coverage; overall repo coverage must be ≥ 80%.*

### 5. Configuration Validation & Hash Check
Validates tool definitions, guardrail limits, and calculates the canonical SHA-256 config hash:
```bash
python -m sentinel_config.validate --check-files --check-impl
```

### 6. Tool Literal Leakage Check
Ensures no tool IDs, budgets, thresholds, or permissions are hardcoded outside [packages/sentinel_config](file:///c:/Codes/CyberDetectionAI/packages/sentinel_config/):
```bash
python scripts/check_no_hardcoded_tools.py
```

---

## Running Adversarial Security Tests

To verify that the system defends against active bypass attempts (path traversal, audit tampering, illegal `applied=True` updates, kill switch overrides, role escalation, and budget exhaustion):

```bash
pytest tests/test_security_audit/test_invariants_adversarial.py -v
```

---

## Development Workflow & Guidelines

- **🔒 Safety-Critical Packages**: Any change to `packages/policy/`, `packages/gateway/`, `packages/redaction/`, `packages/audit/`, or `packages/sentinel_config/` is safety-critical and requires security review with tests written first.
- **Never Weaken Guardrails**: Do not modify thresholds, bypass checks, or relax invariants to make a test pass.
- **Single Source of Truth**: All tools and budgets must be declared in [packages/sentinel_config/tools.py](file:///c:/Codes/CyberDetectionAI/packages/sentinel_config/tools.py) and [packages/sentinel_config/guardrails.py](file:///c:/Codes/CyberDetectionAI/packages/sentinel_config/guardrails.py).
- **Keep Documentation Updated**: Record completed tasks in [brain/18_CHANGELOG.md](file:///c:/Codes/CyberDetectionAI/brain/18_CHANGELOG.md) and new architectural decisions in [brain/19_DECISIONS.md](file:///c:/Codes/CyberDetectionAI/brain/19_DECISIONS.md).

---

## License

Proprietary — All rights reserved.
