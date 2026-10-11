# SentinelAI Changelog

All notable changes to this project. Format: task id, date, summary.

## [Unreleased]

### P0-01 — Project Scaffold (2026-10-12)
- Created monorepo structure with 12 internal packages
- pyproject.toml with pinned dependencies (Pydantic v2.9, SQLAlchemy 2.0, FastAPI 0.115)
- ruff + mypy --strict configuration
- import-linter contracts enforcing architectural boundaries
- brain/ seed documents (17, 18, 19)

### P0-02 — sentinel_config: Pure Data + Validate (2026-10-12)
- Created packages/sentinel_config/tools.py defining 11 tools with frozen ToolSpec models and validators
- Created packages/sentinel_config/guardrails.py defining budgets, rate limits, scope, and agent constraints
- Enforced invariants: INV-3 (state_changing approval+lab), INV-6 (no network), INV-12 (kill switch on every edge)
- Implemented packages/sentinel_config/validate.py with invariant checking and deterministic canonical SHA-256 config hash
- Added scripts/check_no_hardcoded_tools.py to prevent literal leakage outside sentinel_config
- 100% passing tests in tests/test_sentinel_config/

### P0-03 — Contracts: Pydantic v2 Models & Invariants (2026-10-12)
- Created packages/contracts/enums.py for canonical enums: TrustLevel, InvestigationStatus, Severity, PolicyAction, ApprovalStatus, Role, ErrorCodePrefix, SSEEventType
- Created packages/contracts/models.py for Pydantic v2 domain schemas with validators
- Enforced invariants: INV-14 (remediation proposal applied=False enforced by validator), UTC timezone-awareness on all datetimes, trust='untrusted' default on evidence envelopes
- Added RFC 7807 ProblemDetail model with strict code prefix validation and leakage protection (no stack traces or SQL)
- Implemented Hypothesis property-based tests in tests/test_contracts/test_properties.py verifying JSON roundtrip and invariant preservation

### P0-04 — Database Schema + Alembic Migrations (2026-10-12)
- Implemented SQLAlchemy 2.0 ORM models in packages/api/db_models.py for all 8 entities
- Enforced DB CHECK constraints: ck_remediation_proposals_never_applied (applied = false, INV-14), ck_evidence_trust (trust in ('untrusted', 'system', 'operator'), INV-7), ck_investigations_status, ck_findings_severity
- Configured GIN index on events.fields JSONB column and compound index on (investigation_id, timestamp)
- Created Alembic configuration (alembic.ini, env.py, script.py.mako) supporting async PostgreSQL 16 migrations and offline SQL generation
- Created initial migration alembic/versions/001_initial_schema.py defining tables, indexes, constraints, and PostgreSQL role creation + grant matrix (app_rw, gateway_rw, policy_admin, operator, eval_rw)
- 100% passing tests in tests/test_contracts/test_db_schema.py including Alembic static SQL generation assertions

### P0-05 — Policy Engine (Pure Authorization Function) 🔒 (2026-10-12)
- Implemented pure function evaluate_policy in packages/policy/engine.py
- Enforced strict 9-stage evaluation order: Kill Switch -> Wall & Tool Budgets -> Denial Limits -> Tool Registry -> Enabled State -> Parameter Schemas (traversal prevention) -> Risk Class/Role -> Human Approvals -> ALLOW with explicit controls
- Output controls enforced on ALLOW: timeout_seconds, max_output_bytes, network_allowed=False, retry_on_error
- Exception-safe fallback returning DENY (POLICY_INTERNAL_ERROR) on any runtime anomaly
- Reached 98% branch coverage with 19 tests in tests/test_policy/test_engine.py and Hypothesis property-based tests in tests/test_policy/test_properties.py

### P0-06 — Audit Hash Chain & Concurrent Serialization 🔒 (2026-10-12)
- Implemented cryptographic hash chain SHA-256(prev_hash ‖ canonical_json(row)) in packages/audit/chain.py
- Implemented audit chain verifier verify_chain in packages/audit/verifier.py validating sequence continuity, hash link integrity, and payload fidelity
- Established concurrent serialization strategy using PostgreSQL transaction-level advisory lock (AUDIT_ADVISORY_LOCK_ID = 481928374829104) and InMemoryAuditChainWriter
- Proven concurrent serialization under 200 simultaneous async writers with zero gaps or hash collisions in tests/test_audit/test_concurrency.py
- 100% passing tests in tests/test_audit/ with 92% coverage

### AUDIT-01 — Adversarial Security, SRE & Invariant Audit 🔒 (2026-10-12)
- BASELINE GATES: Ran ruff, mypy --strict, lint-imports, pytest with coverage, sentinel_config.validate, check_no_hardcoded_tools.
- FIX (Finding 1): Resolved PERF401 list.extend in packages/sentinel_config/validate.py.
- FIX (Finding 2): Reached 100% branch coverage on packages/policy/engine.py via enum_values and bounded integer tests in tests/test_policy/test_engine.py.
- ENHANCEMENT: Added tools and gateway to forbidden_modules for agent in .importlinter to formally enforce INV-1 & INV-5.
- ADVERSARIAL SUITE: Expanded tests/test_security_audit/test_invariants_adversarial.py to 20 tests covering all invariants INV-1 through INV-14.
- Rev 2 Report:
  TASK: AUDIT-01 (Adversarial Security Audit) | STATUS: COMPLETED | CHANGED: packages/sentinel_config/validate.py, .importlinter, tests/test_policy/test_engine.py, tests/test_security_audit/test_invariants_adversarial.py | TESTS -> 100 passed in 5.55s (100% policy branch coverage, 90.37% repo coverage) | INVARIANTS TOUCHED: INV-1..INV-14 | DECISIONS: ADR-009 | UNVERIFIED: OpenAPI diff (P1-04), React frontend (P6-01), Docker compose E2E (P7) | NEXT: P1-01 Redaction Engine

### DOCS-01 — Setup README Documentation (2026-10-12)
- Created comprehensive repository [README.md](file:///c:/Codes/CyberDetectionAI/README.md) detailing architecture, authority split, INV-1..INV-14 invariants table, 12-package monorepo layout, prerequisites, local environment installation, database migrations with role matrix, verification gates (ruff, mypy, lint-imports, pytest, validate, check_no_hardcoded_tools), and adversarial security test execution.
- Rev 2 Report:
  TASK: DOCS-01 (Setup README Documentation) | STATUS: COMPLETED | CHANGED: README.md | TESTS -> 100 passed in 2.17s | INVARIANTS TOUCHED: INV-1..INV-14 | DECISIONS: None | UNVERIFIED: None | NEXT: P1-01 Redaction Engine




