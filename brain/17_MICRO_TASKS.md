# SentinelAI Micro-Tasks (P0–P7)
# Editable by build process. Precedence: brain/00 > 11 > 04 > rest.

## Phase 0 — Foundation (no agent, no LLM)

### P0-01 Project Scaffold ✅
- [x] pyproject.toml, monorepo layout, ruff/mypy, .importlinter, .gitignore
- [x] brain/ seed (17, 18, 19)
- [x] Empty package __init__.py for all 12 packages
- AC: `pip install -e ".[dev]"`, `ruff check .`, `mypy --strict packages/` all green

### P0-02 sentinel_config — Pure Data + Validate ✅
- [x] packages/sentinel_config/tools.py — ToolSpec frozen models for all 11 tools
- [x] packages/sentinel_config/guardrails.py — budget, limiter, scope config
- [x] packages/sentinel_config/validate.py — closed-schema checks, enabled-tool tests
- [x] tests/test_sentinel_config/
- [x] scripts/check_no_hardcoded_tools.py
- AC: validate.py exits 0; property tests pass; no tool id/threshold/budget literals outside sentinel_config

### P0-03 Contracts — Pydantic v2 Models ✅
- [x] packages/contracts/ — Investigation, Evidence, Finding, AuditEntry, PolicyDecision, ToolCall, SSEEvent, Error, all typed
- [x] Validators, invariants, field constraints (UUIDv7, UTC, trust enum, applied=false)
- AC: mypy --strict; round-trip serialization tests; hypothesis for invariants

### P0-04 Database Schema + Alembic ✅
- [x] alembic/ config targeting Postgres 16 + pgvector
- [x] Initial migration: tables, CHECK constraints, GIN index, roles/grants
- [x] Role matrix: app_rw, gateway_rw, policy_admin, operator, eval_rw
- AC: migration applies to clean Postgres; CHECK constraints tested; roles verified

### P0-05 Policy Engine 🔒 ✅
- [x] packages/policy/engine.py — pure function, decision table
- [x] Kill switch → budgets → registered → target → scope → operation → params → role → approval → ALLOW
- [x] 100% branch coverage, hypothesis properties
- AC: No ALLOW for unregistered/out-of-scope; budgets monotonic; escalations tighten

### P0-06 Audit Hash Chain 🔒 ✅
- [x] packages/audit/ — INSERT-only, SHA-256 chain, concurrent serialization
- [x] Verifier function
- [x] Advisory lock strategy for concurrent writers
- AC: Chain verifies; concurrent writes serialize correctly; no gaps

## Phase 1 — Evidence Pipeline (code-only, no LLM)

### P1-01 Redaction Engine 🔒
- [ ] packages/redaction/ — patterns, stable pseudonyms, encrypted reversible map
- [ ] CI outbound-capture test
- AC: No fixture secret escapes redaction; consistent pseudonyms; reversible

### P1-02 Evidence Ingest + Parsers
- [ ] packages/evidence/ — upload, format sniffing, parsers (syslog, nginx, JSONL, etc.)
- [ ] 5 MB limit, decompression-ratio guard
- [ ] Envelope wrapping, injection detection (regex)
- AC: Each format parsed from fixtures; injection flags set; boundary collisions stripped

### P1-03 Candidate Extractor + Stats (Code-Only)
- [ ] Pure-code extraction: IPs, domains, hashes, users, timestamps
- [ ] Stats: event counts, time ranges, unique sources
- AC: Known fixtures produce expected candidates and stats

### P1-04 API Skeleton + Error Handling
- [ ] App factory, problem+json, error codes, idempotency
- [ ] SSE with resume, JWT stub, authZ skeleton
- AC: Error responses match spec; SSE resume works; 404 for foreign objects

## Phase 2 — LLM Integration

### P2-01 LLM Client (Mistral)
- [ ] packages/llm/client.py — structured output ladder, token-bucket limiter
- [ ] Mock/replay backends, prompt versioning
- AC: Rate limiting works; structured output validates; replay deterministic

## Phase 3 — Decision Provider

### P3-01 Decision Provider Framework
- [ ] packages/decision/ — JevProvider, FallbackLLMProvider, MockProvider
- [ ] Question files, validation
- AC: Mock returns valid decisions; fallback caps confidence; Jev validation rejects bad answers

## Phase 4 — Gateway + Tools

### P4-01 Gateway Process
- [ ] Separate FastAPI, re-runs policy, audit integration
- AC: Gateway rejects unregistered tools; audit write failure halts

### P4-02 Tool Implementations
- [ ] packages/tools/ — all 12 tools, typed, bounded output
- AC: Each tool has fixture tests; no shell=True; no network

## Phase 5 — Agent Graph

### P5-01 LangGraph State + Nodes
- [ ] State schema, node I/O contracts, edge conditions
- [ ] Budget accounting, kill-switch checks
- AC: Graph compiles; budget exhaustion terminates; kill switch halts ≤2s

## Phase 6 — Frontend

### P6-01 React Console
- [ ] Vite + React + TS strict, Tailwind + Radix
- [ ] SSE connection, card components
- AC: Types from OpenAPI; CSP set; WCAG AA

## Phase 7 — CI + Observability

### P7-01 CI Pipelines
- [ ] ci.yml, policy-gate.yml, evals-smoke.yml, security.yml
- AC: All gates pass on clean main
