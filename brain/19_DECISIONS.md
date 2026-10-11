# SentinelAI Architecture Decision Records

## ADR-001: Monorepo with Import-Linter Boundaries
- **Date:** 2026-10-12
- **Status:** Accepted
- **Context:** SentinelAI has strict invariants (INV-1..14) requiring the agent cannot import sentinel_config internals, policy engine must be pure, and audit/redaction must be isolated.
- **Decision:** Single Python monorepo with `packages/` containing 12 internal packages. Import-linter enforces boundaries at CI time. No separate repos or pip-installable sub-packages for MVP.
- **Alternatives rejected:** Separate repos (too much overhead for solo/small team); namespace packages (no enforcement); runtime import guards (bypassable).
- **Consequences:** All packages share one venv and one pyproject.toml. Import violations are CI failures.

## ADR-002: Dependency Version Pinning Strategy
- **Date:** 2026-10-12
- **Status:** Accepted
- **Context:** Need reproducible builds without blocking security patches.
- **Decision:** Pin to major.minor range (e.g., `>=2.9,<2.10`) in pyproject.toml. Lock exact versions via `pip freeze` in CI. Dependabot/Renovate for patch updates.
- **Alternatives rejected:** Exact pins (blocks patches); unpinned (breaks builds).
- **Consequences:** Minor version bumps require explicit pyproject.toml update and ADR.

## ADR-003: Hatchling Build Backend
- **Date:** 2026-10-12
- **Status:** Accepted
- **Context:** Need a PEP 517 build backend that supports multiple packages in a monorepo.
- **Decision:** Hatchling with explicit `packages` list in `[tool.hatch.build.targets.wheel]`.
- **Alternatives rejected:** setuptools (more complex for multi-package); poetry (version resolver conflicts with monorepo); flit (no multi-package).

## ADR-004: ToolSpec, Guardrails, and Canonical Configuration Hash Pinning
- **Date:** 2026-10-12
- **Status:** Accepted
- **Context:** Tool metadata and guardrail limits must be immutable single-source-of-truth definitions. Policy Engine and Gateway require verified matching configuration before serving requests.
- **Decision:** Frozen Pydantic v2 models in `packages/sentinel_config/{tools,guardrails}.py`. Deterministic canonical JSON serialization and SHA-256 calculation implemented in `sentinel_config.validate.compute_config_hash()`. CI script `scripts/check_no_hardcoded_tools.py` validates that no literals leak into other packages.
- **Alternatives rejected:** YAML config files loaded dynamically at runtime (lacks compile/import-time typing and field validators); distributing tool definitions across individual tool implementation modules (violates single source of truth and allows bypass).
- **Consequences:** Any tool specification or guardrail threshold change modifies the canonical SHA-256 hash, requiring an explicit policy version bump.

## ADR-005: Canonical Contracts and Invariant Enforcement in Pydantic Models
- **Date:** 2026-10-12
- **Status:** Accepted
- **Context:** SentinelAI security invariants require strict constraints across all system layers: remediation proposals must never be marked applied by the agent (INV-14), evidence is untrusted by default (INV-7), error templates must never leak raw models or stack traces, and timestamps must be unambiguous across distributed workers.
- **Decision:** Place all domain models in `packages/contracts/` using Pydantic v2 with frozen configs (`ConfigDict(frozen=True)`). Enforce invariant checks via `@field_validator` (e.g. `RemediationProposal.applied` must be `False`, timestamps must be timezone-aware UTC, error codes must follow standard prefixes). Use `uuid6.uuid7()` for time-sortable UUIDv7 identifiers.
- **Alternatives rejected:** Database-only CHECK constraints (late discovery during commit rather than at instantiation); plain Python dataclasses (no automatic validation or serialization guarantees).
- **Consequences:** Any contract instantiation with invalid invariants fails immediately at runtime with a descriptive `ValidationError`.

## ADR-006: PostgreSQL 16 + pgvector Schema, DB Invariants & Role Matrix
- **Date:** 2026-10-12
- **Status:** Accepted
- **Context:** Database storage must enforce safety invariants at the storage engine level so that even direct database queries or application bugs cannot violate invariants (e.g. marking remediation proposals as applied, or persisting trusted raw evidence). Least privilege requires role isolation between application API, Tool Gateway, Policy Admin, Operator, and Evaluation runners.
- **Decision:** Use SQLAlchemy 2.0 ORM models in `packages/api/db_models.py` (preserving `contracts` purity from DB drivers). Define database CHECK constraints `applied = false` on `remediation_proposals`, `trust IN ('untrusted', 'system', 'operator')` on `evidence`, and GIN indexing on `events.fields`. Implement Alembic async migrations with an initial migration script `001_initial_schema.py` creating the 5 distinct PostgreSQL roles (`app_rw`, `gateway_rw`, `policy_admin`, `operator`, `eval_rw`) with strict table-level and column-level GRANTs.
- **Alternatives rejected:** Single shared database user for all components (violates least privilege and separation of duties); application-only invariant checks without database CHECK constraints (vulnerable to out-of-band updates).
- **Consequences:** Every table write is checked by PostgreSQL constraints. The Tool Gateway and App operate under separate database roles with disjoint write permissions.

## ADR-007: Pure Authorization Policy Engine Decision Pipeline
- **Date:** 2026-10-12
- **Status:** Accepted
- **Context:** SentinelAI authority split requires that the LLM and Decision Provider only propose actions; the Policy Engine is the sole decider of whether a tool execution is permitted. The engine must have no side effects, no database calls, no network I/O, and must guarantee deterministic evaluation order with fail-safe DENY semantics.
- **Decision:** Implement `evaluate_policy` as a pure function in `packages/policy/engine.py`. The function enforces a strict 9-step decision ladder: 1) Kill switch, 2) Budgets (wall-time & tool count), 3) Tool denial limits, 4) Registration check, 5) Enabled check, 6) Parameter schema & path traversal sanitization, 7) Role permissions, 8) Human approval requirement, 9) ALLOW with explicit controls dictionary. Any exception produces an audited DENY with code `POLICY_INTERNAL_ERROR`.
- **Alternatives rejected:** OPA/Rego sidecar (adds latency and out-of-process failure modes for simple static policy rules); scattering policy checks across agent graph nodes (vulnerable to node bypass).
- **Consequences:** Both the Agent and the Tool Gateway invoke the identical pure policy function. Tool Gateway independently re-verifies policy before execution.

## ADR-008: Cryptographic Audit Hash Chain & PostgreSQL Advisory Lock Serialization
- **Date:** 2026-10-12
- **Status:** Accepted
- **Context:** Under INV-8, the audit log must be tamper-evident with cryptographic hash chaining `SHA-256(prev_hash ‖ canonical_json(row))`. Under concurrent writers (multiple API worker processes and Tool Gateway workers), uncoordinated writes can cause hash forks or sequence gaps.
- **Decision:** Use a single 64-bit PostgreSQL transaction-level advisory lock (`pg_advisory_xact_lock(481928374829104)`) to serialize the critical section of reading the latest hash and inserting the new hash-chained row. The advisory lock releases automatically at transaction commit/rollback. In-memory / test environments use an `asyncio.Lock` guarded `InMemoryAuditChainWriter`.
- **Alternatives rejected:** Single-threaded worker service / queue (adds external dependency and latency to tool execution, violating requirement that audit write failure must synchronously halt the action); optimistic concurrency retry loops (causes high retry churn and latency spikes under burst investigations).
- **Consequences:** Audit writes are strictly linear with zero gaps. Advisory lock wait is minimal (<2ms per INSERT), supporting up to ~500 audit writes/second.

## ADR-009: Adversarial Invariant Verification & Agent Tool Isolation in Import Linter
- **Date:** 2026-10-12
- **Status:** Accepted
- **Context:** An independent adversarial security review required formal verification that the agent cannot import or execute tools directly (INV-1, INV-5), that policy branches achieve 100% test coverage, and that database grants strictly block any UPDATE/DELETE operations on the audit log.
- **Decision:** Updated `.importlinter` contract `agent-isolation` to explicitly forbid `agent` from importing `tools` and `gateway` (in addition to `sentinel_config.*`). Expanded `tests/test_security_audit/test_invariants_adversarial.py` to 20 tests verifying attacks against all 14 invariants (INV-1..INV-14), including database grant inspections. Reached 100% branch coverage on `packages/policy/engine.py`.
- **Alternatives rejected:** Relying solely on agent framework prompts to prevent tool imports (vulnerable to prompt injection and runtime jailbreaks).
- **Consequences:** Any agent module importing tools or gateway fails CI lint-imports. All 14 security invariants are covered by automated adversarial tests.






