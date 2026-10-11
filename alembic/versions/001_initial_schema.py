"""Initial SentinelAI database schema with roles and constraints.

Revision ID: 001_initial_schema
Revises:
Create Date: 2026-10-12 00:00:00.000000
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Investigations
    op.create_table(
        "investigations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.CheckConstraint(
            "status IN ('active', 'suspended', 'concluded', 'failed')",
            name="ck_investigations_status",
        ),
    )

    # 2. Evidence
    op.create_table(
        "evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "investigation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("investigations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("boundary", sa.String(128), nullable=False),
        sa.Column("trust", sa.String(32), nullable=False, server_default="untrusted"),
        sa.Column("raw_bytes", sa.Integer(), nullable=False),
        sa.Column("format", sa.String(64), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("suspected_injection", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "trust IN ('untrusted', 'system', 'operator')",
            name="ck_evidence_trust",
        ),
    )

    # 3. Events
    op.create_table(
        "events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "evidence_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("evidence.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "investigation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("investigations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(128), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("fields", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("raw_line", sa.Text(), nullable=False),
    )
    op.create_index(
        "ix_events_fields_gin",
        "events",
        ["fields"],
        postgresql_using="gin",
    )
    op.create_index(
        "ix_events_investigation_timestamp",
        "events",
        ["investigation_id", "timestamp"],
    )

    # 4. Findings
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "investigation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("investigations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False, server_default="medium"),
        sa.Column("evidence_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("attack_technique_id", sa.String(32), nullable=True),
        sa.Column("cwe_id", sa.String(32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="ck_findings_severity",
        ),
    )

    # 5. Remediation Proposals (INV-14: applied must be false)
    op.create_table(
        "remediation_proposals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "investigation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("investigations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("diff_content", sa.Text(), nullable=False),
        sa.Column("applied", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "applied = false",
            name="ck_remediation_proposals_never_applied",
        ),
    )

    # 6. Tool Executions
    op.create_table(
        "tool_executions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "investigation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("investigations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tool_id", sa.String(64), nullable=False),
        sa.Column("params", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("result_envelope", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("policy_decision_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("status", sa.String(32), nullable=False, server_default="completed"),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 7. Audit Log (INSERT-only, hash chain)
    op.create_table(
        "audit_log",
        sa.Column("sequence", sa.BigInteger(), sa.Identity(start=1), primary_key=True),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("investigation_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("hash", sa.String(64), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_log_investigation", "audit_log", ["investigation_id"])
    op.create_index("ix_audit_log_sequence", "audit_log", ["sequence"])

    # 8. Policy Versions
    op.create_table(
        "policy_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("sha256", sa.String(64), unique=True, nullable=False),
        sa.Column("config_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 9. Role Grants & Permissions Matrix
    roles_sql = """
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'app_rw') THEN
        CREATE ROLE app_rw;
      END IF;
      IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'gateway_rw') THEN
        CREATE ROLE gateway_rw;
      END IF;
      IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'policy_admin') THEN
        CREATE ROLE policy_admin;
      END IF;
      IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'operator') THEN
        CREATE ROLE operator;
      END IF;
      IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'eval_rw') THEN
        CREATE ROLE eval_rw;
      END IF;
    END
    $$;

    GRANT SELECT, INSERT, UPDATE ON investigations, evidence, events, findings, remediation_proposals, tool_executions TO app_rw;
    GRANT SELECT ON policy_versions TO app_rw;
    GRANT INSERT ON audit_log TO app_rw;

    GRANT SELECT ON investigations, policy_versions TO gateway_rw;
    GRANT INSERT ON evidence, tool_executions, audit_log TO gateway_rw;

    GRANT SELECT, INSERT, UPDATE ON policy_versions TO policy_admin;
    GRANT SELECT ON audit_log TO policy_admin;

    GRANT SELECT ON investigations, findings, remediation_proposals, audit_log TO operator;
    GRANT UPDATE (status) ON investigations TO operator;

    GRANT SELECT, INSERT ON investigations, evidence, events, findings, remediation_proposals, tool_executions, audit_log, policy_versions TO eval_rw;
    """
    op.execute(sa.text(roles_sql))


def downgrade() -> None:
    op.drop_table("policy_versions")
    op.drop_table("audit_log")
    op.drop_table("tool_executions")
    op.drop_table("remediation_proposals")
    op.drop_table("findings")
    op.drop_table("events")
    op.drop_table("evidence")
    op.drop_table("investigations")
