"""Tests for database models, constraints, and DDL generation."""
from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

if TYPE_CHECKING:
    import pytest

from api.db_models import (
    AuditEventModel,
    Base,
    EventModel,
    EvidenceModel,
    RemediationProposalModel,
)


class TestDatabaseSchema:
    """Verify table structures, column definitions, and constraint enforcement."""

    def test_remediation_proposal_check_constraint_applied_false(self) -> None:
        """INV-14: Database must have CHECK constraint enforcing applied = false."""
        checks = [
            c for c in RemediationProposalModel.__table__.constraints
            if isinstance(c, CheckConstraint)
        ]
        sql_texts = [str(c.sqltext) for c in checks]
        assert any("applied = false" in text.lower() or "not applied" in text.lower() for text in sql_texts), (
            f"Missing applied = false CHECK constraint: {sql_texts}"
        )

    def test_evidence_trust_check_constraint(self) -> None:
        """INV-7: Evidence trust level must have valid check constraint."""
        checks = [
            c for c in EvidenceModel.__table__.constraints
            if isinstance(c, CheckConstraint)
        ]
        sql_texts = [str(c.sqltext) for c in checks]
        assert any("trust" in text.lower() for text in sql_texts)

    def test_events_fields_gin_index(self) -> None:
        """Events fields JSONB column must have a GIN index."""
        indexes = [
            idx for idx in EventModel.__table__.indexes
            if "fields" in idx.columns
        ]
        assert len(indexes) == 1
        assert indexes[0].kwargs.get("postgresql_using") == "gin"

    def test_audit_log_has_prev_hash_and_hash(self) -> None:
        """Audit log table must have SHA-256 hash chaining columns."""
        cols = AuditEventModel.__table__.columns
        assert "prev_hash" in cols
        assert "hash" in cols
        assert "sequence" in cols

    def test_ddl_generation_postgresql_dialect(self) -> None:
        """Verify DDL compiles cleanly against PostgreSQL dialect."""
        for table in Base.metadata.sorted_tables:
            ddl = str(CreateTable(table).compile(dialect=postgresql.dialect()))
            assert len(ddl) > 0
            assert table.name in ddl

    def test_alembic_upgrade_sql_runs_cleanly(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Verify Alembic migration environment generates static SQL without errors."""
        from alembic import command
        from alembic.config import Config

        alembic_cfg = Config("alembic.ini")
        command.upgrade(alembic_cfg, "head", sql=True)
        captured = capsys.readouterr()
        sql_output = captured.out

        assert "CREATE TABLE investigations" in sql_output
        assert "ck_remediation_proposals_never_applied CHECK (applied = false)" in sql_output
        assert "ix_events_fields_gin ON events USING gin (fields)" in sql_output
        assert "CREATE TABLE audit_log" in sql_output
        assert "CREATE ROLE app_rw" in sql_output
        assert "CREATE ROLE gateway_rw" in sql_output
        assert "CREATE ROLE policy_admin" in sql_output
        assert "CREATE ROLE operator" in sql_output
        assert "CREATE ROLE eval_rw" in sql_output
        assert "GRANT SELECT, INSERT, UPDATE ON investigations" in sql_output
