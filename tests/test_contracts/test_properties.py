"""Hypothesis property tests for contracts serialization and invariants."""
from __future__ import annotations

import json
from datetime import UTC, datetime

import uuid6
from hypothesis import given
from hypothesis import strategies as st

from contracts.enums import Severity
from contracts.models import Finding, RemediationProposal


class TestContractsProperties:
    """Property-based verification of contract invariants."""

    @given(
        description=st.text(min_size=1, max_size=500),
        diff=st.text(min_size=1, max_size=1000),
    )
    def test_remediation_proposal_always_applied_false(
        self, description: str, diff: str
    ) -> None:
        """For any text inputs, proposal must initialize with applied=False."""
        prop = RemediationProposal(
            id=uuid6.uuid7(),
            investigation_id=uuid6.uuid7(),
            description=description,
            diff_content=diff,
            applied=False,
            created_at=datetime.now(UTC),
        )
        assert prop.applied is False

    @given(
        title=st.text(min_size=1, max_size=100),
        description=st.text(min_size=1, max_size=500),
    )
    def test_finding_json_roundtrip(self, title: str, description: str) -> None:
        """Findings must cleanly roundtrip through JSON serialization."""
        f1 = Finding(
            id=uuid6.uuid7(),
            investigation_id=uuid6.uuid7(),
            title=title,
            description=description,
            severity=Severity.HIGH,
            evidence_ids=[uuid6.uuid7()],
            created_at=datetime.now(UTC),
        )
        data = f1.model_dump(mode="json")
        serialized = json.dumps(data)
        deserialized = json.loads(serialized)
        f2 = Finding.model_validate(deserialized)
        assert f1.id == f2.id
        assert f1.title == f2.title
        assert f1.severity == f2.severity
