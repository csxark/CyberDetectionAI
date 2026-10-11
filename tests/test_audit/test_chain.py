"""Unit tests for the SentinelAI Audit Hash Chain and Verification."""
from __future__ import annotations

from datetime import UTC, datetime

import uuid6

from audit.chain import (
    GENESIS_HASH,
    canonical_json_row,
    compute_audit_hash,
)
from audit.verifier import verify_chain
from contracts.models import AuditEntry


class TestAuditHashChain:
    """Verify cryptographic hash chaining and canonical JSON formatting."""

    def test_genesis_hash_format(self) -> None:
        """Genesis hash is 64 zeros (SHA-256 length)."""
        assert len(GENESIS_HASH) == 64
        assert GENESIS_HASH == "0" * 64

    def test_canonical_json_row_deterministic(self) -> None:
        """Canonical JSON must sort keys and eliminate whitespace."""
        row1 = {"actor": "agent", "action": "tool_call", "sequence": 1}
        row2 = {"sequence": 1, "action": "tool_call", "actor": "agent"}
        assert canonical_json_row(row1) == canonical_json_row(row2)
        assert " " not in canonical_json_row(row1)

    def test_compute_audit_hash_deterministic(self) -> None:
        row = {"sequence": 1, "action": "start"}
        h1 = compute_audit_hash(GENESIS_HASH, row)
        h2 = compute_audit_hash(GENESIS_HASH, row)
        assert len(h1) == 64
        assert h1 == h2

    def test_valid_chain_verifies_cleanly(self) -> None:
        """A properly linked sequence of audit entries passes verification."""
        inv_id = uuid6.uuid7()
        t1 = datetime.now(UTC)
        row1 = {
            "sequence": 1,
            "event_type": "investigation.created",
            "investigation_id": str(inv_id),
            "actor": "analyst",
            "action": "create",
            "payload": {"title": "Test Inv"},
            "timestamp": t1.isoformat(),
        }
        h1 = compute_audit_hash(GENESIS_HASH, row1)
        entry1 = AuditEntry(
            sequence=1,
            event_type="investigation.created",
            investigation_id=inv_id,
            actor="analyst",
            action="create",
            payload={"title": "Test Inv"},
            prev_hash=GENESIS_HASH,
            hash=h1,
            timestamp=t1,
        )

        t2 = datetime.now(UTC)
        row2 = {
            "sequence": 2,
            "event_type": "tool.call.start",
            "investigation_id": str(inv_id),
            "actor": "agent",
            "action": "execute",
            "payload": {"tool": "parse_logs"},
            "timestamp": t2.isoformat(),
        }
        h2 = compute_audit_hash(h1, row2)
        entry2 = AuditEntry(
            sequence=2,
            event_type="tool.call.start",
            investigation_id=inv_id,
            actor="agent",
            action="execute",
            payload={"tool": "parse_logs"},
            prev_hash=h1,
            hash=h2,
            timestamp=t2,
        )

        valid, error = verify_chain([entry1, entry2])
        assert valid is True
        assert error is None

    def test_tampered_payload_breaks_chain(self) -> None:
        """Modifying any field in an entry invalidates the chain."""
        inv_id = uuid6.uuid7()
        t1 = datetime.now(UTC)
        row1 = {
            "sequence": 1,
            "event_type": "investigation.created",
            "investigation_id": str(inv_id),
            "actor": "analyst",
            "action": "create",
            "payload": {"title": "Legit"},
            "timestamp": t1.isoformat(),
        }
        h1 = compute_audit_hash(GENESIS_HASH, row1)
        entry1 = AuditEntry(
            sequence=1,
            event_type="investigation.created",
            investigation_id=inv_id,
            actor="analyst",
            action="create",
            payload={"title": "Legit"},
            prev_hash=GENESIS_HASH,
            hash=h1,
            timestamp=t1,
        )

        # Tampered entry with altered payload
        tampered_entry = entry1.model_copy(update={"payload": {"title": "Hacked"}})
        valid, error = verify_chain([tampered_entry])
        assert valid is False
        assert error is not None
        assert "hash mismatch" in error.lower()

    def test_missing_sequence_breaks_chain(self) -> None:
        """Gap in sequence numbers is detected and rejected."""
        t1 = datetime.now(UTC)
        entry1 = AuditEntry(
            sequence=1,
            event_type="event.1",
            actor="analyst",
            action="create",
            payload={},
            prev_hash=GENESIS_HASH,
            hash=compute_audit_hash(GENESIS_HASH, {
                "sequence": 1, "event_type": "event.1", "investigation_id": None,
                "actor": "analyst", "action": "create", "payload": {}, "timestamp": t1.isoformat()
            }),
            timestamp=t1,
        )

        t3 = datetime.now(UTC)
        entry3 = AuditEntry(
            sequence=3,  # sequence 2 is missing!
            event_type="event.3",
            actor="analyst",
            action="create",
            payload={},
            prev_hash=entry1.hash,
            hash=compute_audit_hash(entry1.hash, {
                "sequence": 3, "event_type": "event.3", "investigation_id": None,
                "actor": "analyst", "action": "create", "payload": {}, "timestamp": t3.isoformat()
            }),
            timestamp=t3,
        )

        valid, error = verify_chain([entry1, entry3])
        assert valid is False
        assert error is not None
        assert "sequence gap" in error.lower()
