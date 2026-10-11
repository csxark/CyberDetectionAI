"""Tests for concurrent audit write serialization."""
from __future__ import annotations

import asyncio
from datetime import datetime

import pytest

from audit.verifier import verify_chain
from audit.writer import InMemoryAuditChainWriter
from contracts.models import AuditEntry


@pytest.mark.asyncio
async def test_concurrent_writers_produce_valid_chain() -> None:
    """Multiple concurrent async writers append entries without race conditions or gaps."""
    writer = InMemoryAuditChainWriter()

    async def _worker(worker_id: int, count: int) -> None:
        for i in range(count):
            await writer.append(
                event_type="test.event",
                actor=f"worker-{worker_id}",
                action=f"action-{i}",
                payload={"worker": worker_id, "step": i},
            )

    # Run 10 concurrent workers each appending 20 entries (200 total)
    workers = [_worker(w, 20) for w in range(10)]
    await asyncio.gather(*workers)

    raw_entries = writer.get_entries()
    assert len(raw_entries) == 200

    # Convert to typed AuditEntry models
    audit_entries = [
        AuditEntry(
            sequence=e["sequence"],
            event_type=e["event_type"],
            investigation_id=None,
            actor=e["actor"],
            action=e["action"],
            payload=e["payload"],
            prev_hash=e["prev_hash"],
            hash=e["hash"],
            timestamp=datetime.fromisoformat(e["timestamp"]),
        )
        for e in raw_entries
    ]

    # Verify entire serialized chain has 0 gaps and 100% valid cryptographic links
    valid, error = verify_chain(audit_entries)
    assert valid is True, f"Chain verification failed: {error}"
