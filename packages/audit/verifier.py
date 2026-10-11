"""Audit log integrity verifier."""
from __future__ import annotations

from typing import TYPE_CHECKING

from audit.chain import compute_audit_hash

if TYPE_CHECKING:
    from contracts.models import AuditEntry


def verify_chain(entries: list[AuditEntry]) -> tuple[bool, str | None]:
    """Verify cryptographic link integrity and sequence continuity of audit log entries."""
    if not entries:
        return True, None

    # Track previous hash; start from first entry's prev_hash or GENESIS_HASH if sequence == 1
    for i, entry in enumerate(entries):
        # 1. Sequence continuity check
        if i > 0 and entry.sequence != entries[i - 1].sequence + 1:
            return False, f"Sequence gap: entry {entry.sequence} does not follow {entries[i - 1].sequence}."

        # 2. Hash link check
        if i > 0 and entry.prev_hash != entries[i - 1].hash:
            return False, f"Broken link at sequence {entry.sequence}: prev_hash does not match previous entry's hash."

        # 3. Payload hash integrity check
        row_dict = {
            "sequence": entry.sequence,
            "event_type": entry.event_type,
            "investigation_id": str(entry.investigation_id) if entry.investigation_id else None,
            "actor": entry.actor,
            "action": entry.action,
            "payload": entry.payload,
            "timestamp": entry.timestamp.isoformat(),
        }
        recomputed = compute_audit_hash(entry.prev_hash, row_dict)
        if recomputed != entry.hash:
            return False, f"Hash mismatch at sequence {entry.sequence}: computed {recomputed} != recorded {entry.hash}."

    return True, None
