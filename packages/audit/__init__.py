"""SentinelAI Audit Module — hash-chained, INSERT-only audit logging."""
from __future__ import annotations

from audit.chain import (
    GENESIS_HASH,
    canonical_json_row,
    compute_audit_hash,
)
from audit.verifier import verify_chain
from audit.writer import AUDIT_ADVISORY_LOCK_ID, InMemoryAuditChainWriter

__all__ = [
    "AUDIT_ADVISORY_LOCK_ID",
    "GENESIS_HASH",
    "InMemoryAuditChainWriter",
    "canonical_json_row",
    "compute_audit_hash",
    "verify_chain",
]
