"""Cryptographic hash chain computation for SentinelAI audit logging.

Enforces:
  - INV-8: Tamper-evident hash chaining SHA-256(prev_hash ‖ canonical_json(row))
  - Canonical JSON: sorted keys, no whitespace, standard string encodings
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS_HASH: str = "0" * 64


def canonical_json_row(row: dict[str, Any]) -> str:
    """Serialize dictionary to deterministic canonical JSON representation."""
    return json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_audit_hash(prev_hash: str, row: dict[str, Any]) -> str:
    """Compute SHA-256(prev_hash ‖ canonical_json(row))."""
    payload_str = canonical_json_row(row)
    combined = f"{prev_hash}{payload_str}".encode()
    return hashlib.sha256(combined).hexdigest()
