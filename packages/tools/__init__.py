"""SentinelAI tools — bounded, typed tool implementations."""
from __future__ import annotations

from tools.handlers import (
    handle_check_patch,
    handle_code_search,
    handle_lab_block_ip,
    handle_lookup_attack_technique,
    handle_match_sigma_rules,
    handle_search_kb,
)

__all__ = [
    "handle_check_patch",
    "handle_code_search",
    "handle_lab_block_ip",
    "handle_lookup_attack_technique",
    "handle_match_sigma_rules",
    "handle_search_kb",
]
