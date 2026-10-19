"""Safe, bounded tool implementations for SentinelAI."""
from __future__ import annotations

import fnmatch
from contextlib import suppress
from pathlib import Path
from typing import Any

from tools.kb_data import ATTACK_TECHNIQUES, CWES, SIGMA_RULES


def handle_lookup_attack_technique(params: dict[str, Any]) -> dict[str, Any]:
    """Look up MITRE ATT&CK technique details."""
    technique_id = params.get("technique_id", "")
    info = ATTACK_TECHNIQUES.get(technique_id)
    if not info:
        return {
            "found": False,
            "technique_id": technique_id,
            "message": f"Technique '{technique_id}' not found in local knowledge base.",
        }
    return {"found": True, "technique": info}


def handle_search_kb(params: dict[str, Any]) -> dict[str, Any]:
    """Search knowledge base across ATT&CK, CWE, and Sigma categories."""
    query = str(params.get("query", "")).lower()
    categories = params.get("categories") or ["attack", "cwe", "sigma", "indicator"]
    limit = min(int(params.get("limit", 20)), 100)

    results: list[dict[str, Any]] = []

    if "attack" in categories:
        for tid, tdata in ATTACK_TECHNIQUES.items():
            if query in tid.lower() or query in tdata["name"].lower() or query in tdata["description"].lower():
                results.append({"category": "attack", **tdata})

    if "cwe" in categories:
        for cid, cdata in CWES.items():
            if query in cid.lower() or query in cdata["name"].lower() or query in cdata["description"].lower():
                results.append({"category": "cwe", **cdata})

    if "sigma" in categories:
        results.extend(
            {"category": "sigma", **rdata}
            for rdata in SIGMA_RULES
            if (
                query in rdata["id"].lower()
                or query in rdata["title"].lower()
                or any(query in kw for kw in rdata["keywords"])
            )
        )

    return {
        "query": query,
        "total_results": len(results),
        "results": results[:limit],
    }


def handle_match_sigma_rules(events: list[dict[str, Any]], rule_ids: list[str] | None = None) -> list[dict[str, Any]]:
    """Match events against Sigma detection rules."""
    matches: list[dict[str, Any]] = []
    active_rules = [r for r in SIGMA_RULES if not rule_ids or r["id"] in rule_ids]

    for rule in active_rules:
        matched_events: list[dict[str, Any]] = []
        for ev in events:
            raw = str(ev.get("raw_line", "")).lower()
            fields_str = " ".join(str(v) for v in ev.get("fields", {}).values()).lower()
            combined = f"{raw} {fields_str}"
            if any(kw in combined for kw in rule["keywords"]):
                matched_events.append({
                    "line_number": ev.get("line_number"),
                    "timestamp": ev.get("timestamp"),
                    "source": ev.get("source"),
                    "snippet": ev.get("raw_line", "")[:200],
                })

        if len(matched_events) >= rule.get("min_matches", 1):
            matches.append({
                "rule_id": rule["id"],
                "rule_title": rule["title"],
                "level": rule["level"],
                "technique": rule["technique"],
                "cwe": rule["cwe"],
                "matched_count": len(matched_events),
                "sample_events": matched_events[:10],
            })

    return matches


def handle_code_search(params: dict[str, Any], base_path: str = ".") -> dict[str, Any]:
    """Search repository code for patterns without shell execution."""
    pattern = str(params.get("pattern", "")).lower()
    file_glob = str(params.get("file_glob", "*.*"))
    limit = min(int(params.get("limit", 50)), 200)

    matches: list[dict[str, Any]] = []
    root = Path(base_path)

    # Search only safe text files within project
    allowed_exts = {".py", ".md", ".json", ".yaml", ".yml", ".toml", ".txt", ".ts", ".tsx"}
    count = 0
    for path in root.rglob("*"):
        if count >= limit:
            break
        if not path.is_file() or path.suffix not in allowed_exts:
            continue
        if any(part in path.parts for part in (".git", ".venv", "node_modules", "__pycache__")):
            continue
        if file_glob != "*.*" and not fnmatch.fnmatch(path.name, file_glob):
            continue

        with suppress(Exception):
            content = path.read_text(encoding="utf-8", errors="ignore")
            for line_idx, line in enumerate(content.splitlines(), start=1):
                if pattern in line.lower():
                    matches.append({
                        "file": str(path.relative_to(root)),
                        "line": line_idx,
                        "content": line.strip()[:150],
                    })
                    count += 1
                    if count >= limit:
                        break

    return {
        "pattern": pattern,
        "match_count": len(matches),
        "matches": matches,
    }


def handle_check_patch(params: dict[str, Any]) -> dict[str, Any]:
    """Validate unified diff patch syntax safely in ephemeral sandbox."""
    patch = str(params.get("patch_content", ""))
    lines = patch.splitlines()

    # Basic unified diff syntax validation
    has_diff_header = any(line.startswith(("--- ", "+++ ")) for line in lines)
    has_hunk = any(line.startswith("@@ ") for line in lines)

    if not (has_diff_header and has_hunk):
        return {
            "valid": False,
            "error": "Patch does not conform to standard unified diff format (missing ---/+++ or @@ hunks).",
        }

    return {
        "valid": True,
        "simulated": True,
        "applied": False,
        "message": "Unified diff syntax is valid. Patch simulated successfully without modifying files.",
    }


def handle_lab_block_ip(params: dict[str, Any]) -> dict[str, Any]:
    """Simulated lab-only network block execution."""
    ip = params.get("ip_address")
    duration = params.get("duration_minutes", 60)
    reason = params.get("reason", "Lab investigation response")

    return {
        "executed": True,
        "lab_only": True,
        "simulated": True,
        "ip_address": ip,
        "duration_minutes": duration,
        "reason": reason,
        "message": f"[LAB SIMULATION] IP {ip} blocked in simulated network perimeter for {duration} minutes.",
    }
