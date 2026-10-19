"""Candidate indicator extractor and statistical baseline generator."""
from __future__ import annotations

import re
from collections import Counter
from typing import TYPE_CHECKING

from evidence.models import ExtractionSummary

if TYPE_CHECKING:
    import uuid
    from datetime import datetime

    from evidence.models import NormalizedEvent

# Indicator Regexes
IPV4_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|edu|gov|io|ai|co|xyz|info|biz|ru|cn|uk|de|eu)\b",
    re.IGNORECASE,
)
HASH_MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
HASH_SHA1_REGEX = re.compile(r"\b[a-fA-F0-9]{40}\b")
HASH_SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")
ATTACK_TECHNIQUE_REGEX = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")
USER_AUTH_REGEX = re.compile(r"(?i)\b(?:for|user)\s+(?:invalid\s+user\s+)?([a-zA-Z0-9_\.\-]{2,32})\b")


class CandidateExtractor:
    """Pure-code extractor for cybersecurity indicators and event statistics."""

    def extract(
        self,
        evidence_id: uuid.UUID,
        events: list[NormalizedEvent],
    ) -> ExtractionSummary:
        """Extract indicators and compute statistics over normalized events."""
        if not events:
            return ExtractionSummary(evidence_id=evidence_id)

        ips: set[str] = set()
        domains: set[str] = set()
        md5_hashes: set[str] = set()
        sha1_hashes: set[str] = set()
        sha256_hashes: set[str] = set()
        users: set[str] = set()
        hosts: set[str] = set()
        techniques: set[str] = set()

        event_types: Counter[str] = Counter()
        sources: set[str] = set()

        time_start: datetime | None = None
        time_end: datetime | None = None
        malformed_count = 0

        for event in events:
            # Track time span
            if time_start is None or event.timestamp < time_start:
                time_start = event.timestamp
            if time_end is None or event.timestamp > time_end:
                time_end = event.timestamp

            sources.add(event.source)
            event_types[event.event_type] += 1
            if event.event_type == "malformed_line":
                malformed_count += 1

            # Extract from fields dict directly
            fields = event.fields
            for k, v in fields.items():
                val_str = str(v)
                k_lower = k.lower()
                if (
                    any(u_key in k_lower for u_key in ("user", "account", "login", "subject", "actor"))
                    and val_str
                    and val_str.lower() not in ("none", "null", "-", "")
                ):
                    users.add(val_str)
                if (
                    any(h_key in k_lower for h_key in ("host", "machine", "device", "workstation"))
                    and val_str
                    and val_str.lower() not in ("none", "null", "-", "")
                ):
                    hosts.add(val_str)

            # Extract regexes across raw line and stringified fields
            text_to_scan = f"{event.source} {event.raw_line} {' '.join(str(v) for v in fields.values())}"

            for match in IPV4_REGEX.finditer(text_to_scan):
                ip = match.group(0)
                # Exclude obvious non-routable dummy numbers if 0.0.0.0
                if ip != "0.0.0.0":  # noqa: S104
                    ips.add(ip)

            for match in DOMAIN_REGEX.finditer(text_to_scan):
                domains.add(match.group(0).lower())

            for match in HASH_SHA256_REGEX.finditer(text_to_scan):
                sha256_hashes.add(match.group(0).lower())

            for match in HASH_SHA1_REGEX.finditer(text_to_scan):
                # Ensure not substring of sha256
                sha1 = match.group(0).lower()
                if not any(sha1 in s256 for s256 in sha256_hashes):
                    sha1_hashes.add(sha1)

            for match in HASH_MD5_REGEX.finditer(text_to_scan):
                md5 = match.group(0).lower()
                if not any(md5 in s256 for s256 in sha256_hashes) and not any(md5 in s1 for s1 in sha1_hashes):
                    md5_hashes.add(md5)

            for match in ATTACK_TECHNIQUE_REGEX.finditer(text_to_scan):
                techniques.add(match.group(1))

            for match in USER_AUTH_REGEX.finditer(text_to_scan):
                u_cand = match.group(1).lower()
                if u_cand not in ("invalid", "user", "from", "port", "none", "null", "sshd", "ssh2"):
                    users.add(u_cand)

        # Add event.source if it looks like a hostname
        for s in sources:
            if s not in ("system", "unknown_source", "parser", "webserver"):
                hosts.add(s)

        candidate_indicators: dict[str, list[str]] = {
            "ips": sorted(ips),
            "domains": sorted(domains),
            "sha256": sorted(sha256_hashes),
            "sha1": sorted(sha1_hashes),
            "md5": sorted(md5_hashes),
            "attack_techniques": sorted(techniques),
        }

        return ExtractionSummary(
            evidence_id=evidence_id,
            total_events=len(events),
            malformed_lines=malformed_count,
            time_start=time_start,
            time_end=time_end,
            unique_sources=sorted(sources),
            unique_ips=sorted(ips),
            unique_users=sorted(users),
            unique_hosts=sorted(hosts),
            event_types=dict(event_types),
            candidate_indicators=candidate_indicators,
        )
