"""Tests for candidate indicator extractor and statistical baseline."""
from __future__ import annotations

import uuid6

from evidence.extractor import CandidateExtractor
from evidence.parser import LogParser


def test_extract_indicators_and_statistics() -> None:
    parser = LogParser()
    extractor = CandidateExtractor()
    sample = (
        "2026-10-18T10:00:00Z webserver sshd: Failed password for root from 192.168.1.50 port 22\n"
        "2026-10-18T10:00:05Z webserver sshd: Failed password for admin from 192.168.1.50 port 22\n"
        "2026-10-18T10:00:10Z webserver attack: Technique T1078 observed contacting malicious.domain.com\n"
    )
    envelope, events = parser.parse(sample, "test.log")
    summary = extractor.extract(envelope.id, events)

    assert summary.total_events == 3
    assert "192.168.1.50" in summary.unique_ips
    assert "root" in summary.unique_users or "admin" in summary.unique_users
    assert "malicious.domain.com" in summary.candidate_indicators["domains"]
    assert "T1078" in summary.candidate_indicators["attack_techniques"]
    assert summary.time_start is not None
    assert summary.time_end is not None


def test_extract_empty_events() -> None:
    extractor = CandidateExtractor()
    summary = extractor.extract(uuid6.uuid7(), [])
    assert summary.total_events == 0
    assert summary.unique_ips == []
