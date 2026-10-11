"""Root conftest — shared fixtures for all SentinelAI tests."""

from __future__ import annotations

import uuid
from typing import Any

import pytest


@pytest.fixture
def investigation_id() -> uuid.UUID:
    """Generate a deterministic investigation ID for tests."""
    return uuid.UUID("01234567-89ab-cdef-0123-456789abcdef")


@pytest.fixture
def sample_log_line() -> str:
    """A single syslog line with no real PII for safe fixture use."""
    return (
        "Oct 10 14:23:01 webserver01 sshd[12345]: "
        "Failed password for invalid user testuser from 198.51.100.42 port 54321 ssh2"
    )


@pytest.fixture
def sample_log_lines() -> list[str]:
    """Multiple syslog lines for batch processing tests."""
    return [
        "Oct 10 14:23:01 webserver01 sshd[12345]: Failed password for invalid user testuser from 198.51.100.42 port 54321 ssh2",
        "Oct 10 14:23:05 webserver01 sshd[12346]: Failed password for invalid user admin from 198.51.100.42 port 54322 ssh2",
        "Oct 10 14:23:10 webserver01 sshd[12347]: Accepted publickey for deploy from 203.0.113.10 port 22 ssh2",
        "Oct 10 14:24:00 webserver01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.42 DST=10.0.0.5 PROTO=TCP SPT=12345 DPT=443",
    ]


@pytest.fixture
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Block all outbound network in tests (safety net)."""
    import socket

    def _blocked(*args: Any, **kwargs: Any) -> None:
        msg = "Network access blocked in tests"
        raise RuntimeError(msg)

    monkeypatch.setattr(socket, "socket", _blocked)
