"""Normalized event models and extraction schemas for evidence."""
from __future__ import annotations

import uuid  # noqa: TCH003
from datetime import UTC, datetime
from typing import Any

import uuid6
from pydantic import BaseModel, ConfigDict, Field, field_validator


def _validate_utc_datetime(v: datetime) -> datetime:
    """Ensure datetime is timezone-aware and set to UTC."""
    if v.tzinfo is None or v.utcoffset() != UTC.utcoffset(v):
        msg = "Timestamp must be timezone-aware UTC."
        raise ValueError(msg)
    return v


class NormalizedEvent(BaseModel):
    """Normalized structured event extracted from raw evidence."""

    model_config = ConfigDict(frozen=True)

    id: uuid.UUID = Field(default_factory=uuid6.uuid7)
    evidence_id: uuid.UUID
    line_number: int = Field(ge=1)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: str = Field(min_length=1, max_length=128, default="unknown_source")
    event_type: str = Field(min_length=1, max_length=64, default="log_entry")
    fields: dict[str, Any] = Field(default_factory=dict)
    raw_line: str = Field(max_length=100_000)

    @field_validator("timestamp")
    @classmethod
    def _check_utc(cls, v: datetime) -> datetime:
        return _validate_utc_datetime(v)


class ExtractionSummary(BaseModel):
    """Summary statistics and candidate indicators extracted from evidence."""

    model_config = ConfigDict(frozen=True)

    evidence_id: uuid.UUID
    total_events: int = 0
    malformed_lines: int = 0
    time_start: datetime | None = None
    time_end: datetime | None = None
    unique_sources: list[str] = Field(default_factory=list)
    unique_ips: list[str] = Field(default_factory=list)
    unique_users: list[str] = Field(default_factory=list)
    unique_hosts: list[str] = Field(default_factory=list)
    event_types: dict[str, int] = Field(default_factory=dict)
    candidate_indicators: dict[str, list[str]] = Field(default_factory=dict)
