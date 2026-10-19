"""Evidence ingest and parsing for security log formats."""
from __future__ import annotations

import csv
import io
import json
import re
from contextlib import suppress
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import uuid6

from contracts.enums import TrustLevel
from contracts.models import EvidenceEnvelope
from evidence.models import NormalizedEvent

if TYPE_CHECKING:
    import uuid

DEFAULT_MAX_EVIDENCE_BYTES: int = 5_242_880  # 5 MB default

# Injection keywords scanner for log content
INJECTION_REGEX = re.compile(
    r"(?i)\b("
    r"ignore\s+(?:all\s+)?previous\s+instructions|"
    r"disregard\s+(?:all\s+)?prior\s+prompts|"
    r"you\s+are\s+now\s+in\s+developer\s+mode|"
    r"system\s+override|"
    r"<script[\s>]|"
    r"bypass\s+policy"
    r")\b"
)

# Common timestamp patterns
ISO_TIMESTAMP_REGEX = re.compile(
    r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b"
)
SYSLOG_TIMESTAMP_REGEX = re.compile(
    r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b"
)
APACHE_TIMESTAMP_REGEX = re.compile(
    r"\[(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]"
)

# Key-Value extractor
KV_REGEX = re.compile(r'([a-zA-Z0-9_\.\-]+)=(?:"([^"]*)"|\'([^\']*)\'|([^\s]+))')


def _parse_timestamp(raw_ts: str) -> datetime | None:
    """Attempt parsing timestamp strings into UTC datetime."""
    cleaned = raw_ts.strip("[](), ")

    # 1. ISO format check
    with suppress(Exception):
        iso_str = cleaned.replace(" ", "T") if " " in cleaned and "T" not in cleaned else cleaned
        if iso_str.endswith("Z"):
            iso_str = iso_str[:-1] + "+00:00"
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)

    # 2. Syslog format: "Oct 12 14:20:11"
    with suppress(Exception):
        current_year = datetime.now(UTC).year
        dt = datetime.strptime(f"{current_year} {cleaned} +0000", "%Y %b %d %H:%M:%S %z")
        return dt.astimezone(UTC)

    # 3. Apache/Nginx format: "12/Oct/2026:14:20:11 +0000"
    with suppress(Exception):
        dt = datetime.strptime(cleaned, "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(UTC)

    return None


def _extract_kv_fields(line: str) -> dict[str, Any]:
    """Extract key=value or key="value" pairs from a string."""
    fields: dict[str, Any] = {}
    for match in KV_REGEX.finditer(line):
        k = match.group(1).lower()
        v = match.group(2) or match.group(3) or match.group(4) or ""
        fields[k] = v
    return fields


class LogParser:
    """Parses raw log files into NormalizedEvent models."""

    def __init__(self, max_bytes: int = DEFAULT_MAX_EVIDENCE_BYTES) -> None:
        self.max_bytes = max_bytes

    def parse(
        self,
        content: str | bytes,
        filename: str,
        investigation_id: uuid.UUID | None = None,  # noqa: ARG002
    ) -> tuple[EvidenceEnvelope, list[NormalizedEvent]]:
        """Parse raw content into an EvidenceEnvelope and list of NormalizedEvents."""
        raw_bytes = content.encode("utf-8") if isinstance(content, str) else content
        if len(raw_bytes) > self.max_bytes:
            msg = f"Evidence size ({len(raw_bytes)} bytes) exceeds limit ({self.max_bytes} bytes)."
            raise ValueError(msg)

        text = raw_bytes.decode("utf-8", errors="replace")
        if not text.strip():
            msg = "Uploaded log file is empty."
            raise ValueError(msg)

        # Detect injection indicators in untrusted log content
        suspected_injection = bool(INJECTION_REGEX.search(text))

        # Format detection
        ext = filename.lower().split(".")[-1] if "." in filename else "txt"
        supported_exts = {"log", "txt", "json", "jsonl", "csv"}
        if ext not in supported_exts:
            msg = f"Unsupported file extension '.{ext}'. Supported formats: {', '.join(sorted(supported_exts))}."
            raise ValueError(msg)

        evidence_id = uuid6.uuid7()
        envelope = EvidenceEnvelope(
            id=evidence_id,
            boundary=f"BOUNDARY_EVID_{evidence_id}",
            trust=TrustLevel.UNTRUSTED,
            raw_bytes=len(raw_bytes),
            format=ext,
            content=text,
            suspected_injection=suspected_injection,
            created_at=datetime.now(UTC),
        )

        events: list[NormalizedEvent] = []
        if ext == "json":
            events = self._parse_json(text, evidence_id)
        elif ext == "jsonl":
            events = self._parse_jsonl(text, evidence_id)
        elif ext == "csv":
            events = self._parse_csv(text, evidence_id)
        else:
            # .log or .txt
            events = self._parse_plaintext(text, evidence_id)

        return envelope, events

    def _parse_json(self, text: str, evidence_id: uuid.UUID) -> list[NormalizedEvent]:
        try:
            data = json.loads(text)
        except Exception as e:
            msg = f"Malformed JSON content: {e}"
            raise ValueError(msg) from e

        items: list[Any] = data if isinstance(data, list) else [data]
        events: list[NormalizedEvent] = []
        now = datetime.now(UTC)

        for idx, item in enumerate(items, start=1):
            if not isinstance(item, dict):
                continue
            events.append(self._normalize_dict_event(item, evidence_id, idx, json.dumps(item), now))
        return events

    def _parse_jsonl(self, text: str, evidence_id: uuid.UUID) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        now = datetime.now(UTC)
        for idx, line in enumerate(text.splitlines(), start=1):
            line_str = line.strip()
            if not line_str:
                continue
            try:
                item = json.loads(line_str)
                if isinstance(item, dict):
                    events.append(self._normalize_dict_event(item, evidence_id, idx, line_str, now))
                else:
                    events.append(self._create_fallback_event(evidence_id, idx, line_str, now, "Non-object JSON record"))
            except Exception:
                events.append(self._create_fallback_event(evidence_id, idx, line_str, now, "Malformed JSONL line"))
        return events

    def _parse_csv(self, text: str, evidence_id: uuid.UUID) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        now = datetime.now(UTC)
        reader = csv.DictReader(io.StringIO(text))
        for idx, row in enumerate(reader, start=2):  # line 1 is header
            events.append(self._normalize_dict_event(dict(row), evidence_id, idx, json.dumps(row), now))
        return events

    def _parse_plaintext(self, text: str, evidence_id: uuid.UUID) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        now = datetime.now(UTC)

        for idx, line in enumerate(text.splitlines(), start=1):
            line_str = line.strip()
            if not line_str:
                continue

            event_time = now
            source = "system"
            event_type = "log"
            fields: dict[str, Any] = {}

            # 1. Try ISO timestamp match
            iso_match = ISO_TIMESTAMP_REGEX.search(line_str)
            if iso_match:
                parsed_ts = _parse_timestamp(iso_match.group(1))
                if parsed_ts:
                    event_time = parsed_ts

            # 2. Try Syslog timestamp match
            elif sys_match := SYSLOG_TIMESTAMP_REGEX.match(line_str):
                parsed_ts = _parse_timestamp(sys_match.group(1))
                if parsed_ts:
                    event_time = parsed_ts
                # Extract host and process in syslog
                parts = line_str[len(sys_match.group(1)):].strip().split(" ", 2)
                if len(parts) >= 1:
                    source = parts[0]
                if len(parts) >= 2:
                    proc = parts[1].rstrip(":")
                    fields["process"] = proc
                    event_type = proc

            # 3. Apache/Nginx format
            elif apache_match := APACHE_TIMESTAMP_REGEX.search(line_str):
                parsed_ts = _parse_timestamp(apache_match.group(1))
                if parsed_ts:
                    event_time = parsed_ts
                source = "webserver"
                event_type = "http_access"

            # Extract key-value pairs if present
            kv_fields = _extract_kv_fields(line_str)
            fields.update(kv_fields)

            # Heuristics for common fields
            if "host" in fields:
                source = str(fields["host"])
            elif "source" in fields:
                source = str(fields["source"])

            if "action" in fields:
                event_type = str(fields["action"])
            elif "event" in fields:
                event_type = str(fields["event"])
            elif "event_type" in fields:
                event_type = str(fields["event_type"])

            fields["message"] = line_str

            events.append(
                NormalizedEvent(
                    id=uuid6.uuid7(),
                    evidence_id=evidence_id,
                    line_number=idx,
                    timestamp=event_time,
                    source=source,
                    event_type=event_type,
                    fields=fields,
                    raw_line=line_str,
                )
            )

        return events

    def _normalize_dict_event(
        self,
        item: dict[str, Any],
        evidence_id: uuid.UUID,
        line_num: int,
        raw_line: str,
        fallback_time: datetime,
    ) -> NormalizedEvent:
        # Search for timestamp
        ts_val = fallback_time
        for ts_key in ("timestamp", "time", "@timestamp", "datetime", "date", "created_at"):
            if val := item.get(ts_key):
                parsed = _parse_timestamp(str(val))
                if parsed:
                    ts_val = parsed
                    break

        # Search for source / host
        source = "unknown_source"
        for src_key in ("source", "host", "hostname", "machine", "service", "system"):
            if val := item.get(src_key):
                source = str(val)
                break

        # Search for event type
        event_type = "event"
        for et_key in ("event_type", "event", "action", "type", "category", "method"):
            if val := item.get(et_key):
                event_type = str(val)
                break

        return NormalizedEvent(
            id=uuid6.uuid7(),
            evidence_id=evidence_id,
            line_number=line_num,
            timestamp=ts_val,
            source=source,
            event_type=event_type,
            fields=item,
            raw_line=raw_line,
        )

    def _create_fallback_event(
        self,
        evidence_id: uuid.UUID,
        line_num: int,
        raw_line: str,
        fallback_time: datetime,
        note: str,
    ) -> NormalizedEvent:
        return NormalizedEvent(
            id=uuid6.uuid7(),
            evidence_id=evidence_id,
            line_number=line_num,
            timestamp=fallback_time,
            source="parser",
            event_type="malformed_line",
            fields={"note": note, "message": raw_line},
            raw_line=raw_line,
        )
