"""In-memory investigation store and audit persistence for local P1 development."""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from audit.writer import InMemoryAuditChainWriter

if TYPE_CHECKING:
    import uuid

    from agent.orchestrator import InvestigationRecord


class LocalInvestigationStore:
    """Thread-safe in-memory store for investigation lifecycle objects and audit logs."""

    def __init__(self) -> None:
        self._investigations: dict[str, InvestigationRecord] = {}
        self.audit_writer = InMemoryAuditChainWriter()
        self.kill_switch_active: bool = False

    def save(self, record: InvestigationRecord) -> None:
        """Store or update an investigation record."""
        self._investigations[str(record.investigation.id)] = record

    def get(self, investigation_id: str | uuid.UUID) -> InvestigationRecord | None:
        """Retrieve an investigation record by UUID or string ID."""
        return self._investigations.get(str(investigation_id))

    def list_all(self) -> list[InvestigationRecord]:
        """List all stored investigation records sorted newest first."""
        return sorted(
            self._investigations.values(),
            key=lambda r: r.created_at,
            reverse=True,
        )

    def set_kill_switch(self, active: bool) -> None:
        """Toggle system-wide kill switch."""
        self.kill_switch_active = active

    def get_audit_entries(self) -> list[dict[str, Any]]:
        """Retrieve all audit hash chain entries."""
        return self.audit_writer.get_entries()


# Global singleton instance for local server lifecycle
GLOBAL_STORE = LocalInvestigationStore()
