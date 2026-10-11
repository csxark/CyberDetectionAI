"""Evaluation context provided to Policy Engine."""
from __future__ import annotations

import uuid  # noqa: TCH003

import uuid6
from pydantic import BaseModel, ConfigDict, Field

from contracts.enums import Role


class PolicyContext(BaseModel):
    """Contextual state snapshot evaluated by Policy Engine."""

    model_config = ConfigDict(frozen=True)

    investigation_id: uuid.UUID = Field(default_factory=uuid6.uuid7)
    caller_role: Role = Role.ANALYST
    kill_switch_active: bool = False
    wall_seconds_used: int = 0
    llm_calls_used: int = 0
    jev_calls_used: int = 0
    tool_calls_used: int = 0
    denials_for_tool: dict[str, int] = Field(default_factory=dict)
    approved_calls: set[uuid.UUID] = Field(default_factory=set)
    investigation_scope_paths: list[str] = Field(default_factory=list)
