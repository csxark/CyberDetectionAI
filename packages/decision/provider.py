"""Decision provider framework for bounded action and tool selection.

Assists with bounded decisions and action recommendations, but NEVER replaces
the independent Policy Engine as the authorizer (INV-1, INV-4).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field


class DecisionRecommendation(BaseModel, frozen=True):
    """Recommendation for next investigation action or tool to consider."""

    tool_id: str
    params: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)
    rationale: str
    provider: str


class DecisionProvider(ABC):
    """Base interface for bounded decision providers."""

    @abstractmethod
    def recommend_actions(
        self,
        extracted_indicators: dict[str, list[str]],
        event_types: dict[str, int],
    ) -> list[DecisionRecommendation]:
        """Propose candidate tool actions for the investigation to consider."""


class RulesDecisionProvider(DecisionProvider):
    """Deterministic rule-based decision provider."""

    def recommend_actions(
        self,
        extracted_indicators: dict[str, list[str]],
        event_types: dict[str, int],  # noqa: ARG002
    ) -> list[DecisionRecommendation]:
        recs: list[DecisionRecommendation] = []

        from contracts.enums import ToolId

        # 1. If attack techniques found in logs, recommend lookup
        techniques = extracted_indicators.get("attack_techniques", [])
        recs.extend(
            DecisionRecommendation(
                tool_id=ToolId.LOOKUP_ATTACK_TECHNIQUE.value,
                params={"technique_id": tech},
                confidence=0.95,
                rationale=f"Observed MITRE ATT&CK indicator '{tech}' in log events.",
                provider="rules",
            )
            for tech in techniques[:3]
        )

        # 2. Always recommend Sigma rule matching to check for known patterns
        recs.append(
            DecisionRecommendation(
                tool_id=ToolId.MATCH_SIGMA_RULES.value,
                params={},
                confidence=0.90,
                rationale="Correlate parsed events against local Sigma attack signature repository.",
                provider="rules",
            )
        )

        # 3. If IPs or hosts found, recommend timeline correlation
        ips = extracted_indicators.get("ips", [])
        if ips:
            recs.append(
                DecisionRecommendation(
                    tool_id=ToolId.CORRELATE_TIMELINE.value,
                    params={"pivot_value": ips[0], "window_minutes": 60},
                    confidence=0.85,
                    rationale=f"Pivot on active external or remote IP '{ips[0]}' to analyze event cluster.",
                    provider="rules",
                )
            )

        return recs


class MockDecisionProvider(RulesDecisionProvider):
    """Local mock decision provider for test and offline environments."""


class JevDecisionProvider(DecisionProvider):
    """Bounded Jev / TypeSafe decision provider with safe local fallback."""

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key
        self.fallback = RulesDecisionProvider()

    def recommend_actions(
        self,
        extracted_indicators: dict[str, list[str]],
        event_types: dict[str, int],
    ) -> list[DecisionRecommendation]:
        if not self.api_key:
            # Safe local fallback when Jev API key is absent
            recs = self.fallback.recommend_actions(extracted_indicators, event_types)
            return [
                DecisionRecommendation(
                    tool_id=r.tool_id,
                    params=r.params,
                    confidence=min(r.confidence, 0.85),
                    rationale=f"[Jev Local Fallback] {r.rationale}",
                    provider="jev_local_fallback",
                )
                for r in recs
            ]
        # Bounded API implementation stub
        return self.fallback.recommend_actions(extracted_indicators, event_types)
