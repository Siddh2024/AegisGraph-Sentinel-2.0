from dataclasses import asdict, dataclass, field
from typing import Dict, Any, List


@dataclass
class RiskBreakdown:
    """Detailed risk contributions by component."""
    components: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, float]:
        return dict(self.components)

    def total(self) -> float:
        return sum(self.components.values())


@dataclass
class RiskAssessment:
    """Central risk assessment model for score, confidence, and decision."""
    overall_score: float
    confidence: float
    decision: str
    breakdown: RiskBreakdown
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_score": self.overall_score,
            "confidence": self.confidence,
            "decision": self.decision,
            "breakdown": self.breakdown.to_dict(),
            "metadata": dict(self.metadata),
        }

    def to_json(self) -> str:
        import json

        return json.dumps(self.to_dict(), default=str)
