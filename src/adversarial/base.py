"""
Base interface for adversarial attacks against the HTGNN fraud detection model.

Every attack class inherits BaseAttack and implements `perturb`. Attacks take a
graph dictionary (the same format used in example_training.py and the trainer's
batches) and return a new graph dictionary with the perturbation applied. They
must not mutate the input.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional
import torch


Graph = Dict[str, torch.Tensor]


@dataclass
class AttackConfig:
    """Configuration for an attack instance.

    budget: fraction of edges/nodes/features to perturb (0.0 to 1.0).
            Each attack interprets this in its own way.
    seed:   for reproducibility across runs.
    """
    budget: float = 0.05
    seed: int = 0


class BaseAttack(ABC):
    """Abstract base class for all adversarial attacks.

    Subclasses implement `perturb(graph) -> Graph`. The name attribute is
    used for reporting.
    """
    name: str = "base"

    def __init__(self, config: Optional[AttackConfig] = None):
        self.config = config or AttackConfig()

    @abstractmethod
    def perturb(self, graph: Graph) -> Graph:
        """Return a perturbed copy of the graph. Must not mutate the input."""
        raise NotImplementedError

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(budget={self.config.budget}, seed={self.config.seed})"