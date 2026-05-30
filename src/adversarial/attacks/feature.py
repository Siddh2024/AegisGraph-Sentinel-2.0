"""
Feature attacks: perturb node attributes without changing graph topology.

Implemented:
    - FeaturePerturbation: add Gaussian noise to node features
"""
from __future__ import annotations
import torch
from ..base import BaseAttack, Graph


class FeaturePerturbation(BaseAttack):
    """Add Gaussian noise to node features.

    Budget = noise standard deviation. Budget 0.05 adds noise drawn from
    N(0, 0.05) to every entry of the node feature matrix. Simulates a
    fraudster making small adjustments to account-level signals (transaction
    averages, login frequency, etc.).

    Note: budget semantics differ from structural attacks. For structural
    attacks it's a fraction of edges; here it's noise magnitude on features.
    The interpretation is per-attack and documented per class.
    """
    name = "feature_perturbation"

    def perturb(self, graph: Graph) -> Graph:
        gen = torch.Generator().manual_seed(self.config.seed)
        noise = torch.randn(graph["x"].shape, generator=gen) * self.config.budget
        return {**graph, "x": graph["x"] + noise}