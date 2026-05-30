"""Service boundary for graph and database services."""

from __future__ import annotations

from typing import Any, Protocol
import networkx as nx


class GraphService(Protocol):
    """Protocol defining transaction graph lookup and statistics access."""

    @property
    def number_of_nodes(self) -> int:
        ...

    @property
    def number_of_edges(self) -> int:
        ...

    def nodes(self) -> Any:
        ...

    def edges(self) -> Any:
        ...

    def add_transaction(
        self,
        src_account: str,
        dst_account: str,
        amount: float,
        timestamp: float,
    ) -> None:
        """Dynamically add or record a transaction edge between accounts."""
        ...

    def get_approx_subgraph(self, account_id: str, max_hops: int = 2) -> nx.DiGraph:
        """Extract a local k-hop subgraph around a specific account ID."""
        ...

    def close(self) -> None:
        """Cleanly close any connection pool resources associated with the provider."""
        ...
