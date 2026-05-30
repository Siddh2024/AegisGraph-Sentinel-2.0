import threading
from collections import defaultdict, deque
from typing import Any, Optional

import networkx as nx
import numpy as np

from ..config import get_settings

# Optional Redis import for production scaling
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class LateralMovementDetector:
    """
    Detects MITRE ATT&CK TA0008 (Lateral Movement).
    Upgraded for multi-worker production environments using Redis state syncing,
    with a thread-safe in-memory fallback for local testing.
    """

    def __init__(
        self,
        history_size=10,
        std_multiplier=2.0,
        spike_multiplier=3.0,
        risk_penalty=0.25,
        graph_service: Optional[Any] = None,
    ):
        self.history_size = history_size
        self.std_multiplier = std_multiplier
        self.spike_multiplier = spike_multiplier
        self.risk_penalty = risk_penalty
        self.graph_service = graph_service

        runtime_settings = get_settings()
        self.redis_url = runtime_settings.innovations.redis_url
        self.use_redis = REDIS_AVAILABLE and self.redis_url

        # Check if graph service is active Neo4j provider
        self.use_neo4j = False
        if self.graph_service is not None:
            # Dynamically check if active
            self.use_neo4j = getattr(self.graph_service, "is_active", False)

        if self.use_neo4j:
            print("LateralMovementDetector: Using active Neo4j Graph Database Backend.")
        elif self.use_redis:
            print("LateralMovementDetector: Connected to Redis Backend for multi-worker scaling.")
            self.redis_client = redis.from_url(self.redis_url, decode_responses=True)
            self._graph_cache = {}
            self.redis_client.setnx("aegis:graph:version", 0)
        else:
            print("LateralMovementDetector: Using Thread-Safe In-Memory Backend (Single Worker).")
            # In-memory fallbacks protected by a Mutex lock
            self._lock = threading.Lock()
            self.centrality_history = defaultdict(
                lambda: deque(maxlen=self.history_size)
            )
            self.active_graph = nx.DiGraph()

    def update_graph(self, src_account, dst_account, amount: float = 1.0, timestamp: Optional[float] = None):
        """Updates the network topology dynamically across all workers."""
        if self.graph_service is not None and getattr(self.graph_service, "is_active", False):
            # Neo4j Active Provider execution
            t = timestamp or time.time()
            self.graph_service.add_transaction(src_account, dst_account, amount, t)
            return

        if self.use_redis:
            # Atomic cross-worker edge weight increment plus version bump for cache invalidation.
            pipe = self.redis_client.pipeline(transaction=True)
            pipe.hincrby(f"aegis:edges:{src_account}", dst_account, 1)
            pipe.hincrby(f"aegis:reverse:{dst_account}", src_account, 1)
            pipe.sadd("aegis:nodes", src_account, dst_account)
            pipe.incr("aegis:graph:version")
            pipe.execute()
        else:
            # Thread-safe in-memory update
            with self._lock:
                if self.active_graph.has_edge(src_account, dst_account):
                    self.active_graph[src_account][dst_account]['weight'] += 1
                else:
                    self.active_graph.add_edge(src_account, dst_account, weight=1)
                if self.active_graph.number_of_nodes() > 10000:
                    nodes_to_remove = list(self.active_graph.nodes())[:100]
                    self.active_graph.remove_nodes_from(nodes_to_remove)

    def _get_approx_graph(self, account_id, max_hops=2):
        """Reconstructs a bounded local graph around an account (Redis mode)."""
        if self.graph_service is not None and getattr(self.graph_service, "is_active", False):
            # Extract subgraph from Neo4j dynamically
            return self.graph_service.get_approx_subgraph(account_id, max_hops)

        if not self.use_redis:
            return self.active_graph

        current_version = int(self.redis_client.get("aegis:graph:version") or 0)
        cached = self._graph_cache.get(account_id)
        if cached and cached[0] == current_version:
            return cached[1]

        G = nx.DiGraph()
        frontier = {account_id}
        visited = {account_id}

        for _ in range(max_hops):
            next_frontier = set()
            for node in frontier:
                outgoing = self.redis_client.hgetall(f"aegis:edges:{node}")
                for dst, weight in outgoing.items():
                    G.add_edge(node, dst, weight=float(weight))
                    if dst not in visited:
                        next_frontier.add(dst)

                incoming = self.redis_client.hgetall(f"aegis:reverse:{node}")
                for src, weight in incoming.items():
                    G.add_edge(src, node, weight=float(weight))
                    if src not in visited:
                        next_frontier.add(src)

            visited.update(next_frontier)
            frontier = next_frontier
            if not frontier:
                break

        if not G.has_node(account_id):
            G.add_node(account_id)

        self._graph_cache[account_id] = (current_version, G)
        return G

    def _calculate_approx_centrality(self, account_id):
        """Calculates localized betweenness centrality safely."""
        if self.use_neo4j or self.use_redis:
            G = self._get_approx_graph(account_id)
        else:
            with self._lock:
                G = self.active_graph.copy()

        num_nodes = G.number_of_nodes()
        if num_nodes < 3:
            return 0.0

        k_approx = min(50, num_nodes)
        centralities = nx.betweenness_centrality(
            G,
            k=k_approx,
            normalized=True,
            weight='weight'
        )
        return centralities.get(account_id, 0.0)

    def analyze_account(self, account_id):
        """Evaluates the account against its historical baseline across workers."""
        current_score = self._calculate_approx_centrality(account_id)

        # 1. Store and retrieve history safely
        if self.use_redis:
            history_key = f"aegis:history:{account_id}"
            self.redis_client.lpush(history_key, current_score)
            self.redis_client.ltrim(history_key, 0, self.history_size - 1)
            
            # Fetch and reverse so oldest is first
            history = [float(x) for x in self.redis_client.lrange(history_key, 0, -1)]
            history.reverse()
        else:
            with self._lock:
                history_deque = self.centrality_history[account_id]
                history_deque.append(current_score)
                history = list(history_deque)

        # 2. Evaluate Triggers
        if len(history) < 3:
            return 0.0, False

        baseline_mean = np.mean(history)
        baseline_std = np.std(history)

        threshold = baseline_mean + (self.std_multiplier * baseline_std)
        std_trigger = current_score > threshold
        mult_trigger = current_score > (self.spike_multiplier * baseline_mean)

        is_pivoting = False
        risk_added = 0.0

        if (std_trigger or mult_trigger) and current_score > 0.05:
            is_pivoting = True
            risk_added = self.risk_penalty

        return risk_added, is_pivoting


if __name__ == "__main__":
    detector = LateralMovementDetector()
    print("Initializing Distributed Lateral Movement Engine...")

    detector.update_graph("ACC_002", "ACC_001")
    detector.update_graph("ACC_001", "ACC_003")

    risk, flagged = detector.analyze_account("ACC_001")
    print(f"Risk Added: {risk} | Pivoting Detected: {flagged}")
