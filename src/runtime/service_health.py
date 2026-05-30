"""Model for service and task health status."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class ServiceHealth:
    """Lightweight metadata modeling a service's runtime health status."""

    name: str
    status: str  # "healthy", "degraded", "unhealthy"
    last_heartbeat: float
    failures: int = 0
    restart_attempts: int = 0
    last_error: Optional[str] = None
