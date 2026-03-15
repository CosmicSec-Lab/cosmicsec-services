"""
Phase 2 — Distributed Scanning Coordinator.

Provides in-memory node registry and target-to-node assignment with
round-robin + health/weight filtering.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class ScanNode:
    node_id: str
    region: str
    capacity: int = 4
    healthy: bool = True
    tags: List[str] = field(default_factory=list)
    active_jobs: int = 0
    last_heartbeat: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "region": self.region,
            "capacity": self.capacity,
            "healthy": self.healthy,
            "tags": self.tags,
            "active_jobs": self.active_jobs,
            "last_heartbeat": self.last_heartbeat,
            "utilization": round(self.active_jobs / self.capacity, 3) if self.capacity else 1.0,
        }


class DistributedScanCoordinator:
    """Simple in-memory coordinator for distributed scan assignment."""

    def __init__(self) -> None:
        self._nodes: Dict[str, ScanNode] = {}

    def register_node(self, node_id: str, region: str, capacity: int = 4, tags: Optional[List[str]] = None) -> Dict[str, Any]:
        node = ScanNode(node_id=node_id, region=region, capacity=max(1, capacity), tags=tags or [])
        self._nodes[node_id] = node
        return node.to_dict()

    def heartbeat(self, node_id: str, healthy: bool = True, active_jobs: Optional[int] = None) -> Optional[Dict[str, Any]]:
        node = self._nodes.get(node_id)
        if node is None:
            return None
        node.healthy = healthy
        if active_jobs is not None:
            node.active_jobs = max(0, active_jobs)
        node.last_heartbeat = datetime.utcnow().isoformat()
        return node.to_dict()

    def list_nodes(self) -> List[Dict[str, Any]]:
        return [n.to_dict() for n in self._nodes.values()]

    def assign_target(
        self,
        target: str,
        replicas: int = 1,
        region_hint: Optional[str] = None,
        required_tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        tags = set(required_tags or [])
        candidates = [
            n for n in self._nodes.values()
            if n.healthy
            and n.active_jobs < n.capacity
            and (region_hint is None or n.region == region_hint)
            and tags.issubset(set(n.tags))
        ]
        if not candidates:
            return {
                "target": target,
                "assigned_nodes": [],
                "replicas": replicas,
                "reason": "No healthy nodes match constraints",
            }

        # Stable assignment seed by target hash for deterministic distribution
        seed = int(hashlib.sha256(target.encode("utf-8")).hexdigest(), 16)
        candidates.sort(key=lambda n: (n.active_jobs / n.capacity, n.node_id))

        selected: List[ScanNode] = []
        for i in range(min(max(1, replicas), len(candidates))):
            idx = (seed + i) % len(candidates)
            node = candidates[idx]
            if node in selected:
                continue
            node.active_jobs += 1
            selected.append(node)

        return {
            "target": target,
            "replicas": replicas,
            "assigned_nodes": [n.to_dict() for n in selected],
            "strategy": "deterministic-hash + utilization-aware",
            "assigned_at": datetime.utcnow().isoformat(),
        }

    def complete_assignment(self, node_id: str) -> bool:
        node = self._nodes.get(node_id)
        if node is None:
            return False
        node.active_jobs = max(0, node.active_jobs - 1)
        node.last_heartbeat = datetime.utcnow().isoformat()
        return True
