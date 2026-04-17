"""In-memory API metrics collector for operational visibility.

This service keeps lightweight counters and latency samples to support
runtime health checks and hardening milestones without external dependencies.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock
from typing import Any


@dataclass(frozen=True)
class _RequestSample:
    """Captured request sample for metric aggregation."""

    latency_ms: float


class MetricsService:
    """Thread-safe in-memory metrics collector."""

    def __init__(self, *, max_latency_samples: int = 5000) -> None:
        self._lock = Lock()
        self._max_latency_samples = max_latency_samples
        self._total_requests = 0
        self._status_class_counts: dict[str, int] = defaultdict(int)
        self._endpoint_counts: dict[str, int] = defaultdict(int)
        self._role_counts: dict[str, int] = defaultdict(int)
        self._latency_samples: deque[_RequestSample] = deque(maxlen=max_latency_samples)

    def record(self, *, endpoint: str, status_code: int, latency_ms: float, role: str | None) -> None:
        """Record one completed API request."""
        status_class = f"{status_code // 100}xx"

        with self._lock:
            self._total_requests += 1
            self._status_class_counts[status_class] += 1
            self._endpoint_counts[endpoint] += 1
            self._role_counts[role or "anonymous"] += 1
            self._latency_samples.append(_RequestSample(latency_ms=max(latency_ms, 0.0)))

    def snapshot(self) -> dict[str, Any]:
        """Return a consistent metrics snapshot."""
        with self._lock:
            samples = [sample.latency_ms for sample in self._latency_samples]
            total = self._total_requests
            status_counts = dict(self._status_class_counts)
            endpoint_counts = dict(self._endpoint_counts)
            role_counts = dict(self._role_counts)

        success = status_counts.get("2xx", 0)
        error_4xx = status_counts.get("4xx", 0)
        error_5xx = status_counts.get("5xx", 0)

        return {
            "total_requests": total,
            "success_count": success,
            "client_error_count": error_4xx,
            "server_error_count": error_5xx,
            "error_rate_5xx": (error_5xx / total) if total else 0.0,
            "latency_ms": {
                "avg": round(sum(samples) / len(samples), 2) if samples else 0.0,
                "p50": self._percentile(samples, 50),
                "p95": self._percentile(samples, 95),
                "p99": self._percentile(samples, 99),
                "count": len(samples),
            },
            "latency_histogram_ms": self._histogram(samples),
            "status_classes": status_counts,
            "requests_by_endpoint": endpoint_counts,
            "requests_by_role": role_counts,
        }

    @staticmethod
    def _percentile(values: list[float], percentile: int) -> float:
        if not values:
            return 0.0
        if len(values) == 1:
            return round(values[0], 2)

        sorted_values = sorted(values)
        rank = (percentile / 100) * (len(sorted_values) - 1)
        lower_idx = int(rank)
        upper_idx = min(lower_idx + 1, len(sorted_values) - 1)

        if lower_idx == upper_idx:
            return round(sorted_values[lower_idx], 2)

        lower_value = sorted_values[lower_idx]
        upper_value = sorted_values[upper_idx]
        fraction = rank - lower_idx
        interpolated = lower_value + (upper_value - lower_value) * fraction
        return round(interpolated, 2)

    @staticmethod
    def _histogram(values: list[float]) -> dict[str, int]:
        buckets = {
            "le_50": 0,
            "le_100": 0,
            "le_250": 0,
            "le_500": 0,
            "le_1000": 0,
            "gt_1000": 0,
        }

        for value in values:
            if value <= 50:
                buckets["le_50"] += 1
            elif value <= 100:
                buckets["le_100"] += 1
            elif value <= 250:
                buckets["le_250"] += 1
            elif value <= 500:
                buckets["le_500"] += 1
            elif value <= 1000:
                buckets["le_1000"] += 1
            else:
                buckets["gt_1000"] += 1

        return buckets
