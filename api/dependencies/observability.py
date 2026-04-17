"""Dependency wiring for observability services."""

from api.services.metrics_service import MetricsService

_metrics_service = MetricsService()


def get_metrics_service() -> MetricsService:
    """Return singleton metrics service."""
    return _metrics_service
