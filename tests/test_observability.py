from __future__ import annotations

from fastapi.testclient import TestClient

from api.dependencies.auth import get_current_user
from api.dependencies.db import get_db_session
from api.dependencies.observability import get_metrics_service
from api.main import app
from api.schemas import AuthRole, AuthenticatedUser
from api.services.metrics_service import MetricsService


def test_metrics_service_snapshot_counts() -> None:
    service = MetricsService()
    service.record(endpoint="GET /dashboard/summary", status_code=200, latency_ms=110.0, role="CISO")
    service.record(endpoint="GET /dashboard/summary", status_code=429, latency_ms=210.0, role="CISO")
    service.record(endpoint="GET /dashboard/latest-alerts", status_code=500, latency_ms=410.0, role="CISO")

    snapshot = service.snapshot()

    assert snapshot["total_requests"] == 3
    assert snapshot["success_count"] == 1
    assert snapshot["client_error_count"] == 1
    assert snapshot["server_error_count"] == 1
    assert snapshot["latency_ms"]["p95"] >= snapshot["latency_ms"]["p50"]
    assert snapshot["latency_histogram_ms"]["le_250"] >= 1


def test_metrics_endpoint_forbidden_for_management(monkeypatch) -> None:
    client = TestClient(app)
    metrics = MetricsService()

    def _fake_db():
        yield None

    app.dependency_overrides[get_db_session] = _fake_db
    app.dependency_overrides[get_metrics_service] = lambda: metrics
    app.dependency_overrides[get_current_user] = lambda: AuthenticatedUser(
        user_id=10,
        username="manager",
        email="manager@example.com",
        role=AuthRole.MANAJEMEN,
        firebase_uid="firebase-manager",
    )
    monkeypatch.setattr("api.routes.observability.get_settings", lambda: type("S", (), {"metrics_enabled": True})())

    response = client.get("/metrics")

    app.dependency_overrides.clear()

    assert response.status_code == 403


def test_metrics_endpoint_returns_snapshot_for_ciso(monkeypatch) -> None:
    client = TestClient(app)
    metrics = MetricsService()
    metrics.record(endpoint="GET /dashboard/summary", status_code=200, latency_ms=120.0, role="CISO")

    def _fake_db():
        yield None

    app.dependency_overrides[get_db_session] = _fake_db
    app.dependency_overrides[get_metrics_service] = lambda: metrics
    app.dependency_overrides[get_current_user] = lambda: AuthenticatedUser(
        user_id=1,
        username="ciso",
        email="ciso@example.com",
        role=AuthRole.CISO,
        firebase_uid="firebase-ciso",
    )
    monkeypatch.setattr("api.routes.observability.get_settings", lambda: type("S", (), {"metrics_enabled": True})())

    response = client.get("/metrics")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.json()
    assert body["total_requests"] >= 1
    assert "latency_ms" in body
    assert "latency_histogram_ms" in body
    assert "requests_by_endpoint" in body
