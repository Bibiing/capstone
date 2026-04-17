from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi.testclient import TestClient

from api.dependencies.auth import get_current_user
from api.dependencies.dashboard import get_dashboard_rate_limiter, get_dashboard_service
from api.dependencies.db import get_db_session
from api.main import app
from api.schemas import AuthRole, AuthenticatedUser, DashboardMetaResponse, DashboardRiskDistribution, DashboardSummaryData, DashboardSummaryResponse


class _FakeDashboardService:
    def get_summary(self, db, *, request_id: str | None = None) -> DashboardSummaryResponse:
        return DashboardSummaryResponse(
            data=DashboardSummaryData(
                total_assets=1,
                risk_distribution=DashboardRiskDistribution(low=1, medium=0, high=0, critical=0),
            ),
            meta=DashboardMetaResponse(generated_at=datetime.now(timezone.utc), request_id=request_id),
        )


def test_dashboard_rate_limit_returns_429(monkeypatch) -> None:
    client = TestClient(app)

    def _fake_db():
        yield None

    app.dependency_overrides[get_db_session] = _fake_db
    app.dependency_overrides[get_dashboard_service] = lambda: _FakeDashboardService()
    app.dependency_overrides[get_current_user] = lambda: AuthenticatedUser(
        user_id=99,
        username="rate-limit-user",
        email="limit@example.com",
        role=AuthRole.CISO,
        firebase_uid="firebase-uid-limit",
    )

    monkeypatch.setattr(
        "api.dependencies.dashboard.get_settings",
        lambda: SimpleNamespace(
            dashboard_rate_limit_per_minute=1,
            dashboard_rate_limit_window_seconds=60,
        ),
    )

    limiter = get_dashboard_rate_limiter()
    limiter.clear()

    first = client.get("/dashboard/summary")
    second = client.get("/dashboard/summary")

    app.dependency_overrides.clear()
    limiter.clear()

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers.get("Retry-After") is not None
