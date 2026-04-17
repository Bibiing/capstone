from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from api.dependencies.auth import get_current_user
from api.dependencies.dashboard import get_dashboard_service
from api.dependencies.db import get_db_session
from api.main import app
from api.schemas import (
    AuthRole,
    AuthenticatedUser,
    DashboardActivityLogItem,
    DashboardAssetsSortBy,
    DashboardAssetsTableItem,
    DashboardAssetsTableResponse,
    DashboardAssetDetailData,
    DashboardAssetDetailResponse,
    DashboardAssetProfile,
    DashboardAssetSecurityReportData,
    DashboardAssetSecurityReportResponse,
    DashboardLatestAlertItem,
    DashboardLatestAlertsResponse,
    DashboardMetaResponse,
    DashboardRiskLevel,
    DashboardRiskDistribution,
    DashboardRiskHistoryItem,
    DashboardRiskTrendData,
    DashboardRiskTrendPoint,
    DashboardRiskTrendResponse,
    DashboardSortOrder,
    DashboardSecurityAlertItem,
    DashboardRiskSummary,
    DashboardSummaryData,
    DashboardSummaryResponse,
    DashboardTrendPeriod,
    DashboardVulnerabilityItem,
)


class _FakeDashboardService:
    def get_summary(self, db, *, request_id: str | None = None) -> DashboardSummaryResponse:
        return DashboardSummaryResponse(
            data=DashboardSummaryData(
                total_assets=12,
                risk_distribution=DashboardRiskDistribution(low=3, medium=5, high=3, critical=1),
            ),
            meta=DashboardMetaResponse(
                generated_at=datetime.now(timezone.utc),
                request_id=request_id,
            ),
        )

    def get_risk_trend(
        self,
        db,
        *,
        period: DashboardTrendPeriod,
        request_id: str | None = None,
    ) -> DashboardRiskTrendResponse:
        return DashboardRiskTrendResponse(
            data=DashboardRiskTrendData(
                period=period,
                total_points=1,
                points=[
                    DashboardRiskTrendPoint(
                        timestamp=datetime.now(timezone.utc),
                        average_risk=55.5,
                        low_count=1,
                        medium_count=2,
                        high_count=1,
                        critical_count=0,
                        total_samples=4,
                    )
                ],
            ),
            meta=DashboardMetaResponse(
                generated_at=datetime.now(timezone.utc),
                request_id=request_id,
            ),
        )

    def get_latest_alerts(self, db, *, limit: int, request_id: str | None = None) -> DashboardLatestAlertsResponse:
        return DashboardLatestAlertsResponse(
            data=[
                DashboardLatestAlertItem(
                    asset_id="11111111-1111-1111-1111-111111111111",
                    asset_name="core-db",
                    risk_status="High",
                    event_time=datetime.now(timezone.utc),
                    alert_summary="Brute force pattern",
                    rule_level=12,
                )
            ],
            meta=DashboardMetaResponse(
                generated_at=datetime.now(timezone.utc),
                request_id=request_id,
                total_items=1,
            ),
        )

    def get_assets_table(
        self,
        db,
        *,
        page: int,
        page_size: int,
        sort_by: DashboardAssetsSortBy,
        sort_order: DashboardSortOrder,
        asset_status: str | None,
        risk_level: DashboardRiskLevel | None,
        request_id: str | None = None,
    ) -> DashboardAssetsTableResponse:
        return DashboardAssetsTableResponse(
            data=[
                DashboardAssetsTableItem(
                    asset_id="11111111-1111-1111-1111-111111111111",
                    asset_name="core-db",
                    asset_type="database",
                    risk_score=82.2,
                    risk_status="High",
                    status="active",
                    last_updated=datetime.now(timezone.utc),
                )
            ],
            meta=DashboardMetaResponse(
                generated_at=datetime.now(timezone.utc),
                request_id=request_id,
                page=page,
                page_size=page_size,
                total_items=1,
                total_pages=1,
            ),
        )

    def get_asset_detail(self, db, *, asset_id, request_id: str | None = None) -> DashboardAssetDetailResponse:
        now = datetime.now(timezone.utc)
        return DashboardAssetDetailResponse(
            data=DashboardAssetDetailData(
                asset_profile=DashboardAssetProfile(
                    asset_id=str(asset_id),
                    asset_name="core-db",
                    asset_type="database",
                    asset_status="active",
                    ip_address="10.0.0.10",
                    last_updated=now,
                ),
                risk_summary=DashboardRiskSummary(
                    current_risk_score=82.2,
                    risk_status="High",
                    risk_description="Risk is high; prioritize remediation.",
                    impact_score=0.8,
                    vulnerability_score=66.4,
                    threat_score=72.0,
                ),
                vulnerabilities=[
                    DashboardVulnerabilityItem(
                        name="Current vulnerability posture",
                        score=66.4,
                        status="High",
                        detail="Derived from the latest SCA snapshot.",
                    )
                ],
                security_alerts=[
                    DashboardSecurityAlertItem(
                        event_time=now,
                        rule_level=12,
                        rule_id="5710",
                        description="Brute force pattern",
                    )
                ],
                activity_log=[
                    DashboardActivityLogItem(
                        event_time=now,
                        activity_type="manual-review",
                        activity_detail="Security team reviewed alert.",
                    )
                ],
                last_updated=now,
            ),
            meta=DashboardMetaResponse(
                generated_at=now,
                request_id=request_id,
            ),
        )

    def get_asset_security_report(self, db, *, asset_id, request_id: str | None = None) -> DashboardAssetSecurityReportResponse:
        now = datetime.now(timezone.utc)
        return DashboardAssetSecurityReportResponse(
            data=DashboardAssetSecurityReportData(
                asset_profile=DashboardAssetProfile(
                    asset_id=str(asset_id),
                    asset_name="core-db",
                    asset_type="database",
                    asset_status="active",
                    ip_address="10.0.0.10",
                    last_updated=now,
                ),
                risk_summary=DashboardRiskSummary(
                    current_risk_score=82.2,
                    risk_status="High",
                    risk_description="Risk is high; prioritize remediation.",
                    impact_score=0.8,
                    vulnerability_score=66.4,
                    threat_score=72.0,
                ),
                risk_history_7d=[
                    DashboardRiskHistoryItem(
                        date=now,
                        risk_score=82.2,
                        status="High",
                        detail="Impact 0.80, Vulnerability 66.40, Threat 72.00",
                    )
                ],
                vulnerabilities=[
                    DashboardVulnerabilityItem(
                        name="Current vulnerability posture",
                        score=66.4,
                        status="High",
                        detail="Derived from the latest SCA snapshot.",
                    )
                ],
                security_alerts=[
                    DashboardSecurityAlertItem(
                        event_time=now,
                        rule_level=12,
                        rule_id="5710",
                        description="Brute force pattern",
                    )
                ],
            ),
            meta=DashboardMetaResponse(
                generated_at=now,
                request_id=request_id,
            ),
        )


@pytest.fixture
def dashboard_client():
    client = TestClient(app)

    def _fake_db():
        yield None

    app.dependency_overrides[get_db_session] = _fake_db
    app.dependency_overrides[get_dashboard_service] = lambda: _FakeDashboardService()

    yield client
    app.dependency_overrides.clear()


def _override_user(role: AuthRole):
    return lambda: AuthenticatedUser(
        user_id=1,
        username="dashboard-user",
        email="dashboard@example.com",
        role=role,
        firebase_uid="firebase-uid-dashboard",
    )


def test_dashboard_summary_requires_auth() -> None:
    client = TestClient(app)
    response = client.get("/dashboard/summary")
    assert response.status_code == 401


@pytest.mark.parametrize("role", [AuthRole.CISO, AuthRole.MANAJEMEN])
def test_dashboard_summary_allows_ciso_and_management(dashboard_client: TestClient, role: AuthRole) -> None:
    app.dependency_overrides[get_current_user] = _override_user(role)

    response = dashboard_client.get("/dashboard/summary")

    assert response.status_code == 200
    body = response.json()
    assert body["data"]["total_assets"] == 12
    assert set(body["data"]["risk_distribution"].keys()) == {"low", "medium", "high", "critical"}
    assert "meta" in body


@pytest.mark.parametrize("period", ["daily", "weekly", "monthly", "yearly"])
def test_dashboard_risk_trend_shape(dashboard_client: TestClient, period: str) -> None:
    app.dependency_overrides[get_current_user] = _override_user(AuthRole.MANAJEMEN)

    response = dashboard_client.get(f"/dashboard/risk-trend?period={period}")

    assert response.status_code == 200
    body = response.json()
    assert body["data"]["period"] == period
    assert isinstance(body["data"]["points"], list)
    assert "average_risk" in body["data"]["points"][0]


def test_dashboard_latest_alerts_forbidden_for_management(dashboard_client: TestClient) -> None:
    app.dependency_overrides[get_current_user] = _override_user(AuthRole.MANAJEMEN)

    response = dashboard_client.get("/dashboard/latest-alerts")

    assert response.status_code == 403


def test_dashboard_latest_alerts_allows_ciso(dashboard_client: TestClient) -> None:
    app.dependency_overrides[get_current_user] = _override_user(AuthRole.CISO)

    response = dashboard_client.get("/dashboard/latest-alerts?limit=10")

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body["data"], list)
    assert body["data"][0]["asset_name"] == "core-db"


def test_dashboard_assets_table_forbidden_for_management(dashboard_client: TestClient) -> None:
    app.dependency_overrides[get_current_user] = _override_user(AuthRole.MANAJEMEN)

    response = dashboard_client.get("/dashboard/assets-table")

    assert response.status_code == 403


def test_dashboard_assets_table_supports_pagination_and_sorting_for_ciso(dashboard_client: TestClient) -> None:
    app.dependency_overrides[get_current_user] = _override_user(AuthRole.CISO)

    response = dashboard_client.get(
        "/dashboard/assets-table?page=1&page_size=20&sort_by=risk_score&order=desc&risk_level=high"
    )

    assert response.status_code == 200
    body = response.json()
    assert body["meta"]["page"] == 1
    assert body["meta"]["page_size"] == 20
    assert body["data"][0]["risk_status"] == "High"


def test_dashboard_assets_table_validation_errors(dashboard_client: TestClient) -> None:
    app.dependency_overrides[get_current_user] = _override_user(AuthRole.CISO)

    response = dashboard_client.get("/dashboard/assets-table?page=0&page_size=500")

    assert response.status_code == 422


def test_dashboard_asset_detail_forbidden_for_management(dashboard_client: TestClient) -> None:
    app.dependency_overrides[get_current_user] = _override_user(AuthRole.MANAJEMEN)

    response = dashboard_client.get("/dashboard/assets/11111111-1111-1111-1111-111111111111/detail")

    assert response.status_code == 403


def test_dashboard_asset_detail_valid_for_ciso(dashboard_client: TestClient) -> None:
    app.dependency_overrides[get_current_user] = _override_user(AuthRole.CISO)

    response = dashboard_client.get("/dashboard/assets/11111111-1111-1111-1111-111111111111/detail")

    assert response.status_code == 200
    body = response.json()
    assert body["data"]["asset_profile"]["asset_name"] == "core-db"
    assert body["data"]["risk_summary"]["risk_status"] == "High"
    assert isinstance(body["data"]["activity_log"], list)


def test_dashboard_asset_detail_invalid_uuid(dashboard_client: TestClient) -> None:
    app.dependency_overrides[get_current_user] = _override_user(AuthRole.CISO)

    response = dashboard_client.get("/dashboard/assets/not-a-uuid/detail")

    assert response.status_code == 400


def test_dashboard_asset_security_report_forbidden_for_management(dashboard_client: TestClient) -> None:
    app.dependency_overrides[get_current_user] = _override_user(AuthRole.MANAJEMEN)

    response = dashboard_client.get("/dashboard/assets/11111111-1111-1111-1111-111111111111/security-report")

    assert response.status_code == 403


def test_dashboard_asset_security_report_valid_for_ciso(dashboard_client: TestClient) -> None:
    app.dependency_overrides[get_current_user] = _override_user(AuthRole.CISO)

    response = dashboard_client.get("/dashboard/assets/11111111-1111-1111-1111-111111111111/security-report")

    assert response.status_code == 200
    body = response.json()
    assert body["data"]["risk_summary"]["risk_status"] == "High"
    assert isinstance(body["data"]["risk_history_7d"], list)


def test_dashboard_asset_detail_not_found_returns_404(dashboard_client: TestClient) -> None:
    class _NotFoundService(_FakeDashboardService):
        def get_asset_detail(self, db, *, asset_id, request_id: str | None = None):
            raise ValueError(f"Asset '{asset_id}' not found")

    app.dependency_overrides[get_current_user] = _override_user(AuthRole.CISO)
    app.dependency_overrides[get_dashboard_service] = lambda: _NotFoundService()

    response = dashboard_client.get("/dashboard/assets/11111111-1111-1111-1111-111111111111/detail")

    assert response.status_code == 404
