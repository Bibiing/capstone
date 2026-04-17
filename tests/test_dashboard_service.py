from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from api.schemas import DashboardAssetsSortBy, DashboardRiskLevel, DashboardSortOrder, DashboardTrendPeriod
from api.services.dashboard_service import DashboardService


class _FakeDashboardRepository:
    def __init__(self, total_assets: int, latest_scores: list[float], samples: list[tuple[datetime, float]]):
        self._total_assets = total_assets
        self._latest_scores = latest_scores
        self._samples = samples
        self._latest_alert_rows = []
        self._latest_score_map = {}
        self._assets_table_rows = []
        self._assets_table_total = 0
        self._asset = None
        self._latest_score_row = None
        self._security_alert_rows = []
        self._activity_log_rows = []
        self._risk_history_rows = []

    def get_total_assets(self, db):
        return self._total_assets

    def get_latest_risk_scores(self, db):
        return self._latest_scores

    def get_risk_samples_since(self, db, since):
        return self._samples

    def get_latest_alert_rows(self, db, *, limit: int):
        return self._latest_alert_rows[:limit]

    def get_latest_score_map(self, db, asset_ids):
        return self._latest_score_map

    def get_assets_table_rows(self, db, **kwargs):
        return self._assets_table_rows, self._assets_table_total

    def get_asset_by_id(self, db, asset_id):
        return self._asset

    def get_latest_score_row(self, db, asset_id):
        return self._latest_score_row

    def get_security_alert_rows(self, db, asset_id, *, limit: int = 10):
        return self._security_alert_rows[:limit]

    def get_activity_log_rows(self, db, asset_id, *, limit: int = 10):
        return self._activity_log_rows[:limit]

    def get_risk_history_since(self, db, asset_id, since):
        return self._risk_history_rows


def test_dashboard_summary_distribution_counts() -> None:
    repo = _FakeDashboardRepository(
        total_assets=4,
        latest_scores=[20.0, 50.0, 80.0, 95.0],
        samples=[],
    )
    service = DashboardService(repository=repo)

    response = service.get_summary(db=None, request_id="req-summary")

    assert response.data.total_assets == 4
    assert response.data.risk_distribution.low == 1
    assert response.data.risk_distribution.medium == 1
    assert response.data.risk_distribution.high == 1
    assert response.data.risk_distribution.critical == 1
    assert response.meta.request_id == "req-summary"


def test_dashboard_trend_monthly_bucketing() -> None:
    samples = [
        (datetime(2026, 4, 1, 8, 0, tzinfo=timezone.utc), 30.0),
        (datetime(2026, 4, 1, 14, 0, tzinfo=timezone.utc), 50.0),
        (datetime(2026, 4, 2, 10, 0, tzinfo=timezone.utc), 90.0),
    ]
    repo = _FakeDashboardRepository(total_assets=2, latest_scores=[40.0, 60.0], samples=samples)
    service = DashboardService(repository=repo)

    response = service.get_risk_trend(db=None, period=DashboardTrendPeriod.MONTHLY, request_id="req-trend")

    assert response.data.period == DashboardTrendPeriod.MONTHLY
    assert response.data.total_points == 2
    assert response.data.points[0].average_risk == 40.0
    assert response.data.points[0].low_count == 1
    assert response.data.points[0].medium_count == 1
    assert response.data.points[1].average_risk == 90.0
    assert response.data.points[1].critical_count == 1
    assert response.meta.request_id == "req-trend"


def test_dashboard_latest_alerts_uses_latest_score_status() -> None:
    repo = _FakeDashboardRepository(total_assets=0, latest_scores=[], samples=[])
    asset_id = "asset-1"
    repo._latest_alert_rows = [
        (asset_id, "core-db", 10, "Suspicious auth activity", datetime(2026, 4, 17, 10, 0, tzinfo=timezone.utc))
    ]
    repo._latest_score_map = {asset_id: 91.0}
    service = DashboardService(repository=repo)

    response = service.get_latest_alerts(db=None, limit=20, request_id="req-alert")

    assert len(response.data) == 1
    assert response.data[0].risk_status == "Critical"
    assert response.meta.request_id == "req-alert"


def test_dashboard_assets_table_sets_pagination_meta() -> None:
    repo = _FakeDashboardRepository(total_assets=0, latest_scores=[], samples=[])
    repo._assets_table_rows = [
        (
            "asset-1",
            "core-db",
            "database",
            "active",
            datetime(2026, 4, 17, 8, 0, tzinfo=timezone.utc),
            82.5,
            datetime(2026, 4, 17, 9, 0, tzinfo=timezone.utc),
        )
    ]
    repo._assets_table_total = 9
    service = DashboardService(repository=repo)

    response = service.get_assets_table(
        db=None,
        page=2,
        page_size=4,
        sort_by=DashboardAssetsSortBy.RISK_SCORE,
        sort_order=DashboardSortOrder.DESC,
        asset_status="active",
        risk_level=DashboardRiskLevel.HIGH,
        request_id="req-table",
    )

    assert len(response.data) == 1
    assert response.data[0].risk_status == "High"
    assert response.meta.page == 2
    assert response.meta.page_size == 4
    assert response.meta.total_items == 9
    assert response.meta.total_pages == 3


def test_dashboard_asset_detail_builds_report_contract() -> None:
    repo = _FakeDashboardRepository(total_assets=0, latest_scores=[], samples=[])
    now = datetime(2026, 4, 17, 10, 0, tzinfo=timezone.utc)
    repo._asset = SimpleNamespace(
        id="asset-1",
        name="core-db",
        asset_type="database",
        status="active",
        ip_address="10.0.0.10",
        updated_at=now,
    )
    repo._latest_score_row = SimpleNamespace(
        score_i=0.8,
        score_v=66.4,
        score_t=72.0,
        score_r=82.2,
        calculated_at=now,
    )
    repo._security_alert_rows = [(now, 12, "5710", "Brute force pattern")]
    repo._activity_log_rows = [(now, "manual-review", "Security team reviewed alert.")]
    service = DashboardService(repository=repo)

    response = service.get_asset_detail(db=None, asset_id="asset-1", request_id="req-detail")

    assert response.data.asset_profile.asset_name == "core-db"
    assert response.data.risk_summary.risk_status == "High"
    assert response.data.vulnerabilities[0].name == "Current vulnerability posture"
    assert response.data.activity_log[0].activity_type == "manual-review"
    assert response.meta.request_id == "req-detail"


def test_dashboard_asset_security_report_builds_7d_history() -> None:
    repo = _FakeDashboardRepository(total_assets=0, latest_scores=[], samples=[])
    now = datetime(2026, 4, 17, 10, 0, tzinfo=timezone.utc)
    repo._asset = SimpleNamespace(
        id="asset-1",
        name="core-db",
        asset_type="database",
        status="active",
        ip_address="10.0.0.10",
        updated_at=now,
    )
    repo._latest_score_row = SimpleNamespace(
        score_i=0.8,
        score_v=66.4,
        score_t=72.0,
        score_r=82.2,
        calculated_at=now,
    )
    repo._risk_history_rows = [
        SimpleNamespace(
            calculated_at=now,
            score_i=0.8,
            score_v=66.4,
            score_t=72.0,
            score_r=82.2,
        )
    ]
    repo._security_alert_rows = [(now, 12, "5710", "Brute force pattern")]
    service = DashboardService(repository=repo)

    response = service.get_asset_security_report(db=None, asset_id="asset-1", request_id="req-report")

    assert response.data.asset_profile.asset_name == "core-db"
    assert response.data.risk_history_7d[0].status == "High"
    assert response.data.security_alerts[0].rule_id == "5710"
    assert response.meta.request_id == "req-report"


def test_dashboard_asset_detail_missing_asset_raises_value_error() -> None:
    repo = _FakeDashboardRepository(total_assets=0, latest_scores=[], samples=[])
    repo._latest_score_row = None
    service = DashboardService(repository=repo)

    try:
        service.get_asset_detail(db=None, asset_id="asset-1")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "not found" in str(exc)
