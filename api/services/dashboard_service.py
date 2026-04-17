"""Dashboard orchestration service.

Phase 1 scope:
- summary cards (total assets + risk distribution)
- risk trend chart with daily/weekly/monthly/yearly period buckets
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

from sqlalchemy.orm import Session

from api.schemas import (
    DashboardAssetsSortBy,
    DashboardAssetsTableItem,
    DashboardAssetsTableResponse,
    DashboardAssetDetailData,
    DashboardAssetDetailResponse,
    DashboardAssetProfile,
    DashboardAssetSecurityReportData,
    DashboardAssetSecurityReportResponse,
    DashboardActivityLogItem,
    DashboardMetaResponse,
    DashboardLatestAlertItem,
    DashboardLatestAlertsResponse,
    DashboardRiskDistribution,
    DashboardRiskLevel,
    DashboardRiskHistoryItem,
    DashboardRiskSummary,
    DashboardRiskTrendData,
    DashboardRiskTrendPoint,
    DashboardRiskTrendResponse,
    DashboardSortOrder,
    DashboardSecurityAlertItem,
    DashboardSummaryData,
    DashboardSummaryResponse,
    DashboardVulnerabilityItem,
    DashboardTrendPeriod,
)
from api.services.scoring_engine import classify_severity
from database.repositories.dashboard_repository import DashboardRepository


@dataclass(frozen=True)
class _BucketSpec:
    lookback: timedelta
    normalize: Callable[[datetime], datetime]


class DashboardService:
    """Service layer for dashboard read APIs."""

    def __init__(self, repository: DashboardRepository | None = None) -> None:
        self._repo = repository or DashboardRepository()

    def get_summary(self, db: Session, *, request_id: str | None = None) -> DashboardSummaryResponse:
        """Build dashboard summary cards from latest asset risk snapshots."""
        total_assets = self._repo.get_total_assets(db)
        latest_scores = self._repo.get_latest_risk_scores(db)

        distribution = self._build_distribution(latest_scores)
        return DashboardSummaryResponse(
            data=DashboardSummaryData(
                total_assets=total_assets,
                risk_distribution=distribution,
            ),
            meta=DashboardMetaResponse(
                generated_at=datetime.now(timezone.utc),
                request_id=request_id,
            ),
        )

    def get_risk_trend(
        self,
        db: Session,
        *,
        period: DashboardTrendPeriod,
        request_id: str | None = None,
    ) -> DashboardRiskTrendResponse:
        """Build aggregated trend line data for dashboard charts."""
        spec = self._get_bucket_spec(period)
        since = datetime.now(timezone.utc) - spec.lookback

        samples = self._repo.get_risk_samples_since(db, since=since)
        points = self._build_trend_points(samples=samples, normalize=spec.normalize)

        return DashboardRiskTrendResponse(
            data=DashboardRiskTrendData(
                period=period,
                total_points=len(points),
                points=points,
            ),
            meta=DashboardMetaResponse(
                generated_at=datetime.now(timezone.utc),
                request_id=request_id,
            ),
        )

    def get_latest_alerts(
        self,
        db: Session,
        *,
        limit: int,
        request_id: str | None = None,
    ) -> DashboardLatestAlertsResponse:
        """Return latest alerts feed enriched with current risk status."""
        rows = self._repo.get_latest_alert_rows(db, limit=limit)
        asset_ids = [row[0] for row in rows]
        latest_score_map = self._repo.get_latest_score_map(db, asset_ids)

        items: list[DashboardLatestAlertItem] = []
        for asset_id, asset_name, rule_level, description, event_time in rows:
            score = latest_score_map.get(asset_id)
            if score is None:
                risk_status = self._classify_from_rule_level(rule_level)
            else:
                risk_status = classify_severity(score)

            items.append(
                DashboardLatestAlertItem(
                    asset_id=str(asset_id),
                    asset_name=asset_name,
                    risk_status=risk_status,
                    event_time=event_time,
                    alert_summary=description,
                    rule_level=rule_level,
                )
            )

        return DashboardLatestAlertsResponse(
            data=items,
            meta=DashboardMetaResponse(
                generated_at=datetime.now(timezone.utc),
                request_id=request_id,
                total_items=len(items),
            ),
        )

    def get_assets_table(
        self,
        db: Session,
        *,
        page: int,
        page_size: int,
        sort_by: DashboardAssetsSortBy,
        sort_order: DashboardSortOrder,
        asset_status: str | None,
        risk_level: DashboardRiskLevel | None,
        request_id: str | None = None,
    ) -> DashboardAssetsTableResponse:
        """Return paginated dashboard assets table rows."""
        rows, total_items = self._repo.get_assets_table_rows(
            db,
            page=page,
            page_size=page_size,
            sort_by=sort_by.value,
            sort_order=sort_order.value,
            asset_status=asset_status,
            risk_bounds=self._risk_bounds(risk_level),
        )

        items = [
            DashboardAssetsTableItem(
                asset_id=str(asset_id),
                asset_name=asset_name,
                asset_type=asset_type,
                risk_score=round(score_r, 2) if score_r is not None else None,
                risk_status=classify_severity(score_r) if score_r is not None else "Unknown",
                status=status,
                last_updated=last_score_at or updated_at,
            )
            for asset_id, asset_name, asset_type, status, updated_at, score_r, last_score_at in rows
        ]

        total_pages = (total_items + page_size - 1) // page_size if total_items > 0 else 0

        return DashboardAssetsTableResponse(
            data=items,
            meta=DashboardMetaResponse(
                generated_at=datetime.now(timezone.utc),
                request_id=request_id,
                page=page,
                page_size=page_size,
                total_items=total_items,
                total_pages=total_pages,
            ),
        )

    def get_asset_detail(
        self,
        db: Session,
        *,
        asset_id,
        request_id: str | None = None,
    ) -> DashboardAssetDetailResponse:
        """Return detailed asset information for the dashboard popup."""
        asset = self._repo.get_asset_by_id(db, asset_id)
        if asset is None:
            raise ValueError(f"Asset '{asset_id}' not found")

        latest = self._repo.get_latest_score_row(db, asset_id)
        if latest is None:
            raise ValueError(f"No score data found for asset '{asset_id}'")

        last_updated = latest.calculated_at
        return DashboardAssetDetailResponse(
            data=DashboardAssetDetailData(
                asset_profile=self._build_asset_profile(asset=asset, last_updated=last_updated),
                risk_summary=self._build_risk_summary(latest),
                vulnerabilities=self._build_vulnerabilities(latest),
                security_alerts=self._build_security_alerts(
                    self._repo.get_security_alert_rows(db, asset_id, limit=10)
                ),
                activity_log=self._build_activity_logs(
                    self._repo.get_activity_log_rows(db, asset_id, limit=10)
                ),
                last_updated=last_updated,
            ),
            meta=DashboardMetaResponse(
                generated_at=datetime.now(timezone.utc),
                request_id=request_id,
            ),
        )

    def get_asset_security_report(
        self,
        db: Session,
        *,
        asset_id,
        request_id: str | None = None,
    ) -> DashboardAssetSecurityReportResponse:
        """Return detailed security report for a single asset."""
        asset = self._repo.get_asset_by_id(db, asset_id)
        if asset is None:
            raise ValueError(f"Asset '{asset_id}' not found")

        latest = self._repo.get_latest_score_row(db, asset_id)
        if latest is None:
            raise ValueError(f"No score data found for asset '{asset_id}'")

        since = datetime.now(timezone.utc) - timedelta(days=7)
        history_rows = self._repo.get_risk_history_since(db, asset_id, since)

        return DashboardAssetSecurityReportResponse(
            data=DashboardAssetSecurityReportData(
                asset_profile=self._build_asset_profile(asset=asset, last_updated=latest.calculated_at),
                risk_summary=self._build_risk_summary(latest),
                risk_history_7d=self._build_risk_history(history_rows),
                vulnerabilities=self._build_vulnerabilities(latest),
                security_alerts=self._build_security_alerts(
                    self._repo.get_security_alert_rows(db, asset_id, limit=20)
                ),
            ),
            meta=DashboardMetaResponse(
                generated_at=datetime.now(timezone.utc),
                request_id=request_id,
            ),
        )

    @staticmethod
    def _build_distribution(scores: list[float]) -> DashboardRiskDistribution:
        distribution = DashboardRiskDistribution(low=0, medium=0, high=0, critical=0)
        for score in scores:
            severity = classify_severity(score)
            if severity == "Low":
                distribution.low += 1
            elif severity == "Medium":
                distribution.medium += 1
            elif severity == "High":
                distribution.high += 1
            else:
                distribution.critical += 1
        return distribution

    @staticmethod
    def _build_trend_points(
        *,
        samples: list[tuple[datetime, float]],
        normalize: Callable[[datetime], datetime],
    ) -> list[DashboardRiskTrendPoint]:
        grouped_scores: dict[datetime, list[float]] = defaultdict(list)
        severity_counts: dict[datetime, dict[str, int]] = defaultdict(lambda: {"Low": 0, "Medium": 0, "High": 0, "Critical": 0})

        for ts, score in samples:
            bucket_key = normalize(ts)
            grouped_scores[bucket_key].append(score)
            severity = classify_severity(score)
            severity_counts[bucket_key][severity] += 1

        points: list[DashboardRiskTrendPoint] = []
        for timestamp in sorted(grouped_scores.keys()):
            scores = grouped_scores[timestamp]
            counts = severity_counts[timestamp]
            points.append(
                DashboardRiskTrendPoint(
                    timestamp=timestamp,
                    average_risk=round(sum(scores) / len(scores), 2),
                    low_count=counts["Low"],
                    medium_count=counts["Medium"],
                    high_count=counts["High"],
                    critical_count=counts["Critical"],
                    total_samples=len(scores),
                )
            )

        return points

    @staticmethod
    def _get_bucket_spec(period: DashboardTrendPeriod) -> _BucketSpec:
        if period == DashboardTrendPeriod.DAILY:
            return _BucketSpec(
                lookback=timedelta(hours=24),
                normalize=lambda dt: dt.replace(minute=0, second=0, microsecond=0),
            )
        if period == DashboardTrendPeriod.WEEKLY:
            return _BucketSpec(
                lookback=timedelta(days=7),
                normalize=lambda dt: dt.replace(hour=0, minute=0, second=0, microsecond=0),
            )
        if period == DashboardTrendPeriod.MONTHLY:
            return _BucketSpec(
                lookback=timedelta(days=30),
                normalize=lambda dt: dt.replace(hour=0, minute=0, second=0, microsecond=0),
            )
        return _BucketSpec(
            lookback=timedelta(days=365),
            normalize=lambda dt: dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0),
        )

    @staticmethod
    def _risk_bounds(level: DashboardRiskLevel | None) -> tuple[float, float] | None:
        if level is None:
            return None
        if level == DashboardRiskLevel.LOW:
            return (0.0, 40.0)
        if level == DashboardRiskLevel.MEDIUM:
            return (40.0, 70.0)
        if level == DashboardRiskLevel.HIGH:
            return (70.0, 90.0)
        return (90.0, 101.0)

    @staticmethod
    def _classify_from_rule_level(rule_level: int) -> str:
        if rule_level >= 12:
            return "High"
        if rule_level >= 5:
            return "Medium"
        return "Low"

    @staticmethod
    def _build_asset_profile(asset, *, last_updated: datetime) -> DashboardAssetProfile:
        return DashboardAssetProfile(
            asset_id=str(asset.id),
            asset_name=asset.name,
            asset_type=asset.asset_type,
            asset_status=asset.status,
            ip_address=asset.ip_address,
            last_updated=last_updated,
        )

    @staticmethod
    def _build_risk_summary(latest) -> DashboardRiskSummary:
        score_status = classify_severity(latest.score_r)
        return DashboardRiskSummary(
            current_risk_score=round(latest.score_r, 2),
            risk_status=score_status,
            risk_description=DashboardService._describe_risk(score_status),
            impact_score=latest.score_i,
            vulnerability_score=latest.score_v,
            threat_score=latest.score_t,
        )

    @staticmethod
    def _build_vulnerabilities(latest) -> list[DashboardVulnerabilityItem]:
        return [
            DashboardVulnerabilityItem(
                name="Current vulnerability posture",
                score=round(latest.score_v, 2),
                status=classify_severity(latest.score_v),
                detail="Derived from the latest SCA snapshot.",
            ),
            DashboardVulnerabilityItem(
                name="Threat pressure",
                score=round(latest.score_t, 2),
                status=classify_severity(latest.score_t),
                detail="Derived from recent alert activity and time decay.",
            ),
        ]

    @staticmethod
    def _build_security_alerts(rows: list[tuple]) -> list[DashboardSecurityAlertItem]:
        return [
            DashboardSecurityAlertItem(
                event_time=row[0],
                rule_level=row[1],
                rule_id=row[2],
                description=row[3],
            )
            for row in rows
        ]

    @staticmethod
    def _build_activity_logs(rows: list[tuple]) -> list[DashboardActivityLogItem]:
        return [
            DashboardActivityLogItem(
                event_time=row[0],
                activity_type=row[1],
                activity_detail=row[2],
            )
            for row in rows
        ]

    @staticmethod
    def _build_risk_history(rows) -> list[DashboardRiskHistoryItem]:
        return [
            DashboardRiskHistoryItem(
                date=row.calculated_at,
                risk_score=round(row.score_r, 2),
                status=classify_severity(row.score_r),
                detail=(
                    f"Impact {row.score_i:.2f}, Vulnerability {row.score_v:.2f}, Threat {row.score_t:.2f}"
                ),
            )
            for row in rows
        ]

    @staticmethod
    def _describe_risk(status: str) -> str:
        return {
            "Low": "Risk is currently low and does not require immediate action.",
            "Medium": "Risk is moderate; monitor and plan mitigation.",
            "High": "Risk is high; prioritize remediation.",
            "Critical": "Risk is critical; immediate mitigation is required.",
        }.get(status, "Risk status unavailable.")
