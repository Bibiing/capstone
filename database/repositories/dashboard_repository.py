"""Repository for dashboard-focused read models.

This module keeps dashboard aggregation queries isolated from route/service code
so they are easy to test and optimize independently.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from database.models import AlertSnapshot, Asset, AssetActivityLog, RiskScore


class DashboardRepository:
    """Read-only data access for dashboard endpoints."""

    def get_asset_by_id(self, db: Session, asset_id) -> Asset | None:
        """Return one asset by primary key."""
        return db.get(Asset, asset_id)

    def get_total_assets(self, db: Session) -> int:
        """Return total distinct assets that have score snapshots."""
        count = db.execute(select(func.count(func.distinct(RiskScore.asset_id)))).scalar_one()
        return int(count or 0)

    def get_latest_risk_scores(self, db: Session) -> list[float]:
        """Return latest score_r for each asset."""
        latest_subquery = (
            select(
                RiskScore.asset_id,
                func.max(RiskScore.calculated_at).label("max_calculated_at"),
            )
            .group_by(RiskScore.asset_id)
            .subquery()
        )

        rows = db.execute(
            select(RiskScore.score_r)
            .join(
                latest_subquery,
                (RiskScore.asset_id == latest_subquery.c.asset_id)
                & (RiskScore.calculated_at == latest_subquery.c.max_calculated_at),
            )
        ).all()

        return [float(row[0]) for row in rows]

    def get_latest_score_row(self, db: Session, asset_id) -> RiskScore | None:
        """Return the latest score row for one asset."""
        return db.execute(
            select(RiskScore)
            .where(RiskScore.asset_id == asset_id)
            .order_by(desc(RiskScore.calculated_at))
            .limit(1)
        ).scalar_one_or_none()

    def get_risk_history_since(self, db: Session, asset_id, since: datetime) -> list[RiskScore]:
        """Return historical risk score rows for one asset within a lookback window."""
        return list(
            db.execute(
                select(RiskScore)
                .where(RiskScore.asset_id == asset_id, RiskScore.calculated_at >= since)
                .order_by(RiskScore.calculated_at.asc())
            )
            .scalars()
            .all()
        )

    def get_risk_samples_since(self, db: Session, since: datetime) -> list[tuple[datetime, float]]:
        """Return (timestamp, score_r) samples within a lookback window."""
        rows = db.execute(
            select(RiskScore.calculated_at, RiskScore.score_r)
            .where(RiskScore.calculated_at >= since)
            .order_by(RiskScore.calculated_at.asc())
        ).all()
        return [(row[0], float(row[1])) for row in rows]

    def get_latest_alert_rows(self, db: Session, *, limit: int) -> list[tuple]:
        """Return latest alert snapshots enriched with asset identity."""
        rows = db.execute(
            select(
                AlertSnapshot.asset_id,
                Asset.name,
                AlertSnapshot.rule_level,
                AlertSnapshot.description,
                AlertSnapshot.event_time,
            )
            .join(Asset, Asset.id == AlertSnapshot.asset_id)
            .order_by(desc(AlertSnapshot.event_time))
            .limit(limit)
        ).all()
        return list(rows)

    def get_security_alert_rows(self, db: Session, asset_id, *, limit: int = 10) -> list[tuple]:
        """Return security alert snapshots for one asset."""
        rows = db.execute(
            select(
                AlertSnapshot.event_time,
                AlertSnapshot.rule_level,
                AlertSnapshot.rule_id,
                AlertSnapshot.description,
            )
            .where(AlertSnapshot.asset_id == asset_id)
            .order_by(desc(AlertSnapshot.event_time))
            .limit(limit)
        ).all()
        return list(rows)

    def get_activity_log_rows(self, db: Session, asset_id, *, limit: int = 10) -> list[tuple]:
        """Return activity log rows for one asset."""
        rows = db.execute(
            select(
                AssetActivityLog.event_time,
                AssetActivityLog.activity_type,
                AssetActivityLog.activity_detail,
            )
            .where(AssetActivityLog.asset_id == asset_id)
            .order_by(desc(AssetActivityLog.event_time))
            .limit(limit)
        ).all()
        return list(rows)

    def get_latest_score_map(self, db: Session, asset_ids: list) -> dict:
        """Return latest score per asset_id for a set of assets."""
        if not asset_ids:
            return {}

        latest_subquery = (
            select(
                RiskScore.asset_id,
                func.max(RiskScore.calculated_at).label("max_calculated_at"),
            )
            .where(RiskScore.asset_id.in_(asset_ids))
            .group_by(RiskScore.asset_id)
            .subquery()
        )

        rows = db.execute(
            select(RiskScore.asset_id, RiskScore.score_r)
            .join(
                latest_subquery,
                (RiskScore.asset_id == latest_subquery.c.asset_id)
                & (RiskScore.calculated_at == latest_subquery.c.max_calculated_at),
            )
        ).all()

        return {row[0]: float(row[1]) for row in rows}

    def get_assets_table_rows(
        self,
        db: Session,
        *,
        page: int,
        page_size: int,
        sort_by,
        sort_order,
        asset_status: str | None,
        risk_bounds: tuple[float, float] | None,
    ) -> tuple[list[tuple], int]:
        """Return paginated asset table rows with latest risk score."""
        latest_ts_subquery = (
            select(
                RiskScore.asset_id,
                func.max(RiskScore.calculated_at).label("max_calculated_at"),
            )
            .group_by(RiskScore.asset_id)
            .subquery()
        )

        latest_score_subquery = (
            select(
                RiskScore.asset_id.label("asset_id"),
                RiskScore.score_r.label("score_r"),
                RiskScore.calculated_at.label("calculated_at"),
            )
            .join(
                latest_ts_subquery,
                (RiskScore.asset_id == latest_ts_subquery.c.asset_id)
                & (RiskScore.calculated_at == latest_ts_subquery.c.max_calculated_at),
            )
            .subquery()
        )

        query = (
            select(
                Asset.id,
                Asset.name,
                Asset.asset_type,
                Asset.status,
                Asset.updated_at,
                latest_score_subquery.c.score_r,
                latest_score_subquery.c.calculated_at,
            )
            .outerjoin(latest_score_subquery, latest_score_subquery.c.asset_id == Asset.id)
        )

        count_query = select(func.count(Asset.id)).outerjoin(
            latest_score_subquery,
            latest_score_subquery.c.asset_id == Asset.id,
        )

        if asset_status:
            query = query.where(Asset.status == asset_status)
            count_query = count_query.where(Asset.status == asset_status)

        if risk_bounds:
            low, high = risk_bounds
            query = query.where(latest_score_subquery.c.score_r >= low, latest_score_subquery.c.score_r < high)
            count_query = count_query.where(
                latest_score_subquery.c.score_r >= low,
                latest_score_subquery.c.score_r < high,
            )

        sort_columns = {
            "asset_name": Asset.name,
            "asset_type": Asset.asset_type,
            "risk_score": latest_score_subquery.c.score_r,
            "status": Asset.status,
            "last_updated": Asset.updated_at,
        }
        sort_column = sort_columns[sort_by]
        ordered = sort_column.desc() if sort_order == "desc" else sort_column.asc()

        offset = (page - 1) * page_size
        rows = db.execute(query.order_by(ordered).offset(offset).limit(page_size)).all()
        total_items = int(db.execute(count_query).scalar_one() or 0)

        return list(rows), total_items
