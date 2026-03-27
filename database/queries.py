"""Data access helpers for scoring domain tables.

This module follows the README schema:
- assets
- risk_scores
- alert_snapshots
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import desc, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from database.models import AlertSnapshot, Asset, RiskScore

logger = logging.getLogger(__name__)


# =============================================================================
# Asset Queries
# =============================================================================

def get_all_assets(session: Session) -> list[Asset]:
    """Return all assets ordered by name."""
    return list(session.execute(select(Asset).order_by(Asset.name)).scalars().all())


def get_asset_by_id(session: Session, asset_id: UUID) -> Asset | None:
    """Return one asset by primary key."""
    return session.get(Asset, asset_id)


def get_asset_by_agent_id(session: Session, agent_id: str) -> Asset | None:
    """Return one asset by Wazuh agent ID."""
    return session.execute(select(Asset).where(Asset.agent_id == agent_id)).scalar_one_or_none()


def upsert_asset_by_agent_id(session: Session, asset_data: dict) -> None:
    """Upsert asset by unique agent_id for idempotent sync jobs."""
    stmt = insert(Asset).values(**asset_data)
    stmt = stmt.on_conflict_do_update(
        index_elements=["agent_id"],
        set_={
            "name": stmt.excluded.name,
            "ip_address": stmt.excluded.ip_address,
            "os_type": stmt.excluded.os_type,
            "status": stmt.excluded.status,
            "impact_score": stmt.excluded.impact_score,
            "updated_at": stmt.excluded.updated_at,
        },
    )
    session.execute(stmt)
    logger.debug("Upserted asset by agent_id=%s", asset_data.get("agent_id"))


# =============================================================================
# Risk Score Queries
# =============================================================================

def insert_risk_score(session: Session, risk_score: RiskScore) -> None:
    """Insert one risk score snapshot."""
    session.add(risk_score)


def get_latest_score(session: Session, asset_id: UUID) -> RiskScore | None:
    """Return latest score row for one asset."""
    return session.execute(
        select(RiskScore)
        .where(RiskScore.asset_id == asset_id)
        .order_by(desc(RiskScore.calculated_at))
        .limit(1)
    ).scalar_one_or_none()


def get_all_latest_scores(session: Session) -> list[RiskScore]:
    """Return latest score row for each asset ordered by score_r descending."""
    subq = (
        select(RiskScore.asset_id, func.max(RiskScore.calculated_at).label("max_ts"))
        .group_by(RiskScore.asset_id)
        .subquery()
    )
    return list(
        session.execute(
            select(RiskScore)
            .join(
                subq,
                (RiskScore.asset_id == subq.c.asset_id)
                & (RiskScore.calculated_at == subq.c.max_ts),
            )
            .order_by(desc(RiskScore.score_r))
        )
        .scalars()
        .all()
    )


def get_score_trend(
    session: Session,
    asset_id: UUID,
    hours: int = 24 * 7,
) -> list[RiskScore]:
    """Return score trend for one asset for given lookback window."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    return list(
        session.execute(
            select(RiskScore)
            .where(RiskScore.asset_id == asset_id, RiskScore.calculated_at >= since)
            .order_by(RiskScore.calculated_at)
        )
        .scalars()
        .all()
    )


# =============================================================================
# Alert Snapshot Queries
# =============================================================================

def insert_alert_snapshots(session: Session, snapshots: list[AlertSnapshot]) -> None:
    """Bulk insert alert snapshots for audit trail."""
    session.add_all(snapshots)
