"""
Database query helpers — repository pattern.

Each function encapsulates a specific DB query or command.
No business logic lives here — only data access.

All functions accept a SQLAlchemy Session as their first argument so
they can participate in the caller's transaction (no nested transactions).

Usage:
    from database import queries
    from database.connection import get_session

    with get_session() as session:
        top_assets = queries.get_all_latest_scores(session)
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import desc, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from database.models import Asset, RiskScore, SCASnapshot, ThreatState

logger = logging.getLogger(__name__)


# =============================================================================
# Asset Queries
# =============================================================================

def get_all_assets(session: Session) -> list[Asset]:
    """Return all registered assets, ordered alphabetically by hostname."""
    return list(session.execute(select(Asset).order_by(Asset.hostname)).scalars().all())


def get_asset_by_id(session: Session, asset_id: str) -> Optional[Asset]:
    """Return an asset by its primary key, or None if not found."""
    return session.get(Asset, asset_id)


def get_asset_by_agent_id(session: Session, wazuh_agent_id: str) -> Optional[Asset]:
    """Return the asset linked to a specific Wazuh agent ID, or None."""
    return session.execute(
        select(Asset).where(Asset.wazuh_agent_id == wazuh_agent_id)
    ).scalar_one_or_none()


def upsert_asset(session: Session, asset_data: dict) -> None:
    """
    Insert a new asset or update an existing one (idempotent).

    Uses PostgreSQL ON CONFLICT DO UPDATE so this function is safe to call
    repeatedly (e.g. on every application start for seeding).

    Args:
        asset_data: Dict with keys matching Asset column names.
                    Must include 'asset_id'.
    """
    stmt = insert(Asset).values(**asset_data)
    stmt = stmt.on_conflict_do_update(
        index_elements=["asset_id"],
        set_={
            "hostname": stmt.excluded.hostname,
            "wazuh_agent_id": stmt.excluded.wazuh_agent_id,
            "ip_address": stmt.excluded.ip_address,
            "likert_score": stmt.excluded.likert_score,
            "description": stmt.excluded.description,
            "updated_at": stmt.excluded.updated_at,
        },
    )
    session.execute(stmt)
    logger.debug("Upserted asset: %s", asset_data.get("asset_id"))


# =============================================================================
# Risk Score Queries
# =============================================================================

def insert_risk_score(session: Session, risk_score: RiskScore) -> None:
    """
    Append a new risk score snapshot to the time-series table.

    Never update existing records — risk_scores is append-only by design.
    """
    session.add(risk_score)
    logger.debug(
        "Inserting risk score | asset=%s score=%.2f severity=%s",
        risk_score.asset_id,
        risk_score.risk_score,
        risk_score.severity,
    )


def get_latest_score(session: Session, asset_id: str) -> Optional[RiskScore]:
    """Return the most recent risk score record for a single asset."""
    return session.execute(
        select(RiskScore)
        .where(RiskScore.asset_id == asset_id)
        .order_by(desc(RiskScore.timestamp))
        .limit(1)
    ).scalar_one_or_none()


def get_all_latest_scores(session: Session) -> list[RiskScore]:
    """
    Return the latest risk score for every asset, sorted by risk_score descending.

    Uses a correlated subquery to pick the max(timestamp) per asset,
    which is efficient on the (asset_id, timestamp) composite index.
    """
    subq = (
        select(RiskScore.asset_id, func.max(RiskScore.timestamp).label("max_ts"))
        .group_by(RiskScore.asset_id)
        .subquery()
    )
    return list(
        session.execute(
            select(RiskScore)
            .join(
                subq,
                (RiskScore.asset_id == subq.c.asset_id)
                & (RiskScore.timestamp == subq.c.max_ts),
            )
            .order_by(desc(RiskScore.risk_score))
        )
        .scalars()
        .all()
    )


def get_top_risk_assets(session: Session, limit: int = 10) -> list[RiskScore]:
    """Return the top N highest-risk assets by latest score."""
    return get_all_latest_scores(session)[:limit]


def get_score_trend(
    session: Session,
    asset_id: str,
    hours: int = 24 * 7,
) -> list[RiskScore]:
    """
    Return ordered time-series risk scores for a single asset.

    Args:
        asset_id:  Target asset.
        hours:     How far back to look. Default: 7 days (168 hours).

    Returns:
        List of RiskScore records ordered by timestamp ascending (oldest → newest),
        suitable for feeding directly into a trend chart.
    """
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    return list(
        session.execute(
            select(RiskScore)
            .where(
                RiskScore.asset_id == asset_id,
                RiskScore.timestamp >= since,
            )
            .order_by(RiskScore.timestamp)
        )
        .scalars()
        .all()
    )


# =============================================================================
# Threat State Queries (T_prev persistence for time-decay)
# =============================================================================

def get_threat_state(session: Session, asset_id: str) -> float:
    """
    Return the stored T_prev value for an asset.

    Returns 0.0 on first run (no state exists yet), which correctly
    initialises the time-decay algorithm with a clean slate.
    """
    state = session.get(ThreatState, asset_id)
    return state.t_previous if state is not None else 0.0


def upsert_threat_state(session: Session, asset_id: str, t_now: float) -> None:
    """
    Persist T_now as T_prev for the next scoring cycle.

    Called at the end of each scoring cycle after the RiskScore has been inserted.
    """
    stmt = insert(ThreatState).values(
        asset_id=asset_id,
        t_previous=t_now,
        updated_at=datetime.now(timezone.utc),
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["asset_id"],
        set_={
            "t_previous": stmt.excluded.t_previous,
            "updated_at": stmt.excluded.updated_at,
        },
    )
    session.execute(stmt)
    logger.debug("Updated threat state | asset=%s t_prev=%.2f", asset_id, t_now)


def reset_threat_state(session: Session, asset_id: str) -> None:
    """
    Reset T_prev to 0.0 — used for remediation simulation.

    Setting T_prev to zero means the next scoring cycle starts with a
    "clean" threat score, simulating a successful incident response.
    """
    stmt = insert(ThreatState).values(
        asset_id=asset_id,
        t_previous=0.0,
        updated_at=datetime.now(timezone.utc),
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["asset_id"],
        set_={
            "t_previous": 0.0,
            "updated_at": stmt.excluded.updated_at,
        },
    )
    session.execute(stmt)
    logger.info("Threat state reset to 0 for remediation | asset=%s", asset_id)


# =============================================================================
# SCA Snapshot Queries
# =============================================================================

def insert_sca_snapshot(session: Session, snapshot: SCASnapshot) -> None:
    """Append a new SCA scan snapshot (historical record)."""
    session.add(snapshot)
    logger.debug(
        "Inserting SCA snapshot | asset=%s pass=%.1f%%",
        snapshot.asset_id,
        snapshot.pass_percentage,
    )


def get_latest_sca(session: Session, asset_id: str) -> Optional[SCASnapshot]:
    """Return the most recent SCA snapshot for an asset, or None."""
    return session.execute(
        select(SCASnapshot)
        .where(SCASnapshot.asset_id == asset_id)
        .order_by(desc(SCASnapshot.scanned_at))
        .limit(1)
    ).scalar_one_or_none()
