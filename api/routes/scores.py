"""
Risk score query routes for fetching latest scores, trends, and details.

Endpoints:
    GET    /scores/latest          - Get latest scores for all assets
    GET    /scores/{asset_id}      - Get latest score for one asset
    GET    /trends/{asset_id}      - Get risk score trend over time
"""

import logging
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from api.dependencies.db import get_db_session
from api.schemas import (
    LatestScoresResponse,
    RiskScoreBreakdown,
    RiskScoreResponse,
    TrendPointResponse,
    TrendResponse,
)
from api.services.scoring_engine import classify_severity
from config.settings import get_settings
from database import queries

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Scores"])
settings = get_settings()

# Mock score store (would be in database in production)
_score_history: dict[str, list[dict]] = {
    "asset-001": [
        {
            "timestamp": datetime.now(timezone.utc) - timedelta(hours=i),
            "risk_score": 45.0 + (i * 2.5),
            "severity": "Medium" if 45.0 + (i * 2.5) < 70 else "High",
            "impact": 1.0,
            "vulnerability": 61.0,
            "threat": 40.0 + i,
            "w1": 0.3,
            "w2": 0.7,
        }
        for i in range(24)
    ],
    "asset-002": [
        {
            "timestamp": datetime.now(timezone.utc) - timedelta(hours=i),
            "risk_score": 35.0 + (i * 1.5),
            "severity": "Low" if 35.0 + (i * 1.5) < 40 else "Medium",
            "impact": 0.9,
            "vulnerability": 40.0,
            "threat": 30.0 + i,
            "w1": 0.3,
            "w2": 0.7,
        }
        for i in range(24)
    ],
    "asset-003": [
        {
            "timestamp": datetime.now(timezone.utc) - timedelta(hours=i),
            "risk_score": 55.0 + (i * 2.0),
            "severity": "Medium",
            "impact": 0.8,
            "vulnerability": 55.0,
            "threat": 50.0 + i,
            "w1": 0.3,
            "w2": 0.7,
        }
        for i in range(24)
    ],
}

# Mock asset mapping
_asset_names = {
    "asset-001": "db-prod-01",
    "asset-002": "web-prod-01",
    "asset-003": "app-server-01",
}


def _risk_score_to_response(score_row, hostname: str, asset_id: str) -> RiskScoreResponse:
    """Map RiskScore row to API schema."""
    breakdown = RiskScoreBreakdown(
        impact=score_row.score_i,
        vulnerability=score_row.score_v,
        threat=score_row.score_t,
        w1=settings.weight_vulnerability,
        w2=settings.weight_threat,
    )
    return RiskScoreResponse(
        asset_id=asset_id,
        hostname=hostname,
        timestamp=score_row.calculated_at,
        risk_score=round(score_row.score_r, 2),
        severity=classify_severity(score_row.score_r),
        breakdown=breakdown,
    )


# ============================================================================
# Latest Scores for All Assets
# ============================================================================

@router.get(
    "/scores/latest",
    response_model=LatestScoresResponse,
    status_code=status.HTTP_200_OK,
    summary="Get latest risk scores",
    description="Retrieve the latest risk scores for all assets with summary statistics.",
)
async def get_latest_scores(
    include_summary: bool = Query(True, description="Include summary statistics"),
    db: Session = Depends(get_db_session),
) -> LatestScoresResponse:
    """
    Get the latest risk scores for all registered assets.

    Args:
        include_summary: Whether to include summary statistics

    Returns:
        LatestScoresResponse with scores for all assets and optional summary

    Raises:
        HTTPException 503: If no score data available
    """
    scores: list[RiskScoreResponse] = []
    severity_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    all_risk_values: list[float] = []

    # Primary source: database
    latest_rows = queries.get_all_latest_scores(db)
    if latest_rows:
        for row in latest_rows:
            asset = queries.get_asset_by_id(db, row.asset_id)
            hostname = asset.name if asset else str(row.asset_id)
            asset_id = str(row.asset_id)

            response_row = _risk_score_to_response(row, hostname=hostname, asset_id=asset_id)
            scores.append(response_row)
            all_risk_values.append(response_row.risk_score)
            severity_counts[response_row.severity] += 1

    # Compatibility fallback until all modules consume DB-backed IDs.
    elif _score_history:
        for asset_id, history in _score_history.items():
            if not history:
                continue

            latest = history[0]
            all_risk_values.append(latest["risk_score"])
            severity_counts[latest["severity"]] += 1

            breakdown = RiskScoreBreakdown(
                impact=latest["impact"],
                vulnerability=latest["vulnerability"],
                threat=latest["threat"],
                w1=latest["w1"],
                w2=latest["w2"],
            )

            score_response = RiskScoreResponse(
                asset_id=asset_id,
                hostname=_asset_names.get(asset_id, asset_id),
                timestamp=latest["timestamp"],
                risk_score=round(latest["risk_score"], 2),
                severity=latest["severity"],
                breakdown=breakdown,
            )
            scores.append(score_response)

    else:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No risk scores available yet. Run scoring engine first.",
        )

    # Sort by risk score (highest first)
    scores.sort(key=lambda x: x.risk_score, reverse=True)

    summary = None
    if include_summary and all_risk_values:
        summary = {
            "average_score": round(sum(all_risk_values) / len(all_risk_values), 2),
            "min_score": round(min(all_risk_values), 2),
            "max_score": round(max(all_risk_values), 2),
            "critical_count": severity_counts["Critical"],
            "high_count": severity_counts["High"],
            "medium_count": severity_counts["Medium"],
            "low_count": severity_counts["Low"],
        }

    logger.debug(
        "Latest scores retrieved | total=%d | high_risk=%d",
        len(scores),
        severity_counts["High"] + severity_counts["Critical"],
    )

    return LatestScoresResponse(
        timestamp=datetime.now(timezone.utc),
        total_assets=len(scores),
        scores=scores,
        summary=summary,
    )


# ============================================================================
# Latest Score for Single Asset
# ============================================================================

@router.get(
    "/scores/{asset_id}",
    response_model=RiskScoreResponse,
    status_code=status.HTTP_200_OK,
    summary="Get asset risk score",
    description="Retrieve the latest risk score and breakdown for a specific asset.",
)
async def get_asset_score(
    asset_id: str,
    db: Session = Depends(get_db_session),
) -> RiskScoreResponse:
    """
    Get the latest risk score for a specific asset.

    Args:
        asset_id: Asset identifier

    Returns:
        RiskScoreResponse with latest score and breakdown

    Raises:
        HTTPException 404: If asset not found or has no scores
    """
    try:
        asset_uuid = UUID(asset_id)
        asset = queries.get_asset_by_id(db, asset_uuid)
        if asset is not None:
            latest = queries.get_latest_score(db, asset_uuid)
            if latest is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"No score data found for asset '{asset_id}'",
                )
            logger.debug("Asset score retrieved | asset_id=%s | score=%.1f", asset_id, latest.score_r)
            return _risk_score_to_response(latest, hostname=asset.name, asset_id=str(asset.id))
    except ValueError:
        # legacy id fallback
        pass

    history = _score_history.get(asset_id, [])
    if not history:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No score data found for asset '{asset_id}'",
        )

    latest = history[0]
    breakdown = RiskScoreBreakdown(
        impact=latest["impact"],
        vulnerability=latest["vulnerability"],
        threat=latest["threat"],
        w1=latest["w1"],
        w2=latest["w2"],
    )
    logger.debug("Asset score retrieved (fallback) | asset_id=%s | score=%.1f", asset_id, latest["risk_score"])
    return RiskScoreResponse(
        asset_id=asset_id,
        hostname=_asset_names.get(asset_id, asset_id),
        timestamp=latest["timestamp"],
        risk_score=round(latest["risk_score"], 2),
        severity=latest["severity"],
        breakdown=breakdown,
    )


# ============================================================================
# Risk Score Trend
# ============================================================================

@router.get(
    "/trends/{asset_id}",
    response_model=TrendResponse,
    status_code=status.HTTP_200_OK,
    summary="Get risk score trend",
    description="Retrieve historical risk score trend for an asset over a specified period.",
)
async def get_asset_trend(
    asset_id: str,
    period: str = Query("7d", pattern="^(1d|7d|30d|90d)$", description="Time period: 1d, 7d, 30d, 90d"),
    db: Session = Depends(get_db_session),
) -> TrendResponse:
    """
    Get risk score trend for a specific asset.

    Args:
        asset_id: Asset identifier
        period: Time period (1d, 7d, 30d, 90d)

    Returns:
        TrendResponse with historical trend data

    Raises:
        HTTPException 404: If asset not found or has no scores
    """
    # Parse period to hours
    period_to_hours = {
        "1d": 24,
        "7d": 7 * 24,
        "30d": 30 * 24,
        "90d": 90 * 24,
    }
    hours = period_to_hours.get(period, 24)

    try:
        asset_uuid = UUID(asset_id)
        asset = queries.get_asset_by_id(db, asset_uuid)
        if asset is not None:
            history = queries.get_score_trend(db=db, asset_id=asset_uuid, hours=hours)
            if not history:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"No trend data found for asset '{asset_id}'",
                )

            trend_data = [
                TrendPointResponse(
                    timestamp=point.calculated_at,
                    risk_score=round(point.score_r, 2),
                    severity=classify_severity(point.score_r),
                )
                for point in history
            ]

            logger.debug(
                "Asset trend retrieved | asset_id=%s | period=%s | points=%d",
                asset_id,
                period,
                len(trend_data),
            )

            return TrendResponse(
                asset_id=str(asset.id),
                hostname=asset.name,
                period=period,
                total_points=len(trend_data),
                trend_data=trend_data,
            )
    except ValueError:
        # legacy id fallback
        pass

    history = _score_history.get(asset_id, [])
    if not history:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No trend data found for asset '{asset_id}'",
        )

    # Filter historical data by period
    cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
    trend_data = [
        TrendPointResponse(
            timestamp=point["timestamp"],
            risk_score=round(point["risk_score"], 2),
            severity=point["severity"],
        )
        for point in history
        if point["timestamp"] >= cutoff_time
    ]

    logger.debug(
        "Asset trend retrieved | asset_id=%s | period=%s | points=%d",
        asset_id,
        period,
        len(trend_data),
    )

    return TrendResponse(
        asset_id=asset_id,
        hostname=_asset_names.get(asset_id, asset_id),
        period=period,
        total_points=len(trend_data),
        trend_data=trend_data,
    )
