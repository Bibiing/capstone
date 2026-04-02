"""
Risk score query routes for fetching latest scores, trends, and details.

Endpoints:
    GET    /scores/latest          - Get latest scores for all assets
    GET    /scores/{asset_id}      - Get latest score for one asset
    GET    /trends/{asset_id}      - Get risk score trend over time
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status

from api.schemas import (
    AutoCalculateScoreRequest,
    CalculateScoreRequest,
    CalculateScoreResponse,
    LatestScoresResponse,
    RiskScoreBreakdown,
    RiskScoreResponse,
    TrendPointResponse,
    TrendResponse,
)
from ingestion.wazuh_client import WazuhClient

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Scores"])

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
    if not _score_history:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No risk scores available yet. Run scoring engine first.",
        )

    scores = []
    severity_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    all_risk_values = []

    for asset_id, history in _score_history.items():
        if not history:
            continue

        latest = history[0]  # Most recent (first in list)
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
async def get_asset_score(asset_id: str) -> RiskScoreResponse:
    """
    Get the latest risk score for a specific asset.

    Args:
        asset_id: Asset identifier

    Returns:
        RiskScoreResponse with latest score and breakdown

    Raises:
        HTTPException 404: If asset not found or has no scores
    """
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

    logger.debug("Asset score retrieved | asset_id=%s | score=%.1f", asset_id, latest["risk_score"])

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
    history = _score_history.get(asset_id, [])
    if not history:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No trend data found for asset '{asset_id}'",
        )

    # Parse period to hours
    period_to_hours = {
        "1d": 24,
        "7d": 7 * 24,
        "30d": 30 * 24,
        "90d": 90 * 24,
    }
    hours = period_to_hours.get(period, 24)

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


# ============================================================================
# Calculate Risk Score
# ============================================================================

def calculate_impact(questionnaire_answers: list[int]) -> float:
    """Calculate Impact score from questionnaire answers."""
    if len(questionnaire_answers) != 8:
        raise ValueError("Must provide exactly 8 questionnaire answers")
    if not all(1 <= ans <= 5 for ans in questionnaire_answers):
        raise ValueError("All answers must be between 1 and 5")
    avg_likert = sum(questionnaire_answers) / len(questionnaire_answers)
    return avg_likert / 5.0


def calculate_vulnerability(sca_pass_percentage: float) -> float:
    """Calculate Vulnerability score from SCA pass percentage."""
    if not (0.0 <= sca_pass_percentage <= 100.0):
        raise ValueError("SCA pass percentage must be between 0 and 100")
    return 100.0 - sca_pass_percentage


def calculate_threat_score(alert_counts: dict, t_previous: float) -> float:
    """Calculate Threat score with time decay."""
    ALERT_WEIGHTS = {
        "low": 1,
        "medium": 5,
        "high": 10,
        "critical": 25,
    }
    DECAY_FACTOR = 0.5

    t_new = sum(
        alert_counts.get(level, 0) * weight
        for level, weight in ALERT_WEIGHTS.items()
    )
    t_now = t_new + (t_previous * DECAY_FACTOR)
    return min(t_now, 100.0)


def calculate_risk_score(I: float, V: float, T: float, w1: float = 0.3, w2: float = 0.7) -> float:
    """Calculate final risk score."""
    R = I * (w1 * V + w2 * T)
    return round(min(max(R, 0), 100), 2)


def get_severity(risk_score: float) -> str:
    """Get severity level based on risk score."""
    if risk_score < 40:
        return "Low"
    elif risk_score < 70:
        return "Medium"
    elif risk_score < 90:
        return "High"
    else:
        return "Critical"


@router.post(
    "/scores/calculate",
    response_model=CalculateScoreResponse,
    status_code=status.HTTP_200_OK,
    summary="Calculate risk score",
    description="Calculate risk score based on Wazuh data and questionnaire answers.",
)
async def calculate_score(request: CalculateScoreRequest) -> CalculateScoreResponse:
    """
    Calculate risk score for an asset based on provided Wazuh data.

    Args:
        request: Calculation parameters

    Returns:
        CalculateScoreResponse with calculated scores

    Raises:
        HTTPException 400: If input validation fails
    """
    try:
        # Calculate components
        impact = calculate_impact(request.questionnaire_answers)
        vulnerability = calculate_vulnerability(request.sca_pass_percentage)
        threat = calculate_threat_score(request.alert_counts, request.t_previous)
        risk_score = calculate_risk_score(impact, vulnerability, threat, request.w1, request.w2)
        severity = get_severity(risk_score)

        # Create formula string
        formula = f"R = {impact:.2f} × ({request.w1}×{vulnerability:.2f} + {request.w2}×{threat:.2f}) = {risk_score:.2f}"

        logger.info(
            "Risk score calculated | asset_id=%s | I=%.2f | V=%.2f | T=%.2f | R=%.2f | severity=%s",
            request.asset_id, impact, vulnerability, threat, risk_score, severity
        )

        return CalculateScoreResponse(
            asset_id=request.asset_id,
            timestamp=datetime.now(timezone.utc),
            impact=round(impact, 2),
            vulnerability=round(vulnerability, 2),
            threat=round(threat, 2),
            risk_score=risk_score,
            severity=severity,
            formula=formula,
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post(
    "/scores/auto-calculate",
    response_model=CalculateScoreResponse,
    status_code=status.HTTP_200_OK,
    summary="Auto-calculate risk score from live Wazuh data",
    description="Automatically fetch SCA and alert data from Wazuh and calculate risk score.",
)
async def auto_calculate_score(request: AutoCalculateScoreRequest) -> CalculateScoreResponse:
    """
    Calculate risk score automatically from live Wazuh data.

    This endpoint:
    1. Fetches SCA pass percentage from Wazuh API
    2. Counts alerts by level from Wazuh Indexer
    3. Uses T_previous = 0 (can be enhanced to fetch from database)
    4. Calculates final risk score

    Args:
        request: Auto-calculation parameters

    Returns:
        CalculateScoreResponse with calculated scores

    Raises:
        HTTPException 400: If Wazuh data fetch fails
        HTTPException 503: If Wazuh service unavailable
    """
    try:
        # Calculate Impact from questionnaire
        impact = calculate_impact(request.questionnaire_answers)

        # Fetch live data from Wazuh
        with WazuhClient.from_settings() as client:
            # Get SCA data
            sca_summaries = client.get_sca_summary(request.wazuh_agent_id)
            if not sca_summaries:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"No SCA data found for agent {request.wazuh_agent_id}"
                )

            # Calculate SCA pass percentage (average across all policies)
            total_checks = sum(s.pass_count + s.fail_count + s.not_applicable for s in sca_summaries)
            total_pass = sum(s.pass_count for s in sca_summaries)
            sca_pass_percentage = (total_pass / total_checks * 100) if total_checks > 0 else 0.0

            # Get alert counts for the lookback period
            to_dt = datetime.now(timezone.utc)
            from_dt = to_dt - timedelta(hours=request.lookback_hours)
            alert_counts = client.count_alerts_by_level(request.wazuh_agent_id, from_dt, to_dt)

        # Calculate Vulnerability and Threat
        vulnerability = calculate_vulnerability(sca_pass_percentage)
        threat = calculate_threat_score(alert_counts, 0.0)  # T_previous = 0 for now

        # Calculate final risk score
        risk_score = calculate_risk_score(impact, vulnerability, threat, request.w1, request.w2)
        severity = get_severity(risk_score)

        # Create formula string
        formula = f"R = {impact:.2f} × ({request.w1}×{vulnerability:.2f} + {request.w2}×{threat:.2f}) = {risk_score:.2f}"

        logger.info(
            "Auto-calculated risk score | asset_id=%s agent_id=%s | I=%.2f | V=%.2f (SCA=%.1f%%) | T=%.2f | R=%.2f | severity=%s",
            request.asset_id, request.wazuh_agent_id, impact, vulnerability, sca_pass_percentage, threat, risk_score, severity
        )

        return CalculateScoreResponse(
            asset_id=request.asset_id,
            timestamp=datetime.now(timezone.utc),
            impact=round(impact, 2),
            vulnerability=round(vulnerability, 2),
            threat=round(threat, 2),
            risk_score=risk_score,
            severity=severity,
            formula=formula,
            data_source="wazuh_live",
        )

    except Exception as e:
        logger.error("Failed to auto-calculate score for asset %s: %s", request.asset_id, str(e))
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Failed to fetch data from Wazuh: {str(e)}"
        )
