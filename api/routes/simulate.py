"""
Simulation routes for testing threat scenarios and remediation.

Endpoints:
    POST   /simulate/spike         - Inject a threat spike
    POST   /simulate/remediation   - Simulate threat remediation (reset threat score)
"""

import logging
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from api.dependencies.db import get_db_session
from api.services.scoring_engine import calculate_r, classify_severity
from api.schemas import (
    RiskScoreBreakdown,
    RiskScoreResponse,
    SimulateSpikeRequest,
    SimulateSpikeResponse,
    SimulateRemediationRequest,
    SimulateRemediationResponse,
)
from config.settings import get_settings
from database import queries
from database.models import RiskScore

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/simulate", tags=["Simulation"])
settings = get_settings()


# ============================================================================
# Simulate Threat Spike
# ============================================================================

@router.post(
    "/spike",
    response_model=SimulateSpikeResponse,
    status_code=status.HTTP_200_OK,
    summary="Simulate threat spike",
    description="Inject a simulated security threat spike into selected assets.",
)
async def simulate_spike(
    request: SimulateSpikeRequest,
    db: Session = Depends(get_db_session),
) -> SimulateSpikeResponse:
    """
    Simulate a threat spike (e.g., brute force attack, malware detection).

    This endpoint increases the threat score (T) for specified assets,
    simulating a real-world security incident.

    Args:
        request: Spike simulation request with asset IDs and threat value

    Returns:
        SimulateSpikeResponse with updated scores

    Raises:
        HTTPException 400: If asset IDs not found
    """
    new_scores = []
    now = datetime.now(timezone.utc)
    valid_assets = []

    # DB-first flow: UUID asset IDs
    for input_asset_id in request.asset_ids:
        try:
            asset_uuid = UUID(input_asset_id)
        except ValueError:
            continue

        asset = queries.get_asset_by_id(db, asset_uuid)
        if asset is None:
            continue

        latest = queries.get_latest_score(db, asset_uuid)
        if latest is None:
            base_i = asset.impact_score if asset.impact_score is not None else 0.5
            base_v = 50.0
            base_period_start = now
        else:
            base_i = latest.score_i
            base_v = latest.score_v
            base_period_start = latest.period_end

        new_threat = min(request.threat_value, 100.0)
        new_risk_score = calculate_r(
            impact_i=base_i,
            vulnerability_v=base_v,
            threat_t=new_threat,
            w1=settings.weight_vulnerability,
            w2=settings.weight_threat,
        )

        db.add(
            RiskScore(
                asset_id=asset.id,
                score_i=base_i,
                score_v=base_v,
                score_t=new_threat,
                score_r=new_risk_score,
                period_start=base_period_start,
                period_end=now,
                calculated_at=now,
            )
        )

        valid_assets.append(input_asset_id)
        new_scores.append(
            RiskScoreResponse(
                asset_id=str(asset.id),
                hostname=asset.name,
                timestamp=now,
                risk_score=round(new_risk_score, 2),
                severity=classify_severity(new_risk_score),
                breakdown=RiskScoreBreakdown(
                    impact=base_i,
                    vulnerability=base_v,
                    threat=new_threat,
                    w1=settings.weight_vulnerability,
                    w2=settings.weight_threat,
                ),
            )
        )

    if not valid_assets:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"None of the provided asset IDs found: {request.asset_ids}",
        )

    invalid_assets = set(request.asset_ids) - set(valid_assets)
    if invalid_assets:
        logger.warning(
            "Some assets not found in simulation | spike | invalid=%s | reason=%s",
            invalid_assets,
            request.reason or "N/A",
        )

    logger.info(
        "Threat spike simulated | affected=%d | reason=%s | threat=%.1f",
        len(valid_assets),
        request.reason or "N/A",
        request.threat_value,
    )

    return SimulateSpikeResponse(
        message=f"Threat spike simulated on {len(valid_assets)} asset(s). Risk scores updated.",
        affected_assets=len(valid_assets),
        new_scores=new_scores,
    )


# ============================================================================
# Simulate Remediation
# ============================================================================

@router.post(
    "/remediation",
    response_model=SimulateRemediationResponse,
    status_code=status.HTTP_200_OK,
    summary="Simulate threat remediation",
    description="Clear threat scores (simulate successful incident response and remediation).",
)
async def simulate_remediation(
    request: SimulateRemediationRequest,
    db: Session = Depends(get_db_session),
) -> SimulateRemediationResponse:
    """
    Simulate threat remediation (e.g., patch applied, malware removed).

    This endpoint resets the threat score (T) to 0 for specified assets,
    simulating a successful incident response and remediation action.

    Args:
        request: Remediation simulation request with asset IDs

    Returns:
        SimulateRemediationResponse with updated scores

    Raises:
        HTTPException 400: If asset IDs not found
    """
    new_scores = []
    now = datetime.now(timezone.utc)
    valid_assets = []

    # DB-first flow: UUID asset IDs
    for input_asset_id in request.asset_ids:
        try:
            asset_uuid = UUID(input_asset_id)
        except ValueError:
            continue

        asset = queries.get_asset_by_id(db, asset_uuid)
        if asset is None:
            continue

        latest = queries.get_latest_score(db, asset_uuid)
        if latest is None:
            base_i = asset.impact_score if asset.impact_score is not None else 0.5
            base_v = 50.0
            base_period_start = now
        else:
            base_i = latest.score_i
            base_v = latest.score_v
            base_period_start = latest.period_end

        new_threat = 0.0
        new_risk_score = calculate_r(
            impact_i=base_i,
            vulnerability_v=base_v,
            threat_t=new_threat,
            w1=settings.weight_vulnerability,
            w2=settings.weight_threat,
        )

        db.add(
            RiskScore(
                asset_id=asset.id,
                score_i=base_i,
                score_v=base_v,
                score_t=new_threat,
                score_r=new_risk_score,
                period_start=base_period_start,
                period_end=now,
                calculated_at=now,
            )
        )

        valid_assets.append(input_asset_id)
        new_scores.append(
            RiskScoreResponse(
                asset_id=str(asset.id),
                hostname=asset.name,
                timestamp=now,
                risk_score=round(new_risk_score, 2),
                severity=classify_severity(new_risk_score),
                breakdown=RiskScoreBreakdown(
                    impact=base_i,
                    vulnerability=base_v,
                    threat=new_threat,
                    w1=settings.weight_vulnerability,
                    w2=settings.weight_threat,
                ),
            )
        )

    if not valid_assets:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"None of the provided asset IDs found: {request.asset_ids}",
        )

    invalid_assets = set(request.asset_ids) - set(valid_assets)
    if invalid_assets:
        logger.warning(
            "Some assets not found in simulation | remediation | invalid=%s",
            invalid_assets,
        )

    logger.info(
        "Threat remediation simulated | affected=%d | threat_reset_to=0.0",
        len(valid_assets),
    )

    return SimulateRemediationResponse(
        message=f"Threat remediation simulated on {len(valid_assets)} asset(s). Threat scores reset to 0.",
        affected_assets=len(valid_assets),
        new_scores=new_scores,
    )
