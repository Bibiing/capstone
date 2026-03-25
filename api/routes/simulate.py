"""
Simulation routes for testing threat scenarios and remediation.

Endpoints:
    POST   /simulate/spike         - Inject a threat spike
    POST   /simulate/remediation   - Simulate threat remediation (reset threat score)
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, status

from api.routes.scores import _score_history, _asset_names
from api.schemas import (
    RiskScoreBreakdown,
    RiskScoreResponse,
    SimulateSpikeRequest,
    SimulateSpikeResponse,
    SimulateRemediationRequest,
    SimulateRemediationResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/simulate", tags=["Simulation"])


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
async def simulate_spike(request: SimulateSpikeRequest) -> SimulateSpikeResponse:
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
    # Validate assets exist
    valid_assets = [aid for aid in request.asset_ids if aid in _score_history]
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

    new_scores = []
    now = datetime.now(timezone.utc)

    for asset_id in valid_assets:
        history = _score_history[asset_id]
        last_score = history[0] if history else None

        if not last_score:
            continue

        # Calculate new threat value
        # In production, this would interact with the scoring engine
        old_threat = last_score["threat"]
        new_threat = min(request.threat_value, 100.0)  # Cap at 100

        # Recalculate risk score with new threat value
        I = last_score["impact"]
        V = last_score["vulnerability"]
        w1 = last_score["w1"]
        w2 = last_score["w2"]
        new_risk_score = I * (w1 * V + w2 * new_threat)
        new_risk_score = min(max(new_risk_score, 0.0), 100.0)

        # Determine severity
        if new_risk_score >= 90:
            severity = "Critical"
        elif new_risk_score >= 70:
            severity = "High"
        elif new_risk_score >= 40:
            severity = "Medium"
        else:
            severity = "Low"

        # Create new score record
        new_score_entry = {
            "timestamp": now,
            "risk_score": new_risk_score,
            "severity": severity,
            "impact": I,
            "vulnerability": V,
            "threat": new_threat,
            "w1": w1,
            "w2": w2,
        }

        # Prepend to history (most recent first)
        history.insert(0, new_score_entry)

        # Create response
        breakdown = RiskScoreBreakdown(
            impact=I,
            vulnerability=V,
            threat=new_threat,
            w1=w1,
            w2=w2,
        )

        score_response = RiskScoreResponse(
            asset_id=asset_id,
            hostname=_asset_names.get(asset_id, asset_id),
            timestamp=now,
            risk_score=round(new_risk_score, 2),
            severity=severity,
            breakdown=breakdown,
        )
        new_scores.append(score_response)

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
    # Validate assets exist
    valid_assets = [aid for aid in request.asset_ids if aid in _score_history]
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

    new_scores = []
    now = datetime.now(timezone.utc)

    for asset_id in valid_assets:
        history = _score_history[asset_id]
        last_score = history[0] if history else None

        if not last_score:
            continue

        # Reset threat to 0 (remediation complete)
        I = last_score["impact"]
        V = last_score["vulnerability"]
        w1 = last_score["w1"]
        w2 = last_score["w2"]
        new_threat = 0.0

        # Recalculate risk score with threat = 0
        new_risk_score = I * (w1 * V + w2 * new_threat)
        new_risk_score = min(max(new_risk_score, 0.0), 100.0)

        # Determine severity
        if new_risk_score >= 90:
            severity = "Critical"
        elif new_risk_score >= 70:
            severity = "High"
        elif new_risk_score >= 40:
            severity = "Medium"
        else:
            severity = "Low"

        # Create new score record
        new_score_entry = {
            "timestamp": now,
            "risk_score": new_risk_score,
            "severity": severity,
            "impact": I,
            "vulnerability": V,
            "threat": new_threat,
            "w1": w1,
            "w2": w2,
        }

        # Prepend to history
        history.insert(0, new_score_entry)

        # Create response
        breakdown = RiskScoreBreakdown(
            impact=I,
            vulnerability=V,
            threat=new_threat,
            w1=w1,
            w2=w2,
        )

        score_response = RiskScoreResponse(
            asset_id=asset_id,
            hostname=_asset_names.get(asset_id, asset_id),
            timestamp=now,
            risk_score=round(new_risk_score, 2),
            severity=severity,
            breakdown=breakdown,
        )
        new_scores.append(score_response)

    logger.info(
        "Threat remediation simulated | affected=%d | threat_reset_to=0.0",
        len(valid_assets),
    )

    return SimulateRemediationResponse(
        message=f"Threat remediation simulated on {len(valid_assets)} asset(s). Threat scores reset to 0.",
        affected_assets=len(valid_assets),
        new_scores=new_scores,
    )
