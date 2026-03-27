"""
FastAPI routes for ingestion pipeline.

Exposes:
- Manual pipeline triggers
- Pipeline status/health
- Risk score querying
- Scheduler management
"""

import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel

from ingestion.pipeline import IngestionPipeline, PipelineStats
from ingestion.scheduler import get_scheduler, SchedulerConfig
from ingestion.risk_builder import RiskContextBuilder
from database.connection import get_session
from database import queries

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ingestion", tags=["ingestion"])


# ========== Models ==========

class PipelineStatusResponse(BaseModel):
    """Pipeline execution status."""
    status: str
    is_running: bool
    total_runs: int
    total_errors: int
    last_run_at: str | None = None
    last_success_at: str | None = None
    last_error: str | None = None


class HealthCheckResponse(BaseModel):
    """Health check response."""
    health: str
    scheduler_status: str
    is_running: bool
    seconds_since_last_success: int | None = None
    total_runs: int
    consecutive_errors: int


class RiskScoreResponse(BaseModel):
    """Risk score for a single asset."""
    asset_id: str
    hostname: str | None
    risk_score: float
    severity: str
    components: dict[str, float]
    timestamp: str
    trend: str | None = None


class RiskLeaderboardResponse(BaseModel):
    """Leaderboard of highest-risk assets."""
    timestamp: str
    top_assets: list[RiskScoreResponse]


class TriggerPipelineResponse(BaseModel):
    """Response from manual trigger."""
    queued: bool
    message: str


# ========== Endpoints ==========

# ---- Manual Triggers ----

@router.post("/trigger")
async def trigger_pipeline() -> TriggerPipelineResponse:
    """
    Manually trigger pipeline execution.
    
    Queues execution immediately (non-blocking).
    
    Returns:
        Confirmation of queuing
    """
    scheduler = get_scheduler()
    scheduler.trigger_now(wait=False)
    
    logger.info("Manual pipeline trigger requested")
    
    return TriggerPipelineResponse(
        queued=True,
        message="Pipeline execution queued",
    )


@router.post("/trigger/sync-assets")
async def trigger_asset_sync() -> dict[str, Any]:
    """
    Manually trigger asset synchronization from Wazuh.
    
    Useful for re-syncing agents without full pipeline.
    """
    try:
        pipeline = IngestionPipeline()
        stats = pipeline.execute_full_cycle(
            sync_assets=True,
            fetch_alerts=False,
            fetch_sca=False,
            calculate_risks=False,
        )
        
        logger.info("Asset sync triggered manually")
        
        return {
            "success": True,
            "assets_created": stats.assets_created,
            "assets_updated": stats.assets_updated,
            "duration_seconds": stats.duration_seconds,
        }
        
    except Exception as exc:
        logger.error("Asset sync failed | error=%s", str(exc))
        raise HTTPException(status_code=500, detail=str(exc))


# ---- Status & Health ----

@router.get("/status")
async def get_pipeline_status() -> PipelineStatusResponse:
    """Get current pipeline status."""
    scheduler = get_scheduler()
    status = scheduler.get_status()
    
    return PipelineStatusResponse(
        status=status["status"],
        is_running=status["is_running"],
        total_runs=status["total_runs"],
        total_errors=status["total_errors"],
        last_run_at=status["last_run_at"],
        last_success_at=status["last_success_at"],
        last_error=status["last_error"],
    )


@router.get("/health")
async def health_check() -> HealthCheckResponse:
    """
    Health check endpoint.
    
    Returns overall pipeline/scheduler health status.
    """
    scheduler = get_scheduler()
    health = scheduler.get_health()
    
    return HealthCheckResponse(
        health=health["health"],
        scheduler_status=health["scheduler_status"],
        is_running=health["is_running"],
        seconds_since_last_success=int(health["seconds_since_last_success"])
        if health["seconds_since_last_success"]
        else None,
        total_runs=health["total_runs"],
        consecutive_errors=health["consecutive_errors"],
    )


# ---- Risk Scores ----

@router.get("/scores/latest")
async def get_latest_risk_scores(
    limit: int = Query(10, ge=1, le=100),
    session=Depends(get_session),
) -> RiskLeaderboardResponse:
    """
    Get latest risk scores sorted by severity.
    
    Args:
        limit: Maximum number of assets to return
        
    Returns:
        Leaderboard of riskiest assets
    """
    try:
        # Get latest risk scores
        risk_scores = queries.get_latest_risk_scores(session, limit=limit)
        
        assets_response = []
        for risk in risk_scores:
            assets_response.append(
                RiskScoreResponse(
                    asset_id=risk.asset_id,
                    hostname=risk.asset.hostname if risk.asset else None,
                    risk_score=float(risk.risk_score),
                    severity=risk.severity or "unknown",
                    components={
                        "threat": float(risk.threat_component or 0),
                        "vulnerability": float(risk.vulnerability_component or 0),
                        "impact": float(risk.impact_component or 0),
                    },
                    timestamp=risk.calculated_at.isoformat() if risk.calculated_at else None,
                )
            )
        
        return RiskLeaderboardResponse(
            timestamp=datetime.utcnow().isoformat(),
            top_assets=assets_response,
        )
        
    except Exception as exc:
        logger.error("Failed to retrieve risk scores | error=%s", str(exc))
        raise HTTPException(status_code=500, detail="Failed to retrieve risk scores")


@router.get("/scores/asset/{asset_id}")
async def get_asset_risk_score(
    asset_id: str,
    session=Depends(get_session),
) -> RiskScoreResponse:
    """
    Get latest risk score for a specific asset.
    
    Args:
        asset_id: Asset identifier
        
    Returns:
        Latest risk score and components
    """
    try:
        # Get latest risk score for asset
        risk = queries.get_latest_risk_score_for_asset(session, asset_id)
        
        if not risk:
            raise HTTPException(status_code=404, detail=f"No risk score found for asset {asset_id}")
        
        return RiskScoreResponse(
            asset_id=risk.asset_id,
            hostname=risk.asset.hostname if risk.asset else None,
            risk_score=float(risk.risk_score),
            severity=risk.severity or "unknown",
            components={
                "threat": float(risk.threat_component or 0),
                "vulnerability": float(risk.vulnerability_component or 0),
                "impact": float(risk.impact_component or 0),
            },
            timestamp=risk.calculated_at.isoformat() if risk.calculated_at else None,
        )
        
    except Exception as exc:
        logger.error("Failed to retrieve risk score | asset=%s | error=%s", asset_id, str(exc))
        raise HTTPException(status_code=500, detail="Failed to retrieve risk score")


@router.get("/scores/trend/{asset_id}")
async def get_asset_risk_trend(
    asset_id: str,
    days: int = Query(7, ge=1, le=90),
    session=Depends(get_session),
) -> dict[str, Any]:
    """
    Get risk score trend for an asset over time.
    
    Args:
        asset_id: Asset identifier
        days: Number of days to look back (default: 7)
        
    Returns:
        Risk scores over time with trend direction
    """
    try:
        # Get risk score history
        history = queries.get_risk_score_history(session, asset_id, days=days)
        
        if not history:
            raise HTTPException(status_code=404, detail=f"No risk history found for asset {asset_id}")
        
        scores = [
            {
                "timestamp": score.calculated_at.isoformat() if score.calculated_at else None,
                "risk_score": float(score.risk_score),
                "severity": score.severity,
            }
            for score in history
        ]
        
        # Calculate trend
        if len(scores) >= 2:
            first = scores[0]["risk_score"]
            last = scores[-1]["risk_score"]
            trend = "increasing" if last > first else "decreasing" if last < first else "stable"
        else:
            trend = "unknown"
        
        return {
            "asset_id": asset_id,
            "trend": trend,
            "data_points": len(scores),
            "history": scores,
        }
        
    except Exception as exc:
        logger.error("Failed to retrieve risk trend | asset=%s | error=%s", asset_id, str(exc))
        raise HTTPException(status_code=500, detail="Failed to retrieve risk trend")


# ---- Scheduler Management ----

@router.post("/scheduler/start")
async def start_scheduler() -> dict[str, str]:
    """Start the pipeline scheduler."""
    scheduler = get_scheduler()
    scheduler.start()
    logger.info("Scheduler started via API")
    return {"message": "Scheduler started"}


@router.post("/scheduler/stop")
async def stop_scheduler() -> dict[str, str]:
    """Stop the pipeline scheduler."""
    scheduler = get_scheduler()
    scheduler.stop()
    logger.info("Scheduler stopped via API")
    return {"message": "Scheduler stopped"}


@router.post("/scheduler/pause")
async def pause_scheduler() -> dict[str, str]:
    """Pause the scheduler (can resume later)."""
    scheduler = get_scheduler()
    scheduler.pause()
    logger.info("Scheduler paused via API")
    return {"message": "Scheduler paused"}


@router.post("/scheduler/resume")
async def resume_scheduler() -> dict[str, str]:
    """Resume a paused scheduler."""
    scheduler = get_scheduler()
    scheduler.resume()
    logger.info("Scheduler resumed via API")
    return {"message": "Scheduler resumed"}


@router.get("/scheduler/status")
async def get_scheduler_status() -> dict[str, Any]:
    """Get detailed scheduler status."""
    scheduler = get_scheduler()
    return scheduler.get_status()


# ---- Configuration ----

@router.put("/scheduler/config")
async def update_scheduler_config(
    interval_seconds: int = Query(None, ge=60),
    max_retries: int = Query(None, ge=1, le=10),
    error_threshold: int = Query(None, ge=1, le=20),
) -> dict[str, str]:
    """
    Update scheduler configuration.
    
    Args:
        interval_seconds: Execution interval in seconds (min: 60)
        max_retries: Max retry attempts (1-10)
        error_threshold: Pause after N consecutive errors (1-20)
        
    Returns:
        Confirmation of update
    """
    scheduler = get_scheduler()
    
    if interval_seconds:
        scheduler._config.interval_seconds = interval_seconds
    if max_retries:
        scheduler._config.max_retries = max_retries
    if error_threshold:
        scheduler._config.error_threshold = error_threshold
    
    logger.info("Scheduler config updated | interval=%d", scheduler._config.interval_seconds)
    
    return {
        "message": "Configuration updated",
        "interval_seconds": scheduler._config.interval_seconds,
        "max_retries": scheduler._config.max_retries,
        "error_threshold": scheduler._config.error_threshold,
    }


if __name__ == "__main__":
    # Quick test
    print("Pipeline routes registered:")
    for route in router.routes:
        if hasattr(route, "path"):
            print(f"  {route.methods} {route.path}")
