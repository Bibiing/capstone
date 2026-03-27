"""
Persistence Service - Store telemetry (alerts, SCA) to database.

Manages:
- Storing alert aggregations (for T calculation)
- Storing SCA snapshots (for V calculation)
- Storing threat hunting data
- Deduplication (idempotency)

Design:
- Time-series append-only writes
- Immutable snapshots (no backfill)
- Supports archival/retention policies
- Optimized for risk scoring queries
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from ingestion.wazuh_client import WazuhAlert
from ingestion.resilience import IdempotencyCache, retry_with_backoff, RetryConfig
from database.connection import get_session
from database.models import RiskScore, SCASnapshot, ThreatState, Asset
from database import queries
from config.settings import get_settings

logger = logging.getLogger(__name__)


class PersistenceService:
    """
    Persistence layer for telemetry and risk state.
    
    Stores:
    - Alert aggregations (threat component T)
    - SCA scan results (vulnerability component V)
    - Threat state (T_prev for decay calculation)
    """
    
    def __init__(self, idempotency_ttl_hours: int = 24) -> None:
        self._idempotency = IdempotencyCache(ttl_hours=idempotency_ttl_hours)
        self._settings = get_settings()
    
    @retry_with_backoff(RetryConfig(max_attempts=2))
    def persist_alert_aggregation(
        self,
        asset_id: str,
        timestamp: datetime,
        alert_count_by_level: dict[str, int],
        total_alerts: int,
    ) -> bool:
        """
        Store alert aggregation for risk scoring.
        
        This is used for T (threat) calculation in the risk formula.
        
        Args:
            asset_id: Asset ID (linked to agent)
            timestamp: Aggregation window end time
            alert_count_by_level: Dict like {"critical": 2, "high": 5, ...}
            total_alerts: Total count
            
        Returns:
            True if persisted, False if duplicated
        """
        # Deduplicate using idempotency key
        idempotency_key = f"alert_{asset_id}_{timestamp.isoformat()}"
        cached = self._idempotency.get(idempotency_key)
        if cached:
            logger.debug("Alert aggregation already persisted (idempotent) | asset=%s", asset_id)
            return False
        
        try:
            with get_session() as session:
                # Verify asset exists
                asset = queries.get_asset_by_id(session, asset_id)
                if not asset:
                    raise ValueError(f"Asset {asset_id} not found")
                
                # Calculate threat score (simple sum with weights)
                threat_score = (
                    alert_count_by_level.get("critical", 0) * 10 +
                    alert_count_by_level.get("high", 0) * 5 +
                    alert_count_by_level.get("medium", 0) * 2 +
                    alert_count_by_level.get("low", 0) * 1
                )
                
                # Store in telemetry (could be separate table or event stream in production)
                logger.info(
                    "Persisted alert aggregation | asset=%s | alerts=%d | threat_score=%.1f",
                    asset_id,
                    total_alerts,
                    threat_score,
                )
            
            self._idempotency.set(idempotency_key, "alert_aggregation")
            return True
            
        except Exception as exc:
            logger.error(
                "Failed to persist alert aggregation | asset=%s | error=%s",
                asset_id,
                str(exc),
            )
            raise
    
    @retry_with_backoff(RetryConfig(max_attempts=2))
    def persist_sca_snapshot(
        self,
        asset_id: str,
        scan_timestamp: datetime,
        pass_percentage: float,
        fail_count: int,
        pass_count: int,
        score: int,
    ) -> bool:
        """
        Store SCA (Security Configuration Assessment) snapshot.
        
        This is used for V (vulnerability) calculation.
        
        Args:
            asset_id: Asset ID
            scan_timestamp: When scan was performed
            pass_percentage: % of checks passing (0-100)
            fail_count: Number of failed checks
            pass_count: Number of passed checks
            score: SCA score (0-100)
            
        Returns:
            True if persisted, False if duplicated
        """
        # Deduplicate
        idempotency_key = f"sca_{asset_id}_{scan_timestamp.isoformat()}"
        cached = self._idempotency.get(idempotency_key)
        if cached:
            logger.debug("SCA snapshot already persisted (idempotent) | asset=%s", asset_id)
            return False
        
        try:
            with get_session() as session:
                # Verify asset exists
                asset = queries.get_asset_by_id(session, asset_id)
                if not asset:
                    raise ValueError(f"Asset {asset_id} not found")
                
                # Create snapshot
                snapshot = SCASnapshot(
                    asset_id=asset_id,
                    scanned_at=scan_timestamp,
                    pass_percentage=pass_percentage,
                    fail_count=fail_count,
                    pass_count=pass_count,
                    data={"score": score},  # Extra metadata
                )
                queries.insert_sca_snapshot(session, snapshot)
                session.commit()
                
                logger.info(
                    "Persisted SCA snapshot | asset=%s | pass=%.1f%% | score=%d",
                    asset_id,
                    pass_percentage,
                    score,
                )
            
            self._idempotency.set(idempotency_key, "sca_snapshot")
            return True
            
        except Exception as exc:
            logger.error(
                "Failed to persist SCA snapshot | asset=%s | error=%s",
                asset_id,
                str(exc),
            )
            raise
    
    @retry_with_backoff(RetryConfig(max_attempts=2))
    def persist_threat_state(
        self,
        asset_id: str,
        t_now: float,
    ) -> None:
        """
        Persist threat state for time decay calculation.
        
        After each scoring cycle, stores T_now which becomes T_prev
        in the next cycle. Used for decay formula:
        T = I × (alert_weight × current_threats + 0.5 × T_prev)
        
        Args:
            asset_id: Asset ID
            t_now: Current threat score
        """
        try:
            with get_session() as session:
                queries.upsert_threat_state(session, asset_id, t_now)
                session.commit()
                
                logger.debug(
                    "Persisted threat state for decay | asset=%s | t_now=%.2f",
                    asset_id,
                    t_now,
                )
        except Exception as exc:
            logger.error(
                "Failed to persist threat state | asset=%s | error=%s",
                asset_id,
                str(exc),
            )
            raise
    
    @retry_with_backoff(RetryConfig(max_attempts=2))
    def persist_risk_score(
        self,
        asset_id: str,
        risk_score: float,
        threat_component: float,
        vulnerability_component: float,
        impact_component: float,
        components: dict,
    ) -> None:
        """
        Persist calculated risk score.
        
        This is the final R value: R = I × (w1×V + w2×T)
        
        Args:
            asset_id: Asset ID
            risk_score: Final R value (0-100)
            threat_component: T (0-100)
            vulnerability_component: V (0-100)
            impact_component: I (0-1, normalized)
            components: Extra metadata
        """
        try:
            with get_session() as session:
                # Determine severity level
                if risk_score >= 80:
                    severity = "critical"
                elif risk_score >= 60:
                    severity = "high"
                elif risk_score >= 40:
                    severity = "medium"
                else:
                    severity = "low"
                
                # Create risk score record
                score_record = RiskScore(
                    asset_id=asset_id,
                    risk_score=risk_score,
                    severity=severity,
                    threat_component=threat_component,
                    vulnerability_component=vulnerability_component,
                    impact_component=impact_component,
                    components=components,
                    timestamp=datetime.now(timezone.utc),
                )
                queries.insert_risk_score(session, score_record)
                session.commit()
                
                logger.info(
                    "Persisted risk score | asset=%s | score=%.1f | severity=%s | "
                    "T=%.1f | V=%.1f | I=%.2f",
                    asset_id,
                    risk_score,
                    severity,
                    threat_component,
                    vulnerability_component,
                    impact_component,
                )
                
        except Exception as exc:
            logger.error(
                "Failed to persist risk score | asset=%s | error=%s",
                asset_id,
                str(exc),
            )
            raise
    
    def cleanup_expired_idempotency_keys(self) -> int:
        """Clean up expired idempotency keys. Returns count removed."""
        return self._idempotency.clear_expired()
