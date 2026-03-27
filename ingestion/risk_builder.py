"""
Risk Context Builder - Aggregates T, V, I into risk score R.

Implements the risk formula:
    R = I × (w1 × V + w2 × T)

Where:
    I = Impact (asset criticality, 0-1)
    V = Vulnerability (100 - SCA_pass%, 0-100)
    T = Threat (alert count with decay, 0-100)
    w1 = vulnerability weight (default 0.3)
    w2 = threat weight (default 0.7)

Design:
- Fetch latest T, V, I for asset
- Apply time decay for threat score
- Calculate combined risk
- Return components + final score
- Support trend analysis
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from ingestion.asset_service import AssetService
from ingestion.persistence import PersistenceService
from database.connection import get_session
from database.models import Asset, RiskScore
from database import queries
from config.settings import get_settings

logger = logging.getLogger(__name__)


@dataclass
class RiskContext:
    """Risk calculation context for single asset."""
    asset_id: str
    asset: Asset
    
    # Components
    threat_component: float  # T (0-100)
    vulnerability_component: float  # V (0-100)
    impact_component: float  # I (0-1)
    
    # Final score
    risk_score: float  # R (0-100)
    severity: str  # critical, high, medium, low
    
    # Metadata
    timestamp: datetime
    components: dict
    
    def __repr__(self) -> str:
        return (
            f"RiskContext(asset={self.asset_id}, R={self.risk_score:.1f}, "
            f"severity={self.severity}, T={self.threat_component:.1f}, "
            f"V={self.vulnerability_component:.1f}, I={self.impact_component:.2f})"
        )


class RiskContextBuilder:
    """
    Builds risk context by combining threat, vulnerability, and impact.
    """
    
    def __init__(
        self,
        asset_service: Optional[AssetService] = None,
        persistence_service: Optional[PersistenceService] = None,
    ) -> None:
        self._asset_service = asset_service or AssetService()
        self._persistence = persistence_service or PersistenceService()
        self._settings = get_settings()
    
    def build_risk_for_asset(self, asset_id: str) -> Optional[RiskContext]:
        """
        Build complete risk context for single asset.
        
        Orchestrates:
        1. Fetch asset metadata
        2. Calculate vulnerability (V) from latest SCA
        3. Calculate threat (T) from recent alerts + decay
        4. Get impact (I) from asset criticality
        5. Combine into final risk score
        
        Returns:
            RiskContext or None if asset not found
        """
        with get_session() as session:
            # Fetch asset
            asset = queries.get_asset_by_id(session, asset_id)
            if not asset:
                logger.warning("Asset not found | asset_id=%s", asset_id)
                return None
            
            # Calculate components
            impact = self._calculate_impact(asset)
            vulnerability = self._calculate_vulnerability(session, asset_id)
            threat = self._calculate_threat(session, asset_id)
            
            # Combine components
            weighted_threat_vuln = (
                self._settings.weight_vulnerability * vulnerability +
                self._settings.weight_threat * threat
            )
            risk_score = impact * weighted_threat_vuln
            
            # Cap at 100
            risk_score = min(risk_score, 100.0)
            
            # Determine severity
            severity = self._score_to_severity(risk_score)
            
            # Build context
            context = RiskContext(
                asset_id=asset_id,
                asset=asset,
                threat_component=threat,
                vulnerability_component=vulnerability,
                impact_component=impact,
                risk_score=risk_score,
                severity=severity,
                timestamp=datetime.now(timezone.utc),
                components={
                    "formula": f"R = I × (w1×V + w2×T)",
                    "w1_vulnerability": self._settings.weight_vulnerability,
                    "w2_threat": self._settings.weight_threat,
                    "decay_factor": self._settings.decay_factor,
                },
            )
            
            # Persist score
            try:
                self._persistence.persist_risk_score(
                    asset_id=asset_id,
                    risk_score=context.risk_score,
                    threat_component=context.threat_component,
                    vulnerability_component=context.vulnerability_component,
                    impact_component=context.impact_component,
                    components=context.components,
                )
            except Exception as exc:
                logger.error("Failed to persist risk score | error=%s", str(exc))
                # Don't fail the build, persistence is secondary
            
            return context
    
    def build_risk_for_all_assets(self) -> list[RiskContext]:
        """
        Build risk context for all assets.
        
        Returns:
            List of RiskContext objects
        """
        assets = self._asset_service.get_all_assets()
        contexts = []
        
        for asset in assets:
            try:
                context = self.build_risk_for_asset(asset.asset_id)
                if context:
                    contexts.append(context)
            except Exception as exc:
                logger.error(
                    "Failed to build risk context | asset=%s | error=%s",
                    asset.asset_id,
                    str(exc),
                )
        
        return contexts
    
    def _calculate_impact(self, asset: Asset) -> float:
        """
        Calculate impact component (I).
        
        Normalized impact from asset criticality questionnaire:
        I = likert_score / 5.0
        
        Per model:
        - likert_score: 1-5 from criticality questionnaire
        - I: 0.2 to 1.0 (normalized to 0-1 range)
        """
        if not asset.likert_score or asset.likert_score < 1.0:
            return 0.2  # Minimum impact
        
        normalized_impact = asset.likert_score / 5.0
        return min(normalized_impact, 1.0)  # Cap at 1.0
    
    def _calculate_vulnerability(self, session, asset_id: str) -> float:
        """
        Calculate vulnerability component (V).
        
        Per model:
        V = 100 - SCA_pass%
        
        If no recent SCA, returns 50 (neutral/unknown).
        """
        # Get latest SCA snapshot
        latest_sca = queries.get_latest_sca(session, asset_id)
        
        if not latest_sca:
            logger.debug("No SCA data found | asset=%s, using neutral", asset_id)
            return 50.0  # Neutral when unknown
        
        # V = 100 - pass_percentage
        vulnerability = 100.0 - latest_sca.pass_percentage
        return max(0.0, min(vulnerability, 100.0))
    
    def _calculate_threat(self, session, asset_id: str) -> float:
        """
        Calculate threat component (T) with time decay.
        
        Formula:
        T = current_threat_score + (decay_factor × T_prev)
        
        Where:
        - current_threat_score: From recent alerts
        - T_prev: Previous cycle's threat score
        - decay_factor: 0.5 (half-life)
        
        This creates exponential decay: alerts from old cycles
        have diminishing impact.
        """
        # Get T_prev from threat state table
        t_prev = queries.get_threat_state(session, asset_id)
        
        # Get current threat from alerts
        # For now, simplified: would integrate with AlertFetcher in production
        current_threat = self._estimate_current_threat(session, asset_id)
        
        # Apply decay formula
        threat_score = current_threat + (self._settings.decay_factor * t_prev)
        
        # Cap at 100
        threat_score = min(threat_score, 100.0)
        
        # Update T_prev for next cycle
        try:
            self._persistence.persist_threat_state(asset_id, threat_score)
        except Exception as exc:
            logger.warning("Failed to update threat state | error=%s", str(exc))
        
        return threat_score
    
    def _estimate_current_threat(self, session, asset_id: str) -> float:
        """
        Estimate current threat from recent risk scores.
        
        In production: integrate with AlertFetcher for real alert data.
        For now: use trend from recent risk_score records.
        """
        # Get recent risk scores (last 7 days)
        seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
        recent_scores = []
        
        try:
            # Query recent scores
            trend = queries.get_score_trend(session, asset_id, hours=168)  # 7 days
            recent_scores = [score.threat_component for score in trend if score.threat_component]
        except Exception as exc:
            logger.debug("Could not fetch recent threat trends | error=%s", str(exc))
        
        # Average recent threat scores, or return 0
        if recent_scores:
            return sum(recent_scores) / len(recent_scores)
        return 0.0
    
    def _score_to_severity(self, score: float) -> str:
        """Convert risk score (0-100) to severity level."""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        else:
            return "low"
    
    def get_top_risk_assets(self, limit: int = 10) -> list[RiskContext]:
        """
        Get top N assets by risk score.
        
        Args:
            limit: Number of assets to return
            
        Returns:
            Sorted list of RiskContext (highest risk first)
        """
        contexts = self.build_risk_for_all_assets()
        # Sort by risk_score descending
        contexts.sort(key=lambda c: c.risk_score, reverse=True)
        return contexts[:limit]
