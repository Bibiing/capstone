"""
Ingestion Pipeline - Main orchestrator.

Coordinates:
1. Asset sync (Wazuh → DB)
2. Alert fetching & aggregation
3. SCA data collection
4. Risk score calculation
5. Persistence to DB

Design patterns:
- Orchestrator pattern (coordinates multiple services)
- Resilience (retry, circuit breaker, circuit breaker)
- Idempotency (deduplication)
- Observability (logging, metrics)
- Graceful degradation (continue on partial failures)

Execution model:
- Full cycle: asset_sync → fetch_alerts → fetch_sca → build_risk
- Per asset or all assets
- Can be triggered manually or from scheduler
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from ingestion.alert_fetcher import AlertFetcher
from ingestion.sca_fetcher import SCAFetcher
from ingestion.asset_service import AssetService
from ingestion.risk_builder import RiskContext, RiskContextBuilder
from ingestion.persistence import PersistenceService
from ingestion.resilience import CircuitBreaker
from database.connection import get_session
from database import queries

logger = logging.getLogger(__name__)


@dataclass
class PipelineStats:
    """Statistics from pipeline execution."""
    timestamp: datetime
    
    # Asset sync
    assets_created: int = 0
    assets_updated: int = 0
    assets_errors: int = 0
    
    # Alert processing
    alerts_fetched: int = 0
    alerts_errors: int = 0
    
    # SCA processing
    sca_scans_fetched: int = 0
    sca_errors: int = 0
    
    # Risk scoring
    risks_calculated: int = 0
    risks_errors: int = 0
    
    # Timing
    duration_seconds: float = 0.0
    
    def __repr__(self) -> str:
        return (
            f"PipelineStats(assets: {self.assets_created}↑{self.assets_updated}upd, "
            f"alerts: {self.alerts_fetched}, sca: {self.sca_scans_fetched}, "
            f"risks: {self.risks_calculated}, duration: {self.duration_seconds:.1f}s)"
        )


class IngestionPipeline:
    """
    Main ingestion orchestrator.
    
    Coordinates data ingestion from Wazuh → DB → Risk Scoring.
    """
    
    def __init__(
        self,
        asset_service: Optional[AssetService] = None,
        alert_fetcher: Optional[AlertFetcher] = None,
        sca_fetcher: Optional[SCAFetcher] = None,
        risk_builder: Optional[RiskContextBuilder] = None,
        persistence_service: Optional[PersistenceService] = None,
    ) -> None:
        self._asset_service = asset_service or AssetService()
        self._alert_fetcher = alert_fetcher or AlertFetcher()
        self._sca_fetcher = sca_fetcher or SCAFetcher()
        self._risk_builder = risk_builder or RiskContextBuilder()
        self._persistence = persistence_service or PersistenceService()
        
        self._stats: Optional[PipelineStats] = None
    
    def execute_full_cycle(
        self,
        sync_assets: bool = True,
        fetch_alerts: bool = True,
        fetch_sca: bool = True,
        calculate_risks: bool = True,
    ) -> PipelineStats:
        """
        Execute complete ingestion pipeline.
        
        Args:
            sync_assets: Whether to sync Wazuh agents to asset DB
            fetch_alerts: Whether to fetch Wazuh alerts
            fetch_sca: Whether to fetch SCA scan results
            calculate_risks: Whether to calculate risk scores
            
        Returns:
            PipelineStats with execution metrics
        """
        start_time = datetime.now(timezone.utc)
        stats = PipelineStats(timestamp=start_time)
        
        try:
            # Step 1: Sync assets from Wazuh
            if sync_assets:
                logger.info("=== Phase 1: Asset Synchronization ===")
                asset_stats = self._execute_asset_sync()
                stats.assets_created = asset_stats.get("created", 0)
                stats.assets_updated = asset_stats.get("updated", 0)
                stats.assets_errors = asset_stats.get("errors", 0)
            
            # Step 2: Fetch alerts
            if fetch_alerts:
                logger.info("=== Phase 2: Alert Fetching ===")
                alert_count = self._execute_alert_fetch()
                stats.alerts_fetched = alert_count
            
            # Step 3: Fetch SCA scans
            if fetch_sca:
                logger.info("=== Phase 3: SCA Scanning ===")
                sca_count = self._execute_sca_fetch()
                stats.sca_scans_fetched = sca_count
            
            # Step 4: Calculate risk scores
            if calculate_risks:
                logger.info("=== Phase 4: Risk Scoring ===")
                risk_count = self._execute_risk_calculation()
                stats.risks_calculated = risk_count
            
            # Cleanup
            self._cleanup()
            
        except Exception as exc:
            logger.error("Pipeline execution failed | error=%s", str(exc), exc_info=True)
            raise
        finally:
            # Record timing
            end_time = datetime.now(timezone.utc)
            stats.duration_seconds = (end_time - start_time).total_seconds()
            self._stats = stats
        
        logger.info("Pipeline execution complete | stats=%s", stats)
        return stats
    
    def _execute_asset_sync(self) -> dict[str, int]:
        """Execute asset synchronization phase."""
        try:
            stats = self._asset_service.sync_agents_to_assets()
            logger.info("Asset sync completed | stats=%s", stats)
            return stats
        except Exception as exc:
            logger.error("Asset sync failed | error=%s", str(exc))
            return {"created": 0, "updated": 0, "skipped": 0, "errors": 1}
    
    def _execute_alert_fetch(self) -> int:
        """Execute alert fetching phase."""
        try:
            # Get all assets
            assets = self._asset_service.get_all_assets()
            total_alerts = 0
            
            for asset in assets:
                try:
                    if not asset.wazuh_agent_id:
                        continue
                    
                    # Fetch alerts for this asset
                    alerts = self._alert_fetcher.fetch(
                        agent_id=asset.wazuh_agent_id,
                        from_dt=datetime.now(timezone.utc) - timedelta(hours=1),
                    )
                    
                    if alerts.total_count > 0:
                        # Aggregate and persist
                        self._persistence.persist_alert_aggregation(
                            asset_id=asset.asset_id,
                            timestamp=datetime.now(timezone.utc),
                            alert_count_by_level=alerts.count_by_level,
                            total_alerts=alerts.total_count,
                        )
                    
                    total_alerts += alerts.total_count
                    
                except Exception as exc:
                    logger.warning(
                        "Failed to fetch alerts for asset | asset=%s | error=%s",
                        asset.asset_id,
                        str(exc),
                    )
            
            logger.info("Alert fetch completed | total_alerts=%d", total_alerts)
            return total_alerts
            
        except Exception as exc:
            logger.error("Alert fetch phase failed | error=%s", str(exc))
            return 0
    
    def _execute_sca_fetch(self) -> int:
        """Execute SCA fetching phase."""
        try:
            assets = self._asset_service.get_all_assets()
            total_scans = 0
            
            for asset in assets:
                try:
                    if not asset.wazuh_agent_id:
                        continue
                    
                    # Fetch SCA data
                    sca_data = self._sca_fetcher.fetch(
                        agent_id=asset.wazuh_agent_id,
                    )
                    
                    # Persist SCA snapshot
                    self._persistence.persist_sca_snapshot(
                        asset_id=asset.asset_id,
                        scan_timestamp=sca_data.scan_time,
                        pass_percentage=sca_data.pass_percentage,
                        fail_count=sca_data.failed,
                        pass_count=sca_data.passed,
                        score=sca_data.score,
                    )
                    
                    total_scans += 1
                    
                except Exception as exc:
                    logger.warning(
                        "Failed to fetch SCA for asset | asset=%s | error=%s",
                        asset.asset_id,
                        str(exc),
                    )
            
            logger.info("SCA fetch completed | total_scans=%d", total_scans)
            return total_scans
            
        except Exception as exc:
            logger.error("SCA fetch phase failed | error=%s", str(exc))
            return 0
    
    def _execute_risk_calculation(self) -> int:
        """Execute risk score calculation phase."""
        try:
            # Get all assets and calculate risk for each
            contexts = self._risk_builder.build_risk_for_all_assets()
            
            for context in contexts:
                logger.debug("Calculated risk | %s", context)
            
            logger.info("Risk calculation completed | total_assets=%d", len(contexts))
            return len(contexts)
            
        except Exception as exc:
            logger.error("Risk calculation phase failed | error=%s", str(exc))
            return 0
    
    def _cleanup(self) -> None:
        """Cleanup and maintenance tasks."""
        try:
            # Clean expired idempotency keys
            removed = self._persistence.cleanup_expired_idempotency_keys()
            if removed > 0:
                logger.debug("Cleaned up expired idempotency keys | count=%d", removed)
        except Exception as exc:
            logger.warning("Cleanup failed | error=%s", str(exc))
    
    def get_last_stats(self) -> Optional[PipelineStats]:
        """Get statistics from last execution."""
        return self._stats
    
    @property
    def asset_service(self) -> AssetService:
        """Access asset service."""
        return self._asset_service
    
    @property
    def risk_builder(self) -> RiskContextBuilder:
        """Access risk builder."""
        return self._risk_builder
    
    @property
    def circuit_breakers(self) -> list[CircuitBreaker]:
        """Get all circuit breakers for monitoring."""
        return [self._asset_service.circuit_breaker]


if __name__ == "__main__":
    import sys
    
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    
    print("=" * 70)
    print("  Ingestion Pipeline - Full Cycle Execution")
    print("=" * 70)
    
    try:
        pipeline = IngestionPipeline()
        stats = pipeline.execute_full_cycle()
        print(f"\n✓ Pipeline completed successfully")
        print(f"  {stats}")
        
    except Exception as exc:
        print(f"\n✗ Pipeline failed")
        print(f"  {type(exc).__name__}: {exc}")
        sys.exit(1)
