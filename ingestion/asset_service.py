"""
Asset Service - Synchronization from Wazuh API to DB.

Manages:
- Fetching agent list from Wazuh API
- Syncing to asset table in DB
- Agent ↔ Asset ID mapping
- Asset criticality scoring

Design:
- Wazuh API is source of truth for agent inventory
- Seed JSON provides criticality scoring (Likert questionnaire)
- DB stores combined view for risk scoring engine

Sync strategy:
- Fetch all agents from Wazuh
- Match against UUID in asset_criticality config
- For new agents: create asset entry with questionnaire defaults
- For existing: update metadata (IP, hostname) if changed
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from ingestion.wazuh_client import WazuhClient
from ingestion.resilience import CircuitBreaker, CircuitBreakerConfig, retry_with_backoff, RetryConfig
from database.connection import get_session
from database.models import Asset
from database import queries
from config.settings import get_settings
from config.asset_registry import ASSET_CRITICALITY

logger = logging.getLogger(__name__)


class AssetService:
    """
    Asset synchronization service.
    
    Maintains consistency between Wazuh agent inventory and database asset table.
    """
    
    def __init__(
        self,
        wazuh_client: Optional[WazuhClient] = None,
        circuit_breaker: Optional[CircuitBreaker] = None,
    ) -> None:
        self._client = wazuh_client or WazuhClient.from_settings()
        self._breaker = circuit_breaker or CircuitBreaker(
            name="wazuh_asset_sync",
            config=CircuitBreakerConfig(failure_threshold=5, timeout_seconds=300),
        )
    
    @retry_with_backoff(RetryConfig(max_attempts=3))
    def sync_agents_to_assets(self) -> dict[str, int]:
        """
        Fetch agents from Wazuh API and sync to DB.
        
        Returns:
            Dict with stats: created, updated, skipped, errors
        """
        if not self._breaker.can_attempt():
            raise RuntimeError(
                f"Circuit breaker OPEN for {self._breaker.name}. "
                f"Wazuh API may be experiencing issues."
            )
        
        try:
            stats = self._sync_impl()
            self._breaker.record_success()
            return stats
        except Exception as exc:
            self._breaker.record_failure()
            logger.error(
                "Asset sync failed (circuit breaker recorded) | error=%s | breaker=%s",
                str(exc),
                self._breaker,
            )
            raise
    
    def _sync_impl(self) -> dict[str, int]:
        """Implementation of sync logic."""
        stats = {"created": 0, "updated": 0, "skipped": 0, "errors": 0}
        
        # Fetch agents from Wazuh
        try:
            agents = self._client.get_agents()
            logger.info("Fetched agents from Wazuh | count=%d", len(agents))
        except Exception as exc:
            logger.error("Failed to fetch agents from Wazuh | error=%s", str(exc))
            raise
        
        # Sync each agent
        with get_session() as session:
            for agent in agents:
                try:
                    stats_delta = self._sync_agent(session, agent)
                    for key, val in stats_delta.items():
                        stats[key] += val
                except Exception as exc:
                    logger.error(
                        "Error syncing agent | agent_id=%s | error=%s",
                        agent.get("id"),
                        str(exc),
                    )
                    stats["errors"] += 1
            
            session.commit()
        
        logger.info(
            "Asset sync complete | created=%d | updated=%d | skipped=%d | errors=%d",
            stats["created"],
            stats["updated"],
            stats["skipped"],
            stats["errors"],
        )
        return stats
    
    def _sync_agent(self, session, agent: dict) -> dict[str, int]:
        """Sync single agent. Returns delta stats."""
        agent_id = agent.get("id")
        hostname = agent.get("name", "unknown")
        ip_address = agent.get("ip", "")
        
        if not agent_id:
            logger.warning("Agent missing ID, skipping | agent=%s", agent)
            return {"skipped": 1}
        
        # Check if asset already exists
        existing = queries.get_asset_by_agent_id(session, agent_id)
        
        if existing:
            # Update IP and metadata if changed
            if existing.ip_address != ip_address or existing.hostname != hostname:
                existing.ip_address = ip_address
                existing.hostname = hostname
                existing.updated_at = datetime.now(timezone.utc)
                logger.info(
                    "Updated asset metadata | asset_id=%s | hostname=%s | ip=%s",
                    existing.asset_id,
                    hostname,
                    ip_address,
                )
            return {"updated": 1}
        
        # Create new asset
        # Use criticality config if available, otherwise default
        criticality = ASSET_CRITICALITY.get(agent_id, {})
        likert_score = float(criticality.get("likert_score", 3.0))  # Default 3.0 (medium)
        
        asset_id = f"asset-{agent_id}"  # Generate asset ID from agent ID
        
        new_asset = Asset(
            asset_id=asset_id,
            hostname=hostname,
            wazuh_agent_id=agent_id,
            ip_address=ip_address,
            likert_score=likert_score,
            description=criticality.get("description", f"Agent {agent_id}"),
        )
        
        session.add(new_asset)
        logger.info(
            "Created asset from Wazuh agent | asset_id=%s | agent_id=%s | hostname=%s",
            asset_id,
            agent_id,
            hostname,
        )
        
        return {"created": 1}
    
    def get_asset_by_agent_id(self, agent_id: str) -> Optional[Asset]:
        """
        Lookup asset by Wazuh agent ID.
        
        Useful for mapping alert/threat data back to asset.
        """
        with get_session() as session:
            return queries.get_asset_by_agent_id(session, agent_id)
    
    def get_all_assets(self) -> list[Asset]:
        """Get all assets from DB."""
        with get_session() as session:
            return queries.get_all_assets(session)
    
    @property
    def circuit_breaker(self) -> CircuitBreaker:
        """Access circuit breaker for monitoring."""
        return self._breaker
    
    @property
    def client(self) -> WazuhClient:
        """Access underlying Wazuh client."""
        return self._client
