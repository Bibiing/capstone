"""
SCA Fetcher Service.

Responsible for fetching SCA (Security Configuration Assessment) scan results
from the Wazuh API for a given agent, and returning a structured SCAResult
ready for consumption by the Vulnerability Score (V) calculator.

Multiple SCA policies:
    An agent may be scanned against multiple CIS policies simultaneously
    (e.g. CIS Ubuntu 22.04 + CIS Apache).
    This service uses the WORST-CASE strategy — it picks the policy with the
    lowest pass percentage, producing the highest vulnerability score.
    This is conservative and security-appropriate for a risk engine.

Persistence:
    When `persist=True` (default), each SCA result is stored in sca_snapshots
    for historical auditing and compliance reporting.

Usage:
    from ingestion.sca_fetcher import SCAFetcher

    fetcher = SCAFetcher.from_settings()
    result = fetcher.fetch(agent_id="001", asset_id="asset-001")
    if result:
        print(f"Pass: {result.pass_percentage:.1f}%  →  V = {100 - result.pass_percentage:.1f}")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from config.settings import Settings, get_settings
from database.connection import get_session
from database.models import SCASnapshot
from ingestion.wazuh_client import SCASummary, WazuhClient

logger = logging.getLogger(__name__)


# =============================================================================
# SCAResult DTO
# =============================================================================

@dataclass(frozen=True)
class SCAResult:
    """
    Processed SCA result for a single agent, ready for V score computation.

    Attributes:
        agent_id:        Wazuh agent ID.
        asset_id:        Asset ID in our system (same agent, different namespace).
        policy_id:       CIS policy identifier (e.g. "cis_ubuntu22-04").
        policy_name:     Human-readable policy name.
        pass_count:      Number of checks that passed.
        fail_count:      Number of checks that failed.
        total_checks:    pass_count + fail_count (not_applicable excluded).
        pass_percentage: (pass_count / total_checks) × 100.  Range: 0.0–100.0.
        scanned_at:      UTC timestamp when this fetch occurred.

    Derived vulnerability score:
        V = 100.0 - pass_percentage
    """

    agent_id: str
    asset_id: Optional[str]
    policy_id: str
    policy_name: str
    pass_count: int
    fail_count: int
    total_checks: int
    pass_percentage: float
    scanned_at: datetime

    @property
    def vulnerability_score(self) -> float:
        """V = 100 - pass_percentage. Higher = more vulnerable."""
        return round(100.0 - self.pass_percentage, 2)

    @classmethod
    def fallback(cls, agent_id: str, asset_id: Optional[str] = None) -> "SCAResult":
        """
        Return a neutral SCA result (50% pass) when no SCA data is available.

        A fallback of 50% represents an "unknown" posture — neither fully
        compliant nor fully non-compliant. This prevents a missing SCA from
        dominating the risk score.
        """
        return cls(
            agent_id=agent_id,
            asset_id=asset_id,
            policy_id="fallback",
            policy_name="No SCA data available",
            pass_count=0,
            fail_count=0,
            total_checks=0,
            pass_percentage=50.0,
            scanned_at=datetime.now(timezone.utc),
        )


# =============================================================================
# SCAFetcher
# =============================================================================

class SCAFetcher:
    """
    Fetches SCA scan results from Wazuh and returns a single SCAResult.

    When multiple policies exist for an agent, the worst-case (lowest
    pass_percentage) policy is selected to ensure the most conservative
    vulnerability assessment.

    This class does NOT own the WazuhClient lifecycle.
    """

    def __init__(self, client: WazuhClient, persist: bool = True) -> None:
        self._client = client
        self._persist = persist

    @classmethod
    def from_settings(
        cls,
        client: Optional[WazuhClient] = None,
        settings: Optional[Settings] = None,
        persist: bool = True,
    ) -> "SCAFetcher":
        """
        Factory: create an SCAFetcher from application settings.

        Args:
            client:  Existing WazuhClient to reuse. Creates one if not provided.
            settings: Optional Settings override.
            persist: Whether to store SCA snapshots in the database.
        """
        s = settings or get_settings()
        return cls(
            client=client or WazuhClient.from_settings(s),
            persist=persist,
        )

    def fetch(
        self, agent_id: str, asset_id: Optional[str] = None
    ) -> SCAResult:
        """
        Fetch SCA results for one agent.

        Returns SCAResult.fallback() if the agent has no SCA data or the
        query fails, so a missing SCA does not crash the scoring cycle.

        Args:
            agent_id: Wazuh agent ID (e.g. "001").
            asset_id: Our system's asset ID — used for DB persistence.
                      May be None if the agent is not yet linked to an asset.

        Returns:
            SCAResult with the worst-case policy result.
        """
        summaries: list[SCASummary] = []
        try:
            summaries = self._client.get_sca_summary(agent_id)
        except Exception as exc:
            logger.error(
                "Failed to fetch SCA data for agent %s: %s — using fallback.",
                agent_id,
                exc,
            )
            return SCAResult.fallback(agent_id, asset_id)

        if not summaries:
            logger.warning(
                "No SCA policies found for agent %s — using fallback (50%% pass).",
                agent_id,
            )
            return SCAResult.fallback(agent_id, asset_id)

        # Worst-case strategy: pick the policy with the lowest pass percentage
        worst: SCASummary = min(summaries, key=lambda s: s.pass_percentage)

        if len(summaries) > 1:
            logger.info(
                "Agent %s has %d SCA policies — selected worst: %s (%.1f%% pass).",
                agent_id,
                len(summaries),
                worst.policy_id,
                worst.pass_percentage,
            )

        result = SCAResult(
            agent_id=agent_id,
            asset_id=asset_id,
            policy_id=worst.policy_id,
            policy_name=worst.policy_name,
            pass_count=worst.pass_count,
            fail_count=worst.fail_count,
            total_checks=worst.total_checks,
            pass_percentage=worst.pass_percentage,
            scanned_at=datetime.now(timezone.utc),
        )

        logger.info(
            "SCA result | agent=%s policy=%s pass=%d/%d (%.1f%%) → V=%.1f",
            agent_id,
            worst.policy_id,
            worst.pass_count,
            worst.total_checks,
            worst.pass_percentage,
            result.vulnerability_score,
        )

        if self._persist and asset_id:
            self._store_snapshot(asset_id, result)

        return result

    def _store_snapshot(self, asset_id: str, result: SCAResult) -> None:
        """Persist SCA result to sca_snapshots table. Logs and swallows errors."""
        try:
            with get_session() as session:
                snapshot = SCASnapshot(
                    asset_id=asset_id,
                    policy_id=result.policy_id,
                    policy_name=result.policy_name,
                    pass_count=result.pass_count,
                    fail_count=result.fail_count,
                    not_applicable=0,
                    total_checks=result.total_checks,
                    pass_percentage=result.pass_percentage,
                    scanned_at=result.scanned_at,
                )
                session.add(snapshot)
        except Exception as exc:
            # Non-blocking: persistence failure should not abort the scoring cycle
            logger.warning(
                "Failed to persist SCA snapshot for asset %s: %s", asset_id, exc
            )


# =============================================================================
# Demo / Smoke Test
# =============================================================================

if __name__ == "__main__":
    import sys
    import logging
    from datetime import timedelta

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    print("=" * 60)
    print("  SCAFetcher — Demo / Smoke Test")
    print("=" * 60)

    try:
        with WazuhClient.from_settings() as wazuh:
            # persist=False — keep demo non-destructive
            fetcher = SCAFetcher.from_settings(client=wazuh, persist=False)

            now = datetime.now(timezone.utc)
            demo_agents = wazuh.get_agent_ids_from_alerts(
                from_dt=now - timedelta(hours=24),
                to_dt=now,
                limit=5,
            )
            if not demo_agents:
                print("No live agents found in last 24h telemetry.")
                sys.exit(0)

            print(f"Live agents from telemetry: {', '.join(demo_agents)}")

            for agent_id in demo_agents:
                result = fetcher.fetch(agent_id=agent_id, asset_id=None)
                print(
                    f"\nagent={result.agent_id}  asset={result.asset_id}"
                    f"\n  policy : {result.policy_id} — {result.policy_name}"
                    f"\n  pass   : {result.pass_count}/{result.total_checks} "
                    f"({result.pass_percentage:.1f}%)"
                    f"\n  V score: {result.vulnerability_score:.1f}"
                )
    except Exception as exc:
        print(f"\n[ERROR] {type(exc).__name__}: {exc}")
        print("Hint: check .env credentials and Wazuh endpoint reachability.")
        sys.exit(1)

    print("\n[OK] SCAFetcher demo complete.")
