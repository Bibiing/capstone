"""
Alert Fetcher Service.

Responsible for fetching and classifying Wazuh alerts for a given agent
within the current scoring window, and returning a structured AlertCounts
object ready for consumption by the Threat Score calculator.

This service is stateless — it reads from Wazuh and returns data.
Time-window management (lookback hours) is handled here,
not in the WazuhClient.

Usage:
    from ingestion.alert_fetcher import AlertFetcher

    fetcher = AlertFetcher.from_settings()
    counts = fetcher.fetch("001")
    print(counts.total, counts.high, counts.critical)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from config.settings import Settings, get_settings
from ingestion.wazuh_client import WazuhClient

logger = logging.getLogger(__name__)


# =============================================================================
# AlertCounts DTO
# =============================================================================

@dataclass(frozen=True)
class AlertCounts:
    """
    Structured alert count snapshot for one agent in one time window.

    Passed directly to the Threat Score calculator in the scoring engine.

    Attributes:
        agent_id:       Wazuh agent ID.
        window_start:   Inclusive start of the alert query window (UTC).
        window_end:     Inclusive end of the alert query window (UTC).
        low:            Alerts at level 0–4  (weight 1 in threat formula).
        medium:         Alerts at level 5–7  (weight 5 in threat formula).
        high:           Alerts at level 8–11 (weight 10 in threat formula).
        critical:       Alerts at level 12–15 (weight 25 in threat formula).
        total:          Sum of all level groups.
    """

    agent_id: str
    window_start: datetime
    window_end: datetime
    low: int
    medium: int
    high: int
    critical: int
    total: int

    @classmethod
    def empty(cls, agent_id: str) -> "AlertCounts":
        """
        Return a zero-count AlertCounts for agents with no alerts.

        Used as a safe fallback when Wazuh returns no data, so the scoring
        engine can still compute a (low) T score without crashing.
        """
        now = datetime.now(timezone.utc)
        return cls(
            agent_id=agent_id,
            window_start=now,
            window_end=now,
            low=0, medium=0, high=0, critical=0,
            total=0,
        )


# =============================================================================
# AlertFetcher
# =============================================================================

class AlertFetcher:
    """
    Fetches and classifies Wazuh alerts for a single agent per scoring cycle.

    Determines the lookback window based on ALERT_LOOKBACK_HOURS from settings,
    delegates the actual HTTP query to WazuhClient, and returns an AlertCounts.

    This class does NOT own the WazuhClient lifecycle — the caller is responsible
    for creating and closing the client (or passing it as a context manager).
    """

    def __init__(self, client: WazuhClient, lookback_hours: int) -> None:
        self._client = client
        self._lookback_hours = lookback_hours

    @classmethod
    def from_settings(
        cls,
        client: Optional[WazuhClient] = None,
        settings: Optional[Settings] = None,
    ) -> "AlertFetcher":
        """
        Factory: create an AlertFetcher from application settings.

        Args:
            client:   Existing WazuhClient to reuse. Creates one if not provided.
            settings: Optional Settings override (useful in tests).
        """
        s = settings or get_settings()
        return cls(
            client=client or WazuhClient.from_settings(s),
            lookback_hours=s.alert_lookback_hours,
        )

    def fetch(self, agent_id: str) -> AlertCounts:
        """
        Fetch alert counts for one agent for the current lookback window.

        The window is computed at call time:
            window_start = now - ALERT_LOOKBACK_HOURS
            window_end   = now

        Returns AlertCounts.empty() if the query fails with a non-fatal error,
        so a single agent failure does not abort the entire scoring cycle.

        Args:
            agent_id: Wazuh agent ID (e.g. "001").

        Returns:
            AlertCounts with counts per severity level.
        """
        window_end = datetime.now(timezone.utc)
        window_start = window_end - timedelta(hours=self._lookback_hours)

        try:
            raw_counts = self._client.count_alerts_by_level(
                agent_id=agent_id,
                from_dt=window_start,
                to_dt=window_end,
            )
        except Exception as exc:
            logger.error(
                "Failed to fetch alert counts for agent %s: %s — returning zero counts.",
                agent_id,
                exc,
            )
            return AlertCounts.empty(agent_id)

        total = sum(raw_counts.values())

        counts = AlertCounts(
            agent_id=agent_id,
            window_start=window_start,
            window_end=window_end,
            low=raw_counts["low"],
            medium=raw_counts["medium"],
            high=raw_counts["high"],
            critical=raw_counts["critical"],
            total=total,
        )

        if total > 0:
            logger.info(
                "Alert summary | agent=%s total=%d (low=%d medium=%d high=%d critical=%d)",
                agent_id, total,
                counts.low, counts.medium, counts.high, counts.critical,
            )
        else:
            logger.debug("No alerts in window for agent %s", agent_id)

        return counts


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
    print("  AlertFetcher — Demo / Smoke Test")
    print("=" * 60)

    try:
        with WazuhClient.from_settings() as wazuh:
            fetcher = AlertFetcher.from_settings(client=wazuh)

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
                counts = fetcher.fetch(agent_id)
                t_new = (
                    counts.low * 1
                    + counts.medium * 5
                    + counts.high * 10
                    + counts.critical * 25
                )
                print(
                    f"\nagent={counts.agent_id}  total={counts.total}  "
                    f"[low={counts.low} medium={counts.medium} "
                    f"high={counts.high} critical={counts.critical}]"
                )
                print(f"  → T_new_raw = {t_new}")
    except Exception as exc:
        print(f"\n[ERROR] {type(exc).__name__}: {exc}")
        print("Hint: check .env credentials and Wazuh endpoint reachability.")
        sys.exit(1)

    print("\n[OK] AlertFetcher demo complete.")
