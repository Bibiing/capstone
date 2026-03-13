"""
Threat Hunting fetcher.

Provides a structured backend integration with Wazuh Threat Hunting data
from the Indexer/OpenSearch layer.

Why this module exists:
- AlertFetcher is optimized for risk scoring aggregates (T calculation).
- ThreatHuntingFetcher is optimized for investigative visibility:
  event stream, histogram, level distribution, and top rules.

This aligns backend output with what analysts see on the Wazuh Threat Hunting UI,
while exposing a clean Python interface for API and dashboard layers.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from ingestion.wazuh_client import WazuhAlert, WazuhClient

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ThreatHuntingHistogramPoint:
    """Single histogram bucket (timestamp + event count)."""

    timestamp: str
    count: int


@dataclass(frozen=True)
class ThreatHuntingTopRule:
    """Top rule entry from threat hunting aggregation."""

    rule_id: str
    count: int
    description: str
    level: Optional[int]


@dataclass(frozen=True)
class ThreatHuntingSnapshot:
    """Structured threat hunting snapshot for one agent and time window."""

    agent_id: str
    manager_name: Optional[str]
    window_start: datetime
    window_end: datetime
    interval: str
    total_hits: int
    events: list[WazuhAlert]
    histogram: list[ThreatHuntingHistogramPoint]
    by_rule_level: dict[str, int]
    by_level_group: dict[str, int]
    top_rules: list[ThreatHuntingTopRule]


class ThreatHuntingFetcher:
    """
    Fetches Threat Hunting-style telemetry from Wazuh Indexer.

    This class is intentionally thin and delegates query execution to
    WazuhClient.get_threat_hunting_snapshot(), keeping responsibilities clear:
    - WazuhClient: transport + query implementation
    - ThreatHuntingFetcher: service-level orchestration + typed result
    """

    def __init__(self, client: WazuhClient, default_window_hours: int = 24) -> None:
        self._client = client
        self._default_window_hours = default_window_hours

    @classmethod
    def from_settings(
        cls,
        client: Optional[WazuhClient] = None,
        default_window_hours: int = 24,
    ) -> "ThreatHuntingFetcher":
        return cls(client=client or WazuhClient.from_settings(), default_window_hours=default_window_hours)

    def fetch(
        self,
        agent_id: str,
        manager_name: Optional[str] = "manager",
        from_dt: Optional[datetime] = None,
        to_dt: Optional[datetime] = None,
        interval: str = "30m",
        event_limit: int = 100,
    ) -> ThreatHuntingSnapshot:
        """
        Fetch a threat hunting snapshot for one agent.

        Args:
            agent_id: Wazuh agent ID.
            manager_name: Optional manager.name filter (default: "manager").
            from_dt: Start datetime UTC. Defaults to now - default_window_hours.
            to_dt: End datetime UTC. Defaults to now.
            interval: Histogram bucket width, e.g. "30m", "1h".
            event_limit: Maximum number of event rows returned.
        """
        end = to_dt or datetime.now(timezone.utc)
        start = from_dt or (end - timedelta(hours=self._default_window_hours))

        raw = self._client.get_threat_hunting_snapshot(
            agent_id=agent_id,
            manager_name=manager_name,
            from_dt=start,
            to_dt=end,
            interval=interval,
            event_limit=event_limit,
        )

        snapshot = ThreatHuntingSnapshot(
            agent_id=agent_id,
            manager_name=manager_name,
            window_start=start,
            window_end=end,
            interval=interval,
            total_hits=raw["total_hits"],
            events=raw["events"],
            histogram=[
                ThreatHuntingHistogramPoint(
                    timestamp=point["timestamp"],
                    count=point["count"],
                )
                for point in raw["histogram"]
            ],
            by_rule_level=raw["by_rule_level"],
            by_level_group=raw["by_level_group"],
            top_rules=[
                ThreatHuntingTopRule(
                    rule_id=rule["rule_id"],
                    count=rule["count"],
                    description=rule["description"],
                    level=rule["level"],
                )
                for rule in raw["top_rules"]
            ],
        )

        logger.info(
            "Threat hunting fetch complete | agent=%s hits=%d window=%s..%s",
            agent_id,
            snapshot.total_hits,
            snapshot.window_start.isoformat(),
            snapshot.window_end.isoformat(),
        )
        return snapshot


if __name__ == "__main__":
    import logging
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    print("=" * 60)
    print("  ThreatHuntingFetcher - Demo / Smoke Test")
    print("=" * 60)

    try:
        with WazuhClient.from_settings() as client:
            fetcher = ThreatHuntingFetcher.from_settings(client=client)

            # Auto pick one live agent from recent telemetry.
            now = datetime.now(timezone.utc)
            live_agents = client.get_agent_ids_from_alerts(
                from_dt=now - timedelta(hours=24),
                to_dt=now,
                limit=5,
            )
            if not live_agents:
                print("No live agents found in telemetry (last 24h).")
                sys.exit(0)

            agent_id = live_agents[0]
            snapshot = fetcher.fetch(agent_id=agent_id, manager_name="manager")

            print(f"\nagent_id      : {snapshot.agent_id}")
            print(f"total_hits    : {snapshot.total_hits}")
            print(f"window        : {snapshot.window_start.isoformat()} -> {snapshot.window_end.isoformat()}")
            print(f"level_groups  : {snapshot.by_level_group}")
            print("top_rules     :")
            for rule in snapshot.top_rules[:5]:
                print(f"  - {rule.rule_id} (lvl={rule.level}) x{rule.count} | {rule.description}")
            print(f"event_samples : {len(snapshot.events)}")

    except Exception as exc:
        print(f"\n[ERROR] {type(exc).__name__}: {exc}")
        sys.exit(1)

    print("\n[OK] ThreatHuntingFetcher demo complete.")
