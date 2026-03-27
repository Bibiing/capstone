"""Periodic scoring scheduler using APScheduler.

Jobs:
- run_threat_scoring every 4 hours
- run_vulnerability_scoring every 24 hours
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import desc, select

from api.services.scoring_engine import calculate_r, calculate_t, calculate_v, classify_severity
from api.services.wazuh_service import WazuhService
from config.settings import get_settings
from database import queries
from database.connection import get_session
from database.models import AlertSnapshot, Asset, RiskScore

logger = logging.getLogger(__name__)


class ScoringScheduler:
    """Scheduler orchestration for periodic scoring jobs."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.wazuh = WazuhService(self.settings)
        self.scheduler = AsyncIOScheduler(timezone="UTC")

    async def sync_assets_from_wazuh(self) -> None:
        """Synchronize assets table from live Wazuh agents."""
        logger.info("Starting asset sync from Wazuh")

        try:
            agents = await self.wazuh.get_all_agents()
        except Exception as exc:
            logger.exception("Asset sync failed to fetch agents | error=%s", exc)
            return

        now = datetime.now(timezone.utc)
        with get_session() as session:
            synced = 0
            for agent in agents:
                try:
                    queries.upsert_asset_by_agent_id(
                        session,
                        {
                            "agent_id": str(agent.get("agent_id")),
                            "name": agent.get("name") or f"agent-{agent.get('agent_id')}",
                            "ip_address": agent.get("ip_address"),
                            "os_type": agent.get("os_type"),
                            "status": agent.get("status"),
                            "impact_score": 0.5,
                            "updated_at": now,
                        },
                    )
                    synced += 1
                except Exception as exc:
                    logger.exception(
                        "Asset sync upsert failed | agent_id=%s | error=%s",
                        agent.get("agent_id"),
                        exc,
                    )

            logger.info("Asset sync completed | upserted=%d", synced)

    async def run_threat_scoring(self) -> None:
        """Run threat scoring cycle for all assets."""
        now = datetime.now(timezone.utc)
        period_end = now
        period_start = now - timedelta(hours=4)

        logger.info("Starting threat scoring cycle | period=%s..%s", period_start, period_end)

        with get_session() as session:
            assets = session.execute(select(Asset)).scalars().all()

            for asset in assets:
                try:
                    alerts = await self.wazuh.get_alerts_by_agent(
                        agent_id=asset.agent_id,
                        from_time=period_start,
                        to_time=period_end,
                    )

                    latest_score = session.execute(
                        select(RiskScore)
                        .where(RiskScore.asset_id == asset.id)
                        .order_by(desc(RiskScore.calculated_at))
                        .limit(1)
                    ).scalar_one_or_none()

                    t_prev = latest_score.score_t if latest_score else 0.0
                    v_prev = latest_score.score_v if latest_score else 50.0

                    t_now = calculate_t(alerts=alerts, t_previous=t_prev, decay=self.settings.decay_factor)
                    i_now = asset.impact_score if asset.impact_score is not None else 0.5
                    r_now = calculate_r(
                        impact_i=i_now,
                        vulnerability_v=v_prev,
                        threat_t=t_now,
                        w1=self.settings.weight_vulnerability,
                        w2=self.settings.weight_threat,
                    )

                    session.add(
                        RiskScore(
                            asset_id=asset.id,
                            score_i=i_now,
                            score_v=v_prev,
                            score_t=t_now,
                            score_r=r_now,
                            period_start=period_start,
                            period_end=period_end,
                            calculated_at=now,
                        )
                    )

                    snapshots = []
                    for alert in alerts:
                        event_time_raw = alert.get("event_time")
                        try:
                            event_time = datetime.fromisoformat(str(event_time_raw).replace("Z", "+00:00"))
                        except Exception:
                            event_time = now

                        snapshots.append(
                            AlertSnapshot(
                                asset_id=asset.id,
                                rule_level=int(alert.get("level", 0)),
                                rule_id=alert.get("rule_id"),
                                description=alert.get("description"),
                                event_time=event_time,
                                ingested_at=now,
                            )
                        )

                    if snapshots:
                        session.add_all(snapshots)

                    logger.info(
                        "Threat score updated | asset=%s | I=%.2f V=%.2f T=%.2f R=%.2f severity=%s",
                        asset.agent_id,
                        i_now,
                        v_prev,
                        t_now,
                        r_now,
                        classify_severity(r_now),
                    )
                except Exception as exc:
                    logger.exception(
                        "Threat scoring failed for asset_id=%s | error=%s",
                        asset.agent_id,
                        exc,
                    )

    async def run_vulnerability_scoring(self) -> None:
        """Run vulnerability refresh cycle and update latest score per asset."""
        logger.info("Starting vulnerability scoring cycle")

        with get_session() as session:
            assets = session.execute(select(Asset)).scalars().all()

            for asset in assets:
                try:
                    sca_pct = await self.wazuh.get_sca_score(asset.agent_id)
                    v_now = calculate_v(sca_pct)

                    latest_score = session.execute(
                        select(RiskScore)
                        .where(RiskScore.asset_id == asset.id)
                        .order_by(desc(RiskScore.calculated_at))
                        .limit(1)
                    ).scalar_one_or_none()

                    if latest_score is None:
                        logger.warning(
                            "No latest risk score found for asset=%s, skipping V update",
                            asset.agent_id,
                        )
                        continue

                    latest_score.score_v = v_now
                    latest_score.score_r = calculate_r(
                        impact_i=latest_score.score_i,
                        vulnerability_v=v_now,
                        threat_t=latest_score.score_t,
                        w1=self.settings.weight_vulnerability,
                        w2=self.settings.weight_threat,
                    )

                    logger.info(
                        "Vulnerability score updated | asset=%s | V=%.2f | R=%.2f",
                        asset.agent_id,
                        v_now,
                        latest_score.score_r,
                    )
                except Exception as exc:
                    logger.exception(
                        "Vulnerability scoring failed for asset_id=%s | error=%s",
                        asset.agent_id,
                        exc,
                    )

    def start(self) -> None:
        """Register cron jobs and start scheduler."""
        self.scheduler.add_job(self.sync_assets_from_wazuh, "cron", hour="*/6", id="sync_assets_from_wazuh")
        self.scheduler.add_job(self.run_threat_scoring, "cron", hour="*/4", id="run_threat_scoring")
        self.scheduler.add_job(self.run_vulnerability_scoring, "cron", hour="0", id="run_vulnerability_scoring")
        self.scheduler.start()
        logger.info("Scoring scheduler started | asset_sync=6h | threat=4h | vulnerability=24h")


if __name__ == "__main__":
    import asyncio

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    scheduler = ScoringScheduler()
    scheduler.start()

    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        scheduler.scheduler.shutdown(wait=False)
        logger.info("Scoring scheduler stopped")
