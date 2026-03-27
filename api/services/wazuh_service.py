"""Production-oriented Wazuh integration service.

Exposes the functions described in README:
- get_wazuh_token
- get_all_agents
- get_agent_by_id
- get_sca_score
- get_alerts_by_agent
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from config.settings import Settings, get_settings

logger = logging.getLogger(__name__)


@dataclass
class _TokenCache:
    token: str
    expires_at: datetime

    def valid(self) -> bool:
        # Refresh 60s early to avoid using near-expired token.
        return datetime.now(timezone.utc) < (self.expires_at - timedelta(seconds=60))


class WazuhService:
    """Service wrapper for Wazuh Manager API and Wazuh Indexer."""

    ALERT_INDEX_PATTERN = "wazuh-alerts-4.x-*"

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._token_cache: _TokenCache | None = None

    async def get_wazuh_token(self, force_refresh: bool = False) -> str:
        """Authenticate against Wazuh Manager API and return JWT token."""
        if not force_refresh and self._token_cache and self._token_cache.valid():
            return self._token_cache.token

        auth_path = self.settings.wazuh_api_auth_path
        if self.settings.wazuh_api_auth_use_raw and "raw=true" not in auth_path:
            sep = "&" if "?" in auth_path else "?"
            auth_path = f"{auth_path}{sep}raw=true"
        url = f"{self.settings.wazuh_api_url.rstrip('/')}/{auth_path.lstrip('/')}"

        async with httpx.AsyncClient(verify=self.settings.wazuh_verify_ssl, timeout=self.settings.wazuh_api_timeout) as client:
            response = await client.post(
                url,
                auth=(
                    self.settings.wazuh_api_user,
                    self.settings.wazuh_api_password.get_secret_value(),
                ),
            )

        response.raise_for_status()

        token = response.text.strip().strip('"').strip("'")
        if not token:
            try:
                payload = response.json()
                token = (
                    payload.get("data", {}).get("token")
                    or payload.get("token")
                    or payload.get("data")
                )
            except ValueError:
                token = None

        if not isinstance(token, str) or not token:
            raise RuntimeError("Wazuh auth response does not contain a token")

        self._token_cache = _TokenCache(
            token=token,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=14),
        )
        logger.info("Wazuh JWT token refreshed")
        return token

    async def _manager_get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Authenticated GET helper for Wazuh Manager API."""
        for attempt in (1, 2):
            token = await self.get_wazuh_token(force_refresh=(attempt == 2))
            url = f"{self.settings.wazuh_api_url.rstrip('/')}/{path.lstrip('/')}"
            async with httpx.AsyncClient(
                verify=self.settings.wazuh_verify_ssl,
                timeout=self.settings.wazuh_api_timeout,
            ) as client:
                response = await client.get(
                    url,
                    params=params or {},
                    headers={"Authorization": f"Bearer {token}"},
                )

            if response.status_code == 401 and attempt == 1:
                logger.warning("Wazuh token expired, retrying with refresh")
                continue

            response.raise_for_status()
            return response.json()

        raise RuntimeError("Failed manager request after token refresh")

    async def get_all_agents(self) -> list[dict[str, Any]]:
        """Fetch all agents from Wazuh Manager API."""
        payload = await self._manager_get("/agents", params={"limit": 500, "offset": 0})
        items = payload.get("data", {}).get("affected_items", [])
        results: list[dict[str, Any]] = []
        for item in items:
            results.append(
                {
                    "agent_id": item.get("id"),
                    "name": item.get("name"),
                    "ip_address": item.get("ip"),
                    "os_type": item.get("os", {}).get("platform"),
                    "status": item.get("status"),
                }
            )
        return results

    async def get_agent_by_id(self, agent_id: str) -> dict[str, Any] | None:
        """Fetch one agent detail by Wazuh agent ID."""
        payload = await self._manager_get("/agents", params={"agents_list": agent_id})
        items = payload.get("data", {}).get("affected_items", [])
        if not items:
            return None
        item = items[0]
        return {
            "agent_id": item.get("id"),
            "name": item.get("name"),
            "ip_address": item.get("ip"),
            "os_type": item.get("os", {}).get("platform"),
            "status": item.get("status"),
        }

    async def get_sca_score(self, agent_id: str) -> float:
        """Return SCA pass percentage for one agent.

        If multiple policies exist, use worst pass percentage (conservative).
        """
        payload = await self._manager_get(f"/sca/{agent_id}")
        items = payload.get("data", {}).get("affected_items", [])
        if not items:
            return 0.0

        pass_percentages: list[float] = []
        for item in items:
            if isinstance(item.get("score"), str) and item["score"].endswith("%"):
                try:
                    pass_percentages.append(float(item["score"].replace("%", "")))
                    continue
                except ValueError:
                    pass

            passed = float(item.get("pass", 0))
            failed = float(item.get("fail", 0))
            total = passed + failed
            pass_percentages.append((passed / total) * 100.0 if total > 0 else 0.0)

        return round(min(pass_percentages), 2)

    async def get_alerts_by_agent(
        self,
        agent_id: str,
        from_time: datetime,
        to_time: datetime,
        size: int = 1000,
    ) -> list[dict[str, Any]]:
        """Fetch raw alerts from Wazuh Indexer for an agent and time window."""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"agent.id": agent_id}},
                        {
                            "range": {
                                "timestamp": {
                                    "gte": from_time.isoformat(),
                                    "lte": to_time.isoformat(),
                                }
                            }
                        },
                    ]
                }
            },
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": size,
        }

        url = f"{self.settings.wazuh_indexer_url.rstrip('/')}/{self.ALERT_INDEX_PATTERN}/_search"
        async with httpx.AsyncClient(
            verify=self.settings.wazuh_verify_ssl,
            timeout=self.settings.wazuh_api_timeout,
            auth=(
                self.settings.wazuh_indexer_user,
                self.settings.wazuh_indexer_password.get_secret_value(),
            ),
        ) as client:
            response = await client.post(url, json=query)
        response.raise_for_status()

        payload = response.json()
        hits = payload.get("hits", {}).get("hits", [])

        alerts: list[dict[str, Any]] = []
        for hit in hits:
            src = hit.get("_source", {})
            rule = src.get("rule", {})
            alerts.append(
                {
                    "level": int(rule.get("level", 0)),
                    "rule_id": str(rule.get("id", "")) if rule.get("id") is not None else None,
                    "description": rule.get("description"),
                    "event_time": src.get("timestamp"),
                    "raw": src,
                }
            )

        return alerts
