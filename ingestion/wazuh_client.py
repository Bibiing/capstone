"""
Wazuh unified HTTP client.

Architecture:
    _WazuhAPIClient      Low-level client for the Wazuh Manager REST API.
                         Uses JWT Bearer token authentication with automatic
                         token caching and transparent refresh.

    _WazuhIndexerClient  Low-level client for the Wazuh Indexer (OpenSearch).
                         Uses HTTP Basic authentication on every request.

    WazuhClient          Public facade combining both clients with a clean,
                         business-level interface. This is the only class
                         consumers should instantiate.

Security:
    - Credentials are sourced exclusively from Settings (env vars). Never hardcoded.
    - SSL verification is configurable (disable only for self-signed lab certs).
    - JWT tokens are stored in memory only and never written to logs.
    - Passwords use pydantic SecretStr and are accessed only inside this module.

Retry behaviour:
    - Connection errors and 5xx responses are retried with exponential back-off.
    - Authentication errors (401/403) are NOT retried — they signal config issues.
    - A 401 on a live request triggers a one-time silent token refresh before failing.

Usage:
    # As context manager (recommended — ensures connections are released)
    with WazuhClient.from_settings() as client:
        agents = client.get_agents()
        counts = client.count_alerts_by_level("001", from_dt, to_dt)

    # Explicit lifecycle
    client = WazuhClient.from_settings()
    try:
        summary = client.get_sca_summary("001")
    finally:
        client.close()
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from config.settings import Settings, get_settings
from ingestion.exceptions import (
    WazuhAPIError,
    WazuhAuthenticationError,
    WazuhConnectionError,
    WazuhError,
    WazuhRateLimitError,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Data Transfer Objects (DTOs)
# =============================================================================
@dataclass(frozen=True)
class WazuhAgent:
    """Represents a Wazuh-monitored agent (server / workstation)."""

    agent_id: str
    name: str
    ip: str
    status: str                      # active | disconnected | never_connected
    os_platform: Optional[str] = None
    os_name: Optional[str] = None


@dataclass(frozen=True)
class SCASummary:
    """SCA scan result for one agent under one CIS policy."""

    agent_id: str
    policy_id: str
    policy_name: str
    pass_count: int
    fail_count: int
    not_applicable: int

    @property
    def total_checks(self) -> int:
        """Relevant checks = pass + fail (not_applicable excluded)."""
        return self.pass_count + self.fail_count

    @property
    def pass_percentage(self) -> float:
        """Pass rate as a percentage (0.0 – 100.0)."""
        if self.total_checks == 0:
            return 0.0
        return round((self.pass_count / self.total_checks) * 100, 2)


@dataclass(frozen=True)
class WazuhAlert:
    """A single alert event from Wazuh."""

    alert_id: str
    agent_id: str
    agent_name: str
    rule_level: int
    rule_id: str
    rule_description: str
    timestamp: datetime
    source_ip: Optional[str] = None
    mitre_tactics: list[str] = field(default_factory=list)


# =============================================================================
# Internal — JWT Token Cache
# =============================================================================
@dataclass
class _JWTToken:
    """Cached JWT token with expiry awareness."""

    value: str
    expires_at: datetime
    # Refresh 60 seconds before actual expiry to avoid mid-request failures
    _BUFFER_SECONDS: int = 60

    def is_valid(self) -> bool:
        return datetime.now(timezone.utc) < (
            self.expires_at - timedelta(seconds=self._BUFFER_SECONDS)
        )


# =============================================================================
# Internal — Wazuh Manager REST API Client
# =============================================================================

class _WazuhAPIClient:
    """
    Low-level HTTP client for the Wazuh Manager REST API (JWT auth).

    Wazuh JWT tokens expire after 900 seconds (15 minutes) by default.
    This client caches the token and re-authenticates automatically when
    the token is about to expire or a 401 is received mid-session.
    """

    _TOKEN_TTL_SECONDS: int = 900

    def __init__(self, settings: Settings) -> None:
        self._base_url = settings.wazuh_api_url
        self._user = settings.wazuh_api_user
        self._password = settings.wazuh_api_password          # SecretStr
        self._verify_ssl = settings.wazuh_verify_ssl
        self._token: Optional[_JWTToken] = None

        if not self._verify_ssl:
            # Suppress urllib3 InsecureRequestWarning for self-signed certs
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self._http = httpx.Client(
            base_url=self._base_url,
            verify=self._verify_ssl,
            timeout=httpx.Timeout(settings.wazuh_api_timeout),
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            headers={"Content-Type": "application/json"},
        )

    # ── Authentication ─────────────────────────────────────────────────────────

    def _authenticate(self) -> None:
        """Fetch a fresh JWT token and cache it. Raises on auth failure."""
        logger.debug("Authenticating to Wazuh API | user=%s", self._user)
        try:
            resp = self._http.post(
                "/security/user/authenticate",
                auth=(self._user, self._password.get_secret_value()),
            )
        except httpx.ConnectError as exc:
            raise WazuhConnectionError(
                f"Cannot connect to Wazuh API at {self._base_url}: {exc}"
            ) from exc
        except httpx.TimeoutException as exc:
            raise WazuhConnectionError(
                f"Wazuh API authentication timed out: {exc}"
            ) from exc

        if resp.status_code == 401:
            raise WazuhAuthenticationError(
                "Wazuh API: invalid credentials. Check WAZUH_API_USER / WAZUH_API_PASSWORD."
            )
        if resp.status_code == 403:
            raise WazuhAuthenticationError(
                "Wazuh API: authentication succeeded but user has insufficient permissions."
            )
        if resp.status_code == 404:
            raise WazuhAuthenticationError(
                "Wazuh API authentication endpoint not found (404). "
                "Check WAZUH_API_URL (host/port/path), usually manager API listens on :55000."
            )
        if resp.status_code >= 500:
            raise WazuhAPIError(
                f"Wazuh API server error during auth: {resp.text}", resp.status_code
            )
        if resp.status_code != 200:
            raise WazuhAPIError(
                f"Unexpected auth response {resp.status_code}: {resp.text}",
                resp.status_code,
            )

        token_str = resp.json()["data"]["token"]
        self._token = _JWTToken(
            value=token_str,
            expires_at=datetime.now(timezone.utc)
            + timedelta(seconds=self._TOKEN_TTL_SECONDS),
        )
        logger.info("Wazuh API authentication successful.")

    def _get_auth_headers(self) -> dict[str, str]:
        """Return Authorization header. Re-authenticates if token is expired."""
        if self._token is None or not self._token.is_valid():
            self._authenticate()
        return {"Authorization": f"Bearer {self._token.value}"}  # type: ignore[union-attr]

    # ── HTTP Methods ───────────────────────────────────────────────────────────

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((WazuhConnectionError, WazuhAPIError)),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )
    def get(self, path: str, params: dict | None = None) -> Any:
        """
        Authenticated GET against the Wazuh API.

        Transparently refreshes the JWT on a 401 (once).
        Retries automatically on connection errors and 5xx responses.
        """
        for attempt in range(2):
            try:
                resp = self._http.get(
                    path,
                    headers=self._get_auth_headers(),
                    params=params or {},
                )
            except httpx.ConnectError as exc:
                raise WazuhConnectionError(str(exc)) from exc
            except httpx.TimeoutException:
                raise WazuhConnectionError(f"Request timed out: GET {path}")

            if resp.status_code == 401 and attempt == 0:
                # Token may have expired between the is_valid() check and the request
                logger.warning("Received 401 — refreshing JWT and retrying once.")
                self._token = None
                continue

            self._raise_for_status(resp, context=f"GET {path}")
            return resp.json()

        # Should never reach here; retry loop always returns or raises
        raise WazuhAPIError(f"Unexpected retry exhaustion for GET {path}")

    @staticmethod
    def _raise_for_status(resp: httpx.Response, context: str = "") -> None:
        """Map HTTP error codes to typed exceptions."""
        if resp.status_code == 401:
            raise WazuhAuthenticationError(f"Unauthorized {context}")
        if resp.status_code == 403:
            raise WazuhAuthenticationError(f"Forbidden {context}")
        if resp.status_code == 404:
            raise WazuhAPIError(f"Not found: {context}", 404)
        if resp.status_code == 429:
            raise WazuhRateLimitError("Wazuh API rate limit exceeded.")
        if resp.status_code >= 500:
            raise WazuhAPIError(
                f"Server error {resp.status_code} on {context}: {resp.text[:200]}",
                resp.status_code,
            )
        if not resp.is_success:
            raise WazuhAPIError(
                f"Unexpected {resp.status_code} on {context}: {resp.text[:200]}",
                resp.status_code,
            )

    def close(self) -> None:
        self._http.close()


# =============================================================================
# Internal — Wazuh Indexer (OpenSearch) Client
# =============================================================================

class _WazuhIndexerClient:
    """
    Low-level client for the Wazuh Indexer (OpenSearch).

    Uses HTTP Basic authentication on every request.
    Primarily used for alert aggregation queries via the OpenSearch DSL.
    """

    def __init__(self, settings: Settings) -> None:
        self._base_url = settings.wazuh_indexer_url
        self._verify_ssl = settings.wazuh_verify_ssl

        if not self._verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Basic auth passed as a tuple — httpx handles the Authorization header
        self._http = httpx.Client(
            base_url=self._base_url,
            verify=self._verify_ssl,
            auth=(
                settings.wazuh_indexer_user,
                settings.wazuh_indexer_password.get_secret_value(),
            ),
            timeout=httpx.Timeout(60.0),  # Aggregation queries can be slow
            limits=httpx.Limits(max_connections=5, max_keepalive_connections=3),
            headers={"Content-Type": "application/json"},
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=15),
        retry=retry_if_exception_type((WazuhConnectionError, WazuhAPIError)),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )
    def search(self, index_pattern: str, query: dict) -> dict:
        """
        Execute an OpenSearch DSL query.

        Args:
            index_pattern: Index name or wildcard (e.g. "wazuh-alerts-4.x-*").
            query:          Full OpenSearch query body as a Python dict.

        Returns:
            Raw OpenSearch response as a dict.
        """
        try:
            resp = self._http.post(f"/{index_pattern}/_search", json=query)
        except httpx.ConnectError as exc:
            raise WazuhConnectionError(
                f"Cannot connect to Wazuh Indexer at {self._base_url}: {exc}"
            ) from exc
        except httpx.TimeoutException:
            raise WazuhConnectionError("Wazuh Indexer query timed out.")

        if resp.status_code == 401:
            raise WazuhAuthenticationError(
                "Wazuh Indexer: invalid credentials. Check WAZUH_INDEXER_USER / WAZUH_INDEXER_PASSWORD."
            )
        if resp.status_code >= 500:
            raise WazuhAPIError(
                f"Indexer error {resp.status_code}: {resp.text[:200]}", resp.status_code
            )
        if not resp.is_success:
            raise WazuhAPIError(
                f"Indexer error {resp.status_code}: {resp.text[:200]}", resp.status_code
            )

        return resp.json()

    def close(self) -> None:
        self._http.close()


# =============================================================================
# Public Facade — WazuhClient
# =============================================================================

class WazuhClient:
    """
    Unified Wazuh data access facade.

    Combines the API client (JWT) and Indexer client (Basic auth) behind
    a single, clean interface. This is the only class consumers should use.

    Instantiation:
        client = WazuhClient.from_settings()

    Always release connections when done:
        client.close()

    Or use the context manager (recommended):
        with WazuhClient.from_settings() as client:
            agents = client.get_agents()
    """

    # Default OpenSearch index pattern for Wazuh alerts
    ALERT_INDEX = "wazuh-alerts-4.x-*"

    def __init__(
        self,
        api_client: _WazuhAPIClient,
        indexer_client: _WazuhIndexerClient,
    ) -> None:
        self._api = api_client
        self._indexer = indexer_client

    @classmethod
    def from_settings(cls, settings: Optional[Settings] = None) -> "WazuhClient":
        """
        Factory: create a WazuhClient from application settings.

        Args:
            settings: Optional Settings instance. Defaults to get_settings().
        """
        s = settings or get_settings()
        return cls(
            api_client=_WazuhAPIClient(s),
            indexer_client=_WazuhIndexerClient(s),
        )

    # ── Wazuh API Methods ──────────────────────────────────────────────────────

    def get_agents(self, status: str = "active") -> list[WazuhAgent]:
        """
        Return a list of Wazuh agents.

        Args:
            status: Filter by agent status.
                    Options: "active", "disconnected", "never_connected", "all".

        Returns:
            List of WazuhAgent DTOs.
        """
        params: dict[str, Any] = {"limit": 500, "offset": 0}
        if status != "all":
            params["status"] = status

        data = self._api.get("/agents", params=params)
        agents = []
        for item in data.get("data", {}).get("affected_items", []):
            agents.append(
                WazuhAgent(
                    agent_id=item["id"],
                    name=item["name"],
                    ip=item.get("ip", "unknown"),
                    status=item.get("status", "unknown"),
                    os_platform=item.get("os", {}).get("platform"),
                    os_name=item.get("os", {}).get("name"),
                )
            )
        logger.info("Fetched %d agents (status=%s)", len(agents), status)
        return agents

    def get_sca_summary(self, agent_id: str) -> list[SCASummary]:
        """
        Return SCA scan summaries for an agent.

        An agent may have multiple active SCA policies (e.g. CIS Ubuntu + CIS Apache).
        Each policy is returned as a separate SCASummary.
        Returns an empty list if the agent has no SCA data yet.

        Args:
            agent_id: Wazuh agent ID string (e.g. "001").
        """
        try:
            data = self._api.get(f"/sca/{agent_id}")
        except WazuhAPIError as exc:
            if exc.status_code == 400:
                logger.warning("No SCA data available for agent %s", agent_id)
                return []
            raise

        summaries = []
        for item in data.get("data", {}).get("affected_items", []):
            summaries.append(
                SCASummary(
                    agent_id=agent_id,
                    policy_id=item.get("policy_id", "unknown"),
                    policy_name=item.get("name", "unknown"),
                    pass_count=item.get("pass", 0),
                    fail_count=item.get("fail", 0),
                    not_applicable=item.get("not_applicable", 0),
                )
            )
        logger.debug("Fetched %d SCA policies for agent %s", len(summaries), agent_id)
        return summaries

    # ── Wazuh Indexer Methods ──────────────────────────────────────────────────

    def count_alerts_by_level(
        self,
        agent_id: str,
        from_dt: datetime,
        to_dt: datetime,
    ) -> dict[str, int]:
        """
        Return alert counts grouped by severity level for a time window.

        This is the primary data source for computing the Threat Score (T).
        Uses a single aggregation query — efficient even for large alert volumes.

        Level groupings (matching the risk formula weights):
            low      → rule.level  0–4   (weight  1)
            medium   → rule.level  5–7   (weight  5)
            high     → rule.level  8–11  (weight 10)
            critical → rule.level 12–15  (weight 25)

        Args:
            agent_id: Wazuh agent ID.
            from_dt:  Start of the time window (UTC, inclusive).
            to_dt:    End of the time window (UTC, inclusive).

        Returns:
            dict with keys "low", "medium", "high", "critical".
        """
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"agent.id": agent_id}},
                        {
                            "range": {
                                "timestamp": {
                                    "gte": from_dt.isoformat(),
                                    "lte": to_dt.isoformat(),
                                }
                            }
                        },
                    ]
                }
            },
            "aggs": {
                "by_level": {
                    "range": {
                        "field": "rule.level",
                        "ranges": [
                            {"key": "low",      "from": 0,  "to": 5},
                            {"key": "medium",   "from": 5,  "to": 8},
                            {"key": "high",     "from": 8,  "to": 12},
                            {"key": "critical", "from": 12, "to": 16},
                        ],
                    }
                }
            },
            "size": 0,  # Aggregation only — do not return individual documents
        }

        resp = self._indexer.search(self.ALERT_INDEX, query)
        buckets = resp.get("aggregations", {}).get("by_level", {}).get("buckets", [])

        counts: dict[str, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for bucket in buckets:
            name = bucket.get("key", "").lower()
            if name in counts:
                counts[name] = int(bucket.get("doc_count", 0))

        logger.info(
            "Alert counts | agent=%s window=[%s – %s] low=%d medium=%d high=%d critical=%d",
            agent_id,
            from_dt.strftime("%Y-%m-%d %H:%M"),
            to_dt.strftime("%Y-%m-%d %H:%M"),
            counts["low"],
            counts["medium"],
            counts["high"],
            counts["critical"],
        )
        return counts

    def get_recent_alerts(
        self,
        agent_id: str,
        from_dt: datetime,
        to_dt: datetime,
        size: int = 50,
    ) -> list[WazuhAlert]:
        """
        Return individual recent alert records for a given agent and time window.

        For standard scoring, prefer count_alerts_by_level() (more efficient).
        Use this for drill-down views or manual inspection.

        Args:
            agent_id: Wazuh agent ID.
            from_dt:  Start datetime (UTC).
            to_dt:    End datetime (UTC).
            size:     Max number of alerts to return (default: 50).
        """
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"agent.id": agent_id}},
                        {
                            "range": {
                                "timestamp": {
                                    "gte": from_dt.isoformat(),
                                    "lte": to_dt.isoformat(),
                                }
                            }
                        },
                    ]
                }
            },
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": size,
        }

        resp = self._indexer.search(self.ALERT_INDEX, query)
        hits = resp.get("hits", {}).get("hits", [])

        alerts = []
        for hit in hits:
            src = hit.get("_source", {})
            rule = src.get("rule", {})
            mitre = rule.get("mitre", {}) if isinstance(rule.get("mitre"), dict) else {}

            ts_str = src.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                ts = datetime.now(timezone.utc)

            alerts.append(
                WazuhAlert(
                    alert_id=hit.get("_id", ""),
                    agent_id=src.get("agent", {}).get("id", agent_id),
                    agent_name=src.get("agent", {}).get("name", ""),
                    rule_level=rule.get("level", 0),
                    rule_id=str(rule.get("id", "")),
                    rule_description=rule.get("description", ""),
                    timestamp=ts,
                    source_ip=src.get("data", {}).get("srcip"),
                    mitre_tactics=mitre.get("tactic", []),
                )
            )

        return alerts

    def get_agent_ids_from_alerts(
        self,
        from_dt: datetime,
        to_dt: datetime,
        limit: int = 50,
    ) -> list[str]:
        """
        Return distinct agent IDs seen in alert telemetry for a time window.

        This method is indexer-only and does not require Wazuh Manager API access.
        Useful for live demos when indexer is reachable but manager API is not.
        """
        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "timestamp": {
                                    "gte": from_dt.isoformat(),
                                    "lte": to_dt.isoformat(),
                                }
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "by_agent": {
                    "terms": {
                        "field": "agent.id",
                        "size": limit,
                    }
                }
            },
            "size": 0,
        }

        resp = self._indexer.search(self.ALERT_INDEX, query)
        buckets = resp.get("aggregations", {}).get("by_agent", {}).get("buckets", [])
        return [str(b.get("key", "")) for b in buckets if b.get("key")]

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def close(self) -> None:
        """Release all underlying HTTP connections back to the pool."""
        self._api.close()
        self._indexer.close()
        logger.debug("WazuhClient connections closed.")

    def __enter__(self) -> "WazuhClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


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
    print("  WazuhClient — Demo / Smoke Test")
    print("=" * 60)

    try:
        with WazuhClient.from_settings() as client:
            now = datetime.now(timezone.utc)

            # ── 1. List active agents (API) with indexer fallback ──────────
            agent_id: Optional[str] = None
            try:
                agents = client.get_agents(status="active")
                print(f"\n[1] Active agents (API): {len(agents)}")
                for a in agents[:5]:
                    print(
                        f"    • {a.agent_id}  {a.name:<25}  ip={a.ip}  status={a.status}"
                    )
                if agents:
                    agent_id = agents[0].agent_id
            except WazuhError as exc:
                print(f"\n[1] Active agents (API): unavailable ({type(exc).__name__})")
                print("    Falling back to live indexer telemetry for agent discovery.")

            if agent_id is None:
                discovered = client.get_agent_ids_from_alerts(
                    from_dt=now - timedelta(hours=24),
                    to_dt=now,
                    limit=10,
                )
                print(f"\n[1b] Agents seen in alerts (Indexer, 24h): {len(discovered)}")
                for aid in discovered[:5]:
                    print(f"    • {aid}")
                if discovered:
                    agent_id = discovered[0]

            if agent_id is None:
                print("    (no live agents found in API nor telemetry)")
                sys.exit(0)

            # ── 2. Alert counts for selected agent (last 24 h) ─────────────
            counts = client.count_alerts_by_level(
                agent_id, now - timedelta(hours=24), now
            )
            print(f"\n[2] Alert counts (last 24 h) for agent {agent_id}:")
            for level, cnt in counts.items():
                print(f"    {level:<10}: {cnt}")
            t_new = (
                counts["low"] * 1
                + counts["medium"] * 5
                + counts["high"] * 10
                + counts["critical"] * 25
            )
            print(f"    T_new_raw = {t_new}")

            # ── 3. SCA summary for selected agent (API-required) ───────────
            try:
                sca_list = client.get_sca_summary(agent_id)
                print(f"\n[3] SCA policies for agent {agent_id}: {len(sca_list)}")
                for p in sca_list:
                    print(
                        f"    • {p.policy_id:<35}  "
                        f"pass={p.pass_percentage:.1f}%  "
                        f"({p.pass_count}/{p.total_checks})"
                    )
            except WazuhError as exc:
                print(
                    f"\n[3] SCA policies: unavailable ({type(exc).__name__}) "
                    "— requires Wazuh Manager API connectivity."
                )

    except Exception as exc:
        print(f"\n[ERROR] {type(exc).__name__}: {exc}")
        print("\nHint: check .env credentials and Wazuh endpoint reachability.")
        print("Offline demo: python -m ingestion.asset_registry list")
        sys.exit(1)

    print("\n[OK] WazuhClient smoke test passed.")
