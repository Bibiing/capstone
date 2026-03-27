from __future__ import annotations

from datetime import datetime, timezone

import pytest

from api.services.wazuh_service import WazuhService
from config.settings import get_settings


class _FakeResponse:
    def __init__(self, status_code: int = 200, text: str = "", payload: dict | None = None):
        self.status_code = status_code
        self.text = text
        self._payload = payload or {}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"http error {self.status_code}")

    def json(self) -> dict:
        return self._payload


@pytest.mark.asyncio
async def test_get_wazuh_token_uses_cache(monkeypatch):
    settings = get_settings()
    post_calls = {"count": 0}

    class _FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, auth=None, json=None):
            post_calls["count"] += 1
            return _FakeResponse(status_code=200, text='"jwt-token"')

    monkeypatch.setattr("api.services.wazuh_service.httpx.AsyncClient", _FakeAsyncClient)

    service = WazuhService(settings)
    first = await service.get_wazuh_token()
    second = await service.get_wazuh_token()

    assert first == "jwt-token"
    assert second == "jwt-token"
    assert post_calls["count"] == 1


@pytest.mark.asyncio
async def test_get_all_agents_maps_fields(monkeypatch):
    service = WazuhService(get_settings())

    async def _fake_manager_get(path: str, params=None):
        return {
            "data": {
                "affected_items": [
                    {
                        "id": "001",
                        "name": "db-prod-01",
                        "ip": "10.0.0.10",
                        "os": {"platform": "linux"},
                        "status": "active",
                    }
                ]
            }
        }

    monkeypatch.setattr(service, "_manager_get", _fake_manager_get)

    agents = await service.get_all_agents()

    assert len(agents) == 1
    assert agents[0]["agent_id"] == "001"
    assert agents[0]["name"] == "db-prod-01"
    assert agents[0]["ip_address"] == "10.0.0.10"


@pytest.mark.asyncio
async def test_get_alerts_by_agent_parses_indexer_hits(monkeypatch):
    settings = get_settings()

    class _FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, auth=None, json=None):
            return _FakeResponse(
                status_code=200,
                payload={
                    "hits": {
                        "hits": [
                            {
                                "_source": {
                                    "timestamp": "2026-03-27T10:00:00Z",
                                    "rule": {
                                        "id": 5710,
                                        "level": 8,
                                        "description": "Failed SSH login",
                                    },
                                }
                            }
                        ]
                    }
                },
            )

    monkeypatch.setattr("api.services.wazuh_service.httpx.AsyncClient", _FakeAsyncClient)

    service = WazuhService(settings)
    alerts = await service.get_alerts_by_agent(
        agent_id="001",
        from_time=datetime(2026, 3, 27, 9, 0, tzinfo=timezone.utc),
        to_time=datetime(2026, 3, 27, 11, 0, tzinfo=timezone.utc),
    )

    assert len(alerts) == 1
    assert alerts[0]["level"] == 8
    assert alerts[0]["rule_id"] == "5710"
    assert alerts[0]["description"] == "Failed SSH login"
