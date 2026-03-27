from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace
from uuid import uuid4

import pytest

from api.services.scheduler import ScoringScheduler


class _ExecResult:
    def __init__(self, all_items=None, one_item=None):
        self._all_items = all_items or []
        self._one_item = one_item

    def scalars(self):
        return self

    def all(self):
        return self._all_items

    def scalar_one_or_none(self):
        return self._one_item


class _FakeSession:
    def __init__(self, assets=None, latest_score=None):
        self.assets = assets or []
        self.latest_score = latest_score
        self.added = []
        self.added_many = []
        self._execute_count = 0

    def execute(self, stmt):
        self._execute_count += 1
        if self._execute_count == 1:
            return _ExecResult(all_items=self.assets)
        return _ExecResult(one_item=self.latest_score)

    def add(self, obj):
        self.added.append(obj)

    def add_all(self, objs):
        self.added_many.extend(objs)


@pytest.mark.asyncio
async def test_sync_assets_from_wazuh_upserts(monkeypatch):
    scheduler = ScoringScheduler()

    async def _fake_agents():
        return [
            {
                "agent_id": "001",
                "name": "db-prod-01",
                "ip_address": "10.0.0.10",
                "os_type": "linux",
                "status": "active",
            }
        ]

    upsert_calls = []

    def _fake_upsert(session, payload):
        upsert_calls.append(payload)

    @contextmanager
    def _fake_get_session():
        yield _FakeSession()

    monkeypatch.setattr(scheduler.wazuh, "get_all_agents", _fake_agents)
    monkeypatch.setattr("api.services.scheduler.queries.upsert_asset_by_agent_id", _fake_upsert)
    monkeypatch.setattr("api.services.scheduler.get_session", _fake_get_session)

    await scheduler.sync_assets_from_wazuh()

    assert len(upsert_calls) == 1
    assert upsert_calls[0]["agent_id"] == "001"
    assert upsert_calls[0]["name"] == "db-prod-01"


@pytest.mark.asyncio
async def test_run_threat_scoring_inserts_risk_and_alert_snapshots(monkeypatch):
    scheduler = ScoringScheduler()

    fake_asset = SimpleNamespace(id=uuid4(), agent_id="001", impact_score=0.8)
    fake_session = _FakeSession(assets=[fake_asset], latest_score=None)

    @contextmanager
    def _fake_get_session():
        yield fake_session

    async def _fake_alerts(agent_id, from_time, to_time):
        return [
            {
                "level": 8,
                "rule_id": "5710",
                "description": "Failed SSH login",
                "event_time": "2026-03-27T10:00:00Z",
            }
        ]

    monkeypatch.setattr("api.services.scheduler.get_session", _fake_get_session)
    monkeypatch.setattr(scheduler.wazuh, "get_alerts_by_agent", _fake_alerts)

    await scheduler.run_threat_scoring()

    assert len(fake_session.added) == 1
    assert len(fake_session.added_many) == 1
    assert fake_session.added_many[0].rule_id == "5710"
