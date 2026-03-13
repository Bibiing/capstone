"""Unit tests for Wazuh API authentication behaviour."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from config.settings import get_settings
from ingestion.wazuh_client import _WazuhAPIClient


@dataclass
class _FakeResponse:
    status_code: int
    text: str = ""
    payload: Optional[dict[str, Any]] = None

    def json(self) -> dict[str, Any]:
        if self.payload is None:
            raise ValueError("No JSON payload")
        return self.payload


class _FakeHTTPClient:
    def __init__(self, responses_by_url: dict[str, _FakeResponse]) -> None:
        self._responses_by_url = responses_by_url
        self.called_urls: list[str] = []

    def post(self, url: str, auth: Any = None) -> _FakeResponse:
        self.called_urls.append(url)
        if url not in self._responses_by_url:
            return _FakeResponse(status_code=404, text="not found")
        return self._responses_by_url[url]

    def close(self) -> None:
        return None


def test_auth_fallback_to_port_55000_with_raw_token(mock_env):
    """
    If auth endpoint returns 404 on configured URL without a port,
    client should automatically retry on :55000 and parse raw token response.
    """
    get_settings.cache_clear()
    settings = get_settings()

    client = _WazuhAPIClient(settings)

    configured_raw = "https://test-wazuh.local/security/user/authenticate?raw=true"
    configured_legacy = "https://test-wazuh.local/security/user/authenticate"
    fallback_raw = "https://test-wazuh.local:55000/security/user/authenticate?raw=true"

    client._http = _FakeHTTPClient(
        {
            configured_raw: _FakeResponse(status_code=404, text="not found"),
            configured_legacy: _FakeResponse(status_code=404, text="not found"),
            fallback_raw: _FakeResponse(status_code=200, text='"jwt_token_from_raw"'),
        }
    )

    client._authenticate()

    assert client._token is not None
    assert client._token.value == "jwt_token_from_raw"
    assert client._active_base_url == "https://test-wazuh.local:55000"


def test_auth_json_token_parsing(mock_env):
    """Client should also support JSON auth responses with data.token."""
    get_settings.cache_clear()
    settings = get_settings()

    client = _WazuhAPIClient(settings)

    configured_raw = "https://test-wazuh.local/security/user/authenticate?raw=true"

    client._http = _FakeHTTPClient(
        {
            configured_raw: _FakeResponse(
                status_code=200,
                payload={"data": {"token": "jwt_token_from_json"}},
            ),
        }
    )

    client._authenticate()

    assert client._token is not None
    assert client._token.value == "jwt_token_from_json"
