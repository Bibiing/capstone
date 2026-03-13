"""
Unit tests for the ingestion layer.

Tests are organized by class:
    TestSettings          Settings loading, validation, edge cases
    TestAlertFetcher      AlertFetcher.fetch() with mocked WazuhClient
    TestSCAFetcher        SCAFetcher.fetch() with mocked WazuhClient
    TestAlertCountsDTO    AlertCounts.empty() and field semantics
    TestSCAResultDTO      SCAResult.vulnerability_score and fallback

All tests mock WazuhClient so no real Wazuh connection is needed.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from ingestion.alert_fetcher import AlertCounts, AlertFetcher
from ingestion.exceptions import WazuhAuthenticationError, WazuhConnectionError
from ingestion.sca_fetcher import SCAFetcher, SCAResult
from ingestion.wazuh_client import SCASummary


# =============================================================================
# Settings Tests
# =============================================================================

class TestSettings:
    def test_settings_load_from_env(self, test_settings):
        """Settings should correctly parse env vars."""
        assert test_settings.wazuh_api_url == "https://test-wazuh.local"
        assert test_settings.wazuh_indexer_url == "https://test-wazuh.local:9200"
        assert test_settings.wazuh_api_user == "test_user"
        assert test_settings.decay_factor == 0.5
        assert test_settings.weight_vulnerability == 0.3
        assert test_settings.weight_threat == 0.7

    def test_settings_secret_str_not_exposed(self, test_settings):
        """Passwords must use SecretStr — plain string access should fail."""
        pwd_repr = repr(test_settings.wazuh_api_password)
        assert "test_password_secure" not in pwd_repr
        assert "**" in pwd_repr or "SecretStr" in pwd_repr

    def test_settings_secret_str_accessible_via_method(self, test_settings):
        """Password value should be accessible via .get_secret_value()."""
        assert test_settings.wazuh_api_password.get_secret_value() == "test_password_secure"

    def test_settings_strip_trailing_slash(self, mock_env):
        """URLs with trailing slashes should be normalised."""
        from config.settings import get_settings
        with patch.dict("os.environ", {"WAZUH_API_URL": "https://test-wazuh.local/"}):
            get_settings.cache_clear()
            s = get_settings()
            assert s.wazuh_api_url == "https://test-wazuh.local"

    def test_settings_weights_must_sum_to_one(self, mock_env):
        """w1 + w2 != 1.0 should raise ValidationError."""
        from pydantic import ValidationError
        from config.settings import get_settings
        with patch.dict("os.environ", {
            "WEIGHT_VULNERABILITY": "0.4",
            "WEIGHT_THREAT": "0.4",
        }):
            get_settings.cache_clear()
            with pytest.raises(ValidationError, match="must sum to 1.0"):
                get_settings()

    def test_settings_decay_factor_range(self, mock_env):
        """decay_factor must be between 0.0 and 1.0."""
        from pydantic import ValidationError
        from config.settings import get_settings
        with patch.dict("os.environ", {"DECAY_FACTOR": "1.5"}):
            get_settings.cache_clear()
            with pytest.raises(ValidationError):
                get_settings()


# =============================================================================
# AlertCounts DTO Tests
# =============================================================================

class TestAlertCountsDTO:
    def test_empty_returns_zero_counts(self):
        """AlertCounts.empty() should have all zero counts."""
        counts = AlertCounts.empty("001")
        assert counts.agent_id == "001"
        assert counts.low == 0
        assert counts.medium == 0
        assert counts.high == 0
        assert counts.critical == 0
        assert counts.total == 0

    def test_total_field_is_accurate(self):
        """total field must equal sum of all level counts."""
        now = datetime.now(timezone.utc)
        counts = AlertCounts(
            agent_id="001",
            window_start=now,
            window_end=now,
            low=10, medium=5, high=3, critical=1,
            total=19,
        )
        assert counts.total == counts.low + counts.medium + counts.high + counts.critical


# =============================================================================
# AlertFetcher Tests
# =============================================================================

class TestAlertFetcher:
    def test_fetch_returns_alert_counts(self, mock_wazuh_client):
        """fetch() should map raw counts dict to AlertCounts correctly."""
        mock_wazuh_client.count_alerts_by_level.return_value = {
            "low": 10, "medium": 5, "high": 3, "critical": 1,
        }
        fetcher = AlertFetcher(client=mock_wazuh_client, lookback_hours=1)
        result = fetcher.fetch("001")

        assert result.agent_id == "001"
        assert result.low == 10
        assert result.medium == 5
        assert result.high == 3
        assert result.critical == 1
        assert result.total == 19

    def test_fetch_calls_with_correct_agent_id(self, mock_wazuh_client):
        """fetch() must pass the correct agent_id to WazuhClient."""
        mock_wazuh_client.count_alerts_by_level.return_value = {
            "low": 0, "medium": 0, "high": 0, "critical": 0
        }
        fetcher = AlertFetcher(client=mock_wazuh_client, lookback_hours=1)
        fetcher.fetch("007")

        call_kwargs = mock_wazuh_client.count_alerts_by_level.call_args
        assert call_kwargs.kwargs.get("agent_id") == "007" or call_kwargs.args[0] == "007"

    def test_fetch_returns_empty_on_connection_error(self, mock_wazuh_client):
        """fetch() should return empty counts (not raise) on WazuhConnectionError."""
        mock_wazuh_client.count_alerts_by_level.side_effect = WazuhConnectionError("timeout")
        fetcher = AlertFetcher(client=mock_wazuh_client, lookback_hours=1)
        result = fetcher.fetch("001")

        assert result.total == 0
        assert result.agent_id == "001"

    def test_fetch_returns_empty_on_auth_error(self, mock_wazuh_client):
        """fetch() should return empty counts (not raise) on WazuhAuthenticationError."""
        mock_wazuh_client.count_alerts_by_level.side_effect = WazuhAuthenticationError("401")
        fetcher = AlertFetcher(client=mock_wazuh_client, lookback_hours=1)
        result = fetcher.fetch("001")

        assert result.total == 0

    def test_fetch_window_is_lookback_hours_wide(self, mock_wazuh_client):
        """The time window passed to WazuhClient must match lookback_hours."""
        mock_wazuh_client.count_alerts_by_level.return_value = {
            "low": 0, "medium": 0, "high": 0, "critical": 0
        }
        fetcher = AlertFetcher(client=mock_wazuh_client, lookback_hours=4)
        fetcher.fetch("001")

        args = mock_wazuh_client.count_alerts_by_level.call_args
        from_dt = args.kwargs.get("from_dt") or args.args[1]
        to_dt   = args.kwargs.get("to_dt")   or args.args[2]

        window_hours = (to_dt - from_dt).total_seconds() / 3600
        assert abs(window_hours - 4.0) < 0.01


# =============================================================================
# SCAResult DTO Tests
# =============================================================================

class TestSCAResultDTO:
    def test_vulnerability_score_is_complement_of_pass(self):
        """V = 100 - pass_percentage."""
        result = SCAResult(
            agent_id="001", asset_id="asset-001",
            policy_id="cis_test", policy_name="CIS Test",
            pass_count=56, fail_count=87,
            total_checks=143,
            pass_percentage=39.16,
            scanned_at=datetime.now(timezone.utc),
        )
        assert abs(result.vulnerability_score - (100.0 - 39.16)) < 0.01

    def test_fallback_has_50_percent_pass(self):
        """Fallback result should use 50% pass to represent 'unknown' posture."""
        fb = SCAResult.fallback("001")
        assert fb.pass_percentage == 50.0
        assert fb.vulnerability_score == 50.0
        assert fb.policy_id == "fallback"

    def test_fallback_with_asset_id(self):
        """Fallback should carry the asset_id through."""
        fb = SCAResult.fallback("001", asset_id="asset-001")
        assert fb.asset_id == "asset-001"


# =============================================================================
# SCAFetcher Tests
# =============================================================================

class TestSCAFetcher:
    def test_fetch_returns_worst_case_policy(self, mock_wazuh_client):
        """When multiple policies, fetch() should return the one with lowest pass%."""
        mock_wazuh_client.get_sca_summary.return_value = [
            SCASummary(
                agent_id="001", policy_id="cis_ubuntu",
                policy_name="CIS Ubuntu", pass_count=70,
                fail_count=30, not_applicable=5,      # pass% = 70%
            ),
            SCASummary(
                agent_id="001", policy_id="cis_apache",
                policy_name="CIS Apache", pass_count=40,
                fail_count=60, not_applicable=0,      # pass% = 40% ← worst
            ),
        ]
        fetcher = SCAFetcher(client=mock_wazuh_client, persist=False)
        result = fetcher.fetch("001", "asset-001")

        assert result.policy_id == "cis_apache"
        assert result.pass_percentage == 40.0

    def test_fetch_with_single_policy(self, mock_wazuh_client):
        """A single policy should be returned directly."""
        mock_wazuh_client.get_sca_summary.return_value = [
            SCASummary(
                agent_id="001", policy_id="cis_ubuntu",
                policy_name="CIS Ubuntu 22.04",
                pass_count=56, fail_count=87, not_applicable=48,
            ),
        ]
        fetcher = SCAFetcher(client=mock_wazuh_client, persist=False)
        result = fetcher.fetch("001", "asset-001")

        expected_pct = round((56 / (56 + 87)) * 100, 2)
        assert abs(result.pass_percentage - expected_pct) < 0.01
        assert result.policy_id == "cis_ubuntu"

    def test_fetch_returns_fallback_when_no_sca_data(self, mock_wazuh_client):
        """An agent with no SCA data should get a 50% fallback result."""
        mock_wazuh_client.get_sca_summary.return_value = []
        fetcher = SCAFetcher(client=mock_wazuh_client, persist=False)
        result = fetcher.fetch("001", "asset-001")

        assert result.pass_percentage == 50.0
        assert result.policy_id == "fallback"

    def test_fetch_returns_fallback_on_connection_error(self, mock_wazuh_client):
        """fetch() should return fallback (not raise) on WazuhConnectionError."""
        mock_wazuh_client.get_sca_summary.side_effect = WazuhConnectionError("timeout")
        fetcher = SCAFetcher(client=mock_wazuh_client, persist=False)
        result = fetcher.fetch("001", "asset-001")

        assert result.pass_percentage == 50.0
        assert result.policy_id == "fallback"

    def test_vulnerability_score_computed_correctly(self, mock_wazuh_client):
        """V = 100 - pass_percentage computed by SCAResult property."""
        mock_wazuh_client.get_sca_summary.return_value = [
            SCASummary(
                agent_id="001", policy_id="cis_test",
                policy_name="CIS Test", pass_count=60,
                fail_count=40, not_applicable=0,
            ),
        ]
        fetcher = SCAFetcher(client=mock_wazuh_client, persist=False)
        result = fetcher.fetch("001", "asset-001")

        assert result.pass_percentage == 60.0
        assert result.vulnerability_score == 40.0
