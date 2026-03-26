"""
Shared pytest fixtures and configuration.

Fixtures defined here are available to all test files without explicit import.

Key fixtures:
    mock_env            Patches os.environ with test-safe credentials.
    test_settings       Returns a Settings instance loaded from mock_env.
    mock_wazuh_client   A MagicMock replacing WazuhClient for unit testing.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from config.settings import get_settings


# =============================================================================
# Settings Fixtures
# =============================================================================

@pytest.fixture(autouse=True)
def reset_settings_cache():
    """
    Clear the LRU settings cache before and after every test.

    Without this, test settings set by one test would bleed into the next.
    """
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def mock_env():
    """Patch os.environ with safe, test-specific values."""
    env_override = {
        "WAZUH_API_URL": "https://test-wazuh.local",
        "WAZUH_INDEXER_URL": "https://test-wazuh.local:9200",
        "WAZUH_API_USER": "test_user",
        "WAZUH_API_PASSWORD": "test_password_secure",
        "WAZUH_INDEXER_USER": "test_admin",
        "WAZUH_INDEXER_PASSWORD": "test_admin_pass_secure",
        "WAZUH_VERIFY_SSL": "false",
        "DATABASE_URL": "postgresql://test:test@localhost:5432/test_risk",
        "API_SECRET_KEY": "test_secret_key_32_chars_minimum!",
        "WEIGHT_VULNERABILITY": "0.3",
        "WEIGHT_THREAT": "0.7",
        "DECAY_FACTOR": "0.5",
        "ALERT_LOOKBACK_HOURS": "1",
    }
    with patch.dict("os.environ", env_override, clear=False):
        yield env_override


@pytest.fixture
def test_settings(mock_env):
    """Return a Settings instance loaded from the mock environment."""
    return get_settings()


# =============================================================================
# Wazuh Client Fixtures
# =============================================================================

@pytest.fixture
def mock_wazuh_client() -> MagicMock:
    """
    Return a MagicMock that mimics WazuhClient's public interface.

    Used for testing AlertFetcher and SCAFetcher in isolation from
    the real Wazuh API.
    """
    client = MagicMock()

    # Default return values (override per test with client.method.return_value = ...)
    client.get_agents.return_value = []
    client.get_sca_summary.return_value = []
    client.count_alerts_by_level.return_value = {
        "low": 0, "medium": 0, "high": 0, "critical": 0
    }
    client.get_recent_alerts.return_value = []
    client.get_threat_hunting_snapshot.return_value = {
        "agent_id": "001",
        "manager_name": "manager",
        "window_start": datetime(2026, 3, 13, 9, 0, 0, tzinfo=timezone.utc),
        "window_end": datetime(2026, 3, 13, 10, 0, 0, tzinfo=timezone.utc),
        "interval": "30m",
        "total_hits": 0,
        "events": [],
        "histogram": [],
        "by_rule_level": {},
        "by_level_group": {},
        "top_rules": [],
    }

    return client


# =============================================================================
# Time Fixtures
# =============================================================================

@pytest.fixture
def fixed_utc_now() -> datetime:
    """Return a fixed UTC datetime for deterministic time-based tests."""
    return datetime(2026, 3, 13, 10, 0, 0, tzinfo=timezone.utc)


# =============================================================================
# Database Fixtures
# =============================================================================

@pytest.fixture
def test_db_session():
    """
    Provide a fresh test database session for each test.
    
    Uses a temporary file-based SQLite database for better threading support.
    Creates all tables, yields the session for the test, then cleans up.
    """
    import tempfile
    import os
    from sqlalchemy import create_engine, inspect
    from sqlalchemy.orm import sessionmaker
    from database.models import Base
    
    # Create a temporary directory and database file
    temp_dir = tempfile.mkdtemp()
    db_file = os.path.join(temp_dir, "test.db")
    database_url = f"sqlite:///{db_file}"
    
    # Create engine with SQLite for tests
    engine = create_engine(
        database_url,
        echo=False,
        connect_args={"check_same_thread": False}
    )
    
    # Create all tables
    Base.metadata.create_all(engine)
    
    # Verify tables were created
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    assert "users" in tables, f"Tables not created! Found: {tables}"
    
    # Create session factory
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = SessionLocal()
    
    try:
        yield session
    finally:
        session.close()
        engine.dispose()
        # Clean up temp file
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def test_user(test_db_session):
    """
    Create a test user in the database.
    
    Returns a User instance with known credentials for testing auth endpoints.
    """
    from api.security import hash_password
    from database.models import User, UserRole
    
    user = User(
        username="testuser",
        email="test@example.com",
        password_hash=hash_password("SecurePass123!"),
        role=UserRole.ANALYST,
        is_active=False,
        is_verified=False,
    )
    test_db_session.add(user)
    test_db_session.commit()
    
    return user


@pytest.fixture
def test_verified_user(test_db_session):
    """
    Create a verified test user (can login immediately).
    """
    from api.security import hash_password
    from database.models import User, UserRole
    
    user = User(
        username="verified_user",
        email="verified@example.com",
        password_hash=hash_password("SecurePass123!"),
        role=UserRole.ANALYST,
        is_active=True,
        is_verified=True,
    )
    test_db_session.add(user)
    test_db_session.commit()
    
    return user


@pytest.fixture
def test_otp(test_db_session, test_user):
    """
    Create a valid OTP code for test user.
    """
    from database.models import OTPCode
    from api.security import get_otp_expiration_time
    from datetime import datetime, timedelta, timezone
    
    # Use timezone-aware datetime for OTP expiration
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
    
    otp = OTPCode(
        user_id=test_user.user_id,
        code="123456",
        expires_at=expires_at,
        is_used=False,
        attempts=0,
    )
    test_db_session.add(otp)
    test_db_session.commit()
    
    return otp
