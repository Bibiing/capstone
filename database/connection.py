"""
SQLAlchemy engine and session factory.

Provides a thread-safe connection pool and a context-manager session
for use throughout the application.

Usage:
    from database.connection import get_session, check_connection

    # Standard usage — session auto-commits on exit, rolls back on exception
    with get_session() as session:
        asset = session.get(Asset, "asset-001")

    # Health check
    if not check_connection():
        raise RuntimeError("Cannot reach database")
"""

import logging
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from config.settings import get_settings

logger = logging.getLogger(__name__)

# Module-level singletons (initialised lazily on first use)
_engine = None
_SessionFactory: sessionmaker | None = None


def _init_engine():
    """
    Create and configure the SQLAlchemy engine.

    Called automatically on first use of get_session() or get_engine().
    pool_pre_ping=True ensures stale connections (e.g. after DB restart)
    are transparently recycled.
    """
    global _engine, _SessionFactory

    settings = get_settings()
    _engine = create_engine(
        settings.database_url,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_timeout=settings.db_pool_timeout,
        pool_pre_ping=True,   # Detect & reconnect on stale connections
        echo=False,           # Set True to log all SQL (development only)
    )
    _SessionFactory = sessionmaker(bind=_engine, expire_on_commit=False)

    logger.info(
        "Database engine initialised | pool_size=%d | max_overflow=%d",
        settings.db_pool_size,
        settings.db_max_overflow,
    )
    return _engine


def get_engine():
    """Return the global SQLAlchemy engine, initialising on first call."""
    global _engine
    if _engine is None:
        _init_engine()
    return _engine


@contextmanager
def get_session() -> Generator[Session, None, None]:
    """
    Provide a transactional database session via context manager.

    - Commits automatically on clean exit.
    - Rolls back on any exception and re-raises it.
    - Always closes the session to return the connection to the pool.

    Example:
        with get_session() as session:
            session.add(new_record)
            # auto-committed here
    """
    if _SessionFactory is None:
        _init_engine()

    session: Session = _SessionFactory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def check_connection() -> bool:
    """
    Perform a lightweight DB connectivity check.

    Returns True if the database is reachable, False otherwise.
    Safe to call at startup or in a health-check endpoint.
    """
    try:
        engine = get_engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        logger.info("Database connection check: OK")
        return True
    except OperationalError as exc:
        logger.error("Database connection check FAILED: %s", exc)
        return False
