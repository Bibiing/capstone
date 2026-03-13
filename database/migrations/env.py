"""
Alembic migration environment.

Reads the database URL from application settings so migrations always
run against the same database as the application.

Supports both offline mode (generates SQL script) and online mode (live DB).
"""

import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# ── Add project root to sys.path so models can be imported ────────────────────
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from config.settings import get_settings  # noqa: E402
from database.models import Base  # noqa: E402

# Alembic Config object — gives access to values within alembic.ini
config = context.config

# Configure Python logging from alembic.ini [loggers] section
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# The metadata object used for 'autogenerate' support
target_metadata = Base.metadata


def get_db_url() -> str:
    """
    Return the database URL for migrations.

    Reads from application settings (which reads from .env / environment).
    Falls back to DATABASE_URL env var directly if Settings fails to load.
    """
    try:
        return get_settings().database_url
    except Exception:
        url = os.environ.get("DATABASE_URL")
        if not url:
            raise RuntimeError(
                "DATABASE_URL must be set in .env or environment for migrations."
            )
        return url


def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode (generates SQL without connecting to DB).

    Useful for generating a migration script to review before applying.
    Run with: alembic upgrade head --sql
    """
    url = get_db_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode (connects to DB and applies changes live).

    Standard usage: alembic upgrade head
    """
    config_section = config.get_section(config.config_ini_section, {})
    config_section["sqlalchemy.url"] = get_db_url()

    connectable = engine_from_config(
        config_section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,  # Single connection — no pooling needed for migrations
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,           # Detect column type changes
            compare_server_default=True, # Detect default value changes
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
