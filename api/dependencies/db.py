"""Database dependencies for FastAPI routes."""

from typing import Generator

from sqlalchemy.orm import Session

from database.connection import get_session


def get_db_session() -> Generator[Session, None, None]:
    """Provide a transactional database session for request handlers."""
    with get_session() as session:
        yield session
