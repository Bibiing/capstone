"""Database access helpers for authentication workflows."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from database.models import User


class AuthRepository:
    """Encapsulate auth-related DB queries and state changes."""

    def get_user_by_firebase_uid(self, db: Session, firebase_uid: str) -> User | None:
        return db.execute(select(User).where(User.firebase_uid == firebase_uid)).scalar_one_or_none()

    def get_user_by_email(self, db: Session, email: str) -> User | None:
        return db.execute(select(User).where(User.email == email)).scalar_one_or_none()

    def get_user_by_username_or_email(
        self,
        db: Session,
        username: str,
        email: str,
    ) -> User | None:
        return db.execute(
            select(User).where((User.username == username) | (User.email == email))
        ).scalar_one_or_none()

    def username_exists(self, db: Session, username: str) -> bool:
        return db.execute(select(User.user_id).where(User.username == username)).scalar_one_or_none() is not None

    def add_user(self, db: Session, user: User) -> None:
        db.add(user)
