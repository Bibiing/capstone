"""Database access helpers for authentication workflows."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from database.models import OTPCode, User


class AuthRepository:
    """Encapsulate auth-related DB queries and state changes."""

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

    def add_user(self, db: Session, user: User) -> None:
        db.add(user)

    def add_otp(self, db: Session, otp: OTPCode) -> None:
        db.add(otp)

    def get_latest_pending_otp(self, db: Session, user_id: int) -> OTPCode | None:
        return db.execute(
            select(OTPCode)
            .where(OTPCode.user_id == user_id, OTPCode.is_used.is_(False))
            .order_by(OTPCode.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()

    def get_pending_otps(self, db: Session, user_id: int) -> list[OTPCode]:
        return db.execute(
            select(OTPCode).where(OTPCode.user_id == user_id, OTPCode.is_used.is_(False))
        ).scalars().all()
