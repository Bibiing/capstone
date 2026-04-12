"""
SQLAlchemy ORM models for the Risk Scoring Engine.

Tables:
    users           System users with authentication credentials.
    assets          Registered assets synced from Wazuh Manager.
    risk_scores     Time-series of computed risk score snapshots.
    alert_snapshots Raw alert cache per scoring period for audit trail.

Design principles:
    - Use SQLAlchemy 2.x Mapped / mapped_column API (type-safe, IDE-friendly).
    - Models are immutable where appropriate (risk_scores is append-only).
    - Constraints are enforced at the DB level in addition to application code.
    - Indexes are declared explicitly for time-series query performance.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    desc,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

import enum as python_enum


def _utcnow() -> datetime:
    """Return current UTC datetime. Used as column default."""
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""
    pass


# =============================================================================
# User & Authentication
# =============================================================================
class UserRole(str, python_enum.Enum):
    """Enumeration of user roles."""
    CISO = "CISO"
    MANAJEMEN = "Manajemen"


class User(Base):
    """
    System user account with authentication credentials.

    Fields:
    - user_id: Unique identifier (UUID-like, or auto-incremented)
    - username: Unique username for login
    - email: Unique email address (used for OTP-based verification)
        - password_hash: bcrypt-hashed password (never store plain text)
            For Firebase-managed users this stores a sentinel value.
    - role: User permissions level (CISO, Manajemen)
    - is_active: Whether account is enabled (false until email verified)
    - is_verified: Whether email has been verified via OTP
    - created_at, updated_at: Audit timestamps
    """

    __tablename__ = "users"

    user_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(
        String(50), nullable=False, unique=True, index=True,
        comment="Unique username for login."
    )
    email: Mapped[str] = mapped_column(
        String(100), nullable=False, unique=True, index=True,
        comment="Unique email address (used for OTP verification)."
    )
    password_hash: Mapped[str] = mapped_column(
        String(255), nullable=False,
        comment="bcrypt-hashed password. Never store plain text."
    )
    firebase_uid: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True, unique=True, index=True,
        comment="Unique Firebase user UID for external identity mapping."
    )
    auth_provider: Mapped[Optional[str]] = mapped_column(
        String(30), nullable=True,
        comment="Primary auth provider, e.g. password, google.com."
    )
    display_name: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True,
        comment="Display name from identity provider profile."
    )
    avatar_url: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True,
        comment="Profile photo URL from identity provider profile."
    )
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, native_enum=False), nullable=False, default=UserRole.MANAJEMEN,
        comment="User permission level: CISO, Manajemen."
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False,
        comment="Account enabled after email verification."
    )
    is_verified: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False,
        comment="Email address verified via OTP."
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )

    def __repr__(self) -> str:
        return (
            f"User(id={self.user_id}, username={self.username!r}, "
            f"email={self.email!r}, is_verified={self.is_verified})"
        )


# =============================================================================
# Asset (CMDB Entry)
# =============================================================================
class Asset(Base):
    """
    CMDB entry for one monitored asset/agent from Wazuh.

    Schema follows the project README and stores impact score separately
    from periodic risk snapshots.
    """

    __tablename__ = "assets"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    agent_id: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        unique=True,
        index=True,
        comment="Agent ID from Wazuh Manager API.",
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    os_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    status: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    impact_score: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
        comment="Impact score I in 0.0-1.0 from business questionnaire.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )

    risk_scores: Mapped[list[RiskScore]] = relationship(
        "RiskScore", back_populates="asset", cascade="all, delete-orphan"
    )
    alert_snapshots: Mapped[list[AlertSnapshot]] = relationship(
        "AlertSnapshot", back_populates="asset", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return (
            f"Asset(id={self.id}, agent_id={self.agent_id!r}, "
            f"name={self.name!r}, status={self.status!r})"
        )


# =============================================================================
# RiskScore (Time-Series Snapshot)
# =============================================================================
class RiskScore(Base):
    """
    Time-series risk score snapshot for one asset.

    Designed to support trend queries and dashboard drill-down.
    """

    __tablename__ = "risk_scores"
    __table_args__ = (
        Index("idx_risk_scores_asset_time", "asset_id", desc("calculated_at")),
        CheckConstraint(
            "score_r >= 0.0 AND score_r <= 100.0",
            name="ck_risk_scores_r_range",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    asset_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    score_i: Mapped[float] = mapped_column(Float, nullable=False)
    score_v: Mapped[float] = mapped_column(Float, nullable=False)
    score_t: Mapped[float] = mapped_column(Float, nullable=False)
    score_r: Mapped[float] = mapped_column(Float, nullable=False)
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    calculated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    asset: Mapped[Asset] = relationship("Asset", back_populates="risk_scores")

    def __repr__(self) -> str:
        return (
            f"RiskScore(asset_id={self.asset_id}, score_r={self.score_r:.2f}, "
            f"calculated_at={self.calculated_at.isoformat()})"
        )


# =============================================================================
# Alert Snapshot (raw audit cache)
# =============================================================================
class AlertSnapshot(Base):
    """
    Stores raw alert rows used during risk computation for auditability.
    """

    __tablename__ = "alert_snapshots"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    asset_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    rule_level: Mapped[int] = mapped_column(Integer, nullable=False)
    rule_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    asset: Mapped[Asset] = relationship("Asset", back_populates="alert_snapshots")

    def __repr__(self) -> str:
        return (
            f"AlertSnapshot(id={self.id}, asset_id={self.asset_id}, "
            f"rule_level={self.rule_level}, event_time={self.event_time.isoformat()})"
        )
