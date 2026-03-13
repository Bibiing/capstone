"""
SQLAlchemy ORM models for the Risk Scoring Engine.

Tables:
    assets          Registered assets (CMDB) with criticality questionnaire scores.
    risk_scores     Append-only time-series of computed risk score snapshots.
    threat_state    Persists T_prev per asset for the time-decay algorithm.
    sca_snapshots   Historical SCA scan results per asset.

Design principles:
    - Use SQLAlchemy 2.x Mapped / mapped_column API (type-safe, IDE-friendly).
    - Models are immutable where appropriate (risk_scores is append-only).
    - Constraints are enforced at the DB level in addition to application code.
    - Indexes are declared explicitly for time-series query performance.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    """Return current UTC datetime. Used as column default."""
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""
    pass


# =============================================================================
# Asset (CMDB Entry)
# =============================================================================
class Asset(Base):
    """
    Represents a monitored IT asset (server / workstation / application).

    Maps 1-to-1 with a Wazuh agent.
    `likert_score` = average of 8 balanced-scorecard questionnaire answers (1.0–5.0).
    `impact` (property) = likert_score / 5.0  →  normalised multiplier (0.2–1.0).
    """

    __tablename__ = "assets"
    __table_args__ = (
        CheckConstraint(
            "likert_score >= 1.0 AND likert_score <= 5.0",
            name="ck_assets_likert_range",
        ),
    )

    asset_id: Mapped[str] = mapped_column(String(50), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(100), nullable=False)
    wazuh_agent_id: Mapped[Optional[str]] = mapped_column(
        String(10), nullable=True, unique=True,
        comment="Wazuh agent ID (e.g. '001'). NULL if agent not yet linked.",
    )
    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45), nullable=True, comment="IPv4 or IPv6 address."
    )
    likert_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Average of 8 questionnaire answers (1.0–5.0).",
    )
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )

    # ── Relationships ──────────────────────────────────────────────────────────
    risk_scores: Mapped[list[RiskScore]] = relationship(
        "RiskScore", back_populates="asset", cascade="all, delete-orphan"
    )
    threat_state: Mapped[Optional[ThreatState]] = relationship(
        "ThreatState",
        back_populates="asset",
        uselist=False,
        cascade="all, delete-orphan",
    )
    sca_snapshots: Mapped[list[SCASnapshot]] = relationship(
        "SCASnapshot", back_populates="asset", cascade="all, delete-orphan"
    )

    # ── Computed Properties ────────────────────────────────────────────────────
    @property
    def impact(self) -> float:
        """
        Normalised impact multiplier I = likert_score / 5.0.
        Range: 0.20 (likert=1, not critical) → 1.00 (likert=5, most critical).
        """
        return round(self.likert_score / 5.0, 4)

    def __repr__(self) -> str:
        return (
            f"Asset(id={self.asset_id!r}, hostname={self.hostname!r}, "
            f"agent={self.wazuh_agent_id!r}, impact={self.impact:.2f})"
        )


# =============================================================================
# RiskScore (Time-Series Snapshot)
# =============================================================================
class RiskScore(Base):
    """
    Immutable time-series record of a computed risk score for one asset.

    Append-only: never UPDATE an existing row. Each scoring cycle inserts a new row.
    Stores all score components (I, V, T) for full audit trail and drill-down UI.
    """

    __tablename__ = "risk_scores"
    __table_args__ = (
        # Primary index for time-series queries: latest score per asset, trends
        Index("idx_risk_scores_asset_time", "asset_id", "timestamp"),
        CheckConstraint(
            "risk_score >= 0.0 AND risk_score <= 100.0",
            name="ck_risk_score_range",
        ),
        CheckConstraint(
            "severity IN ('Low', 'Medium', 'High', 'Critical')",
            name="ck_risk_severity_values",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[str] = mapped_column(
        String(50),
        ForeignKey("assets.asset_id", ondelete="CASCADE"),
        nullable=False,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    # ── Final aggregated score ─────────────────────────────────────────────────
    risk_score: Mapped[float] = mapped_column(
        Float, nullable=False, comment="R = I × (w1×V + w2×T), range 0–100."
    )
    severity: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        comment="Low (<40) | Medium (<70) | High (<90) | Critical (>=90).",
    )

    # ── Score components (for dashboard breakdown / drill-down) ───────────────
    impact: Mapped[float] = mapped_column(
        Float, nullable=False, comment="I = likert_score / 5.0"
    )
    vulnerability: Mapped[float] = mapped_column(
        Float, nullable=False, comment="V = 100 – SCA_pass_percentage"
    )
    threat: Mapped[float] = mapped_column(
        Float, nullable=False, comment="T_now = T_new + (T_prev × decay_factor), capped at 100."
    )

    # ── T calculation audit fields ─────────────────────────────────────────────
    t_new: Mapped[float] = mapped_column(
        Float, nullable=False, comment="Raw T before decay: Σ(alert_count × weight)."
    )
    t_previous: Mapped[float] = mapped_column(
        Float, nullable=False, comment="T_prev value used in this cycle."
    )

    # ── SCA raw data ───────────────────────────────────────────────────────────
    sca_pass_pct: Mapped[float] = mapped_column(
        Float, nullable=False, comment="Wazuh SCA pass percentage (0–100)."
    )

    # ── Alert breakdown (for audit trail) ─────────────────────────────────────
    alert_count_low: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False, comment="Alerts at level 0–4 (weight 1)."
    )
    alert_count_medium: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False, comment="Alerts at level 5–7 (weight 5)."
    )
    alert_count_high: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False, comment="Alerts at level 8–11 (weight 10)."
    )
    alert_count_critical: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False, comment="Alerts at level 12–15 (weight 25)."
    )

    # ── Relationship ───────────────────────────────────────────────────────────
    asset: Mapped[Asset] = relationship("Asset", back_populates="risk_scores")

    def __repr__(self) -> str:
        return (
            f"RiskScore(asset={self.asset_id!r}, score={self.risk_score:.1f}, "
            f"severity={self.severity!r}, ts={self.timestamp.isoformat()})"
        )


# =============================================================================
# ThreatState (T_prev persistence for time-decay)
# =============================================================================
class ThreatState(Base):
    """
    Persists the T_prev value per asset across scoring cycles.

    One row per asset — upserted at the end of each scoring cycle so that
    the time-decay effect survives process restarts.

    Without this table, T_prev would reset to 0 on every restart, making
    the time-decay algorithm stateless and the graph artificially flat.
    """

    __tablename__ = "threat_state"

    asset_id: Mapped[str] = mapped_column(
        String(50),
        ForeignKey("assets.asset_id", ondelete="CASCADE"),
        primary_key=True,
    )
    t_previous: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
        comment="T_now from the last completed scoring cycle (used as T_prev next cycle).",
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )

    asset: Mapped[Asset] = relationship("Asset", back_populates="threat_state")

    def __repr__(self) -> str:
        return f"ThreatState(asset={self.asset_id!r}, t_prev={self.t_previous:.2f})"


# =============================================================================
# SCASnapshot (Historical SCA scan results)
# =============================================================================
class SCASnapshot(Base):
    """
    Raw SCA scan result for one asset at a specific point in time.

    Used for:
    - Historical auditing of security posture improvements/regressions
    - Debugging unexpected V score changes
    - Trend analysis of SCA compliance over time
    """

    __tablename__ = "sca_snapshots"
    __table_args__ = (
        Index("idx_sca_asset_time", "asset_id", "scanned_at"),
        CheckConstraint(
            "pass_percentage >= 0.0 AND pass_percentage <= 100.0",
            name="ck_sca_pass_range",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[str] = mapped_column(
        String(50),
        ForeignKey("assets.asset_id", ondelete="CASCADE"),
        nullable=False,
    )
    policy_id: Mapped[str] = mapped_column(
        String(100), nullable=False, comment="CIS policy ID from Wazuh SCA."
    )
    policy_name: Mapped[str] = mapped_column(
        String(200), nullable=False, comment="Human-readable policy name."
    )
    pass_count: Mapped[int] = mapped_column(Integer, nullable=False)
    fail_count: Mapped[int] = mapped_column(Integer, nullable=False)
    not_applicable: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_checks: Mapped[int] = mapped_column(
        Integer, nullable=False, comment="pass_count + fail_count (excludes not_applicable)."
    )
    pass_percentage: Mapped[float] = mapped_column(
        Float, nullable=False, comment="(pass_count / total_checks) × 100. V = 100 – this value."
    )
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    asset: Mapped[Asset] = relationship("Asset", back_populates="sca_snapshots")

    def __repr__(self) -> str:
        return (
            f"SCASnapshot(asset={self.asset_id!r}, "
            f"policy={self.policy_id!r}, pass={self.pass_percentage:.1f}%)"
        )
