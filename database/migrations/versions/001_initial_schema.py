"""Initial schema: assets, risk_scores, threat_state, sca_snapshots.

Revision ID: 001
Revises: —
Create Date: 2026-03-13
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── assets ────────────────────────────────────────────────────────────────
    op.create_table(
        "assets",
        sa.Column("asset_id", sa.String(50), primary_key=True),
        sa.Column("hostname", sa.String(100), nullable=False),
        sa.Column("wazuh_agent_id", sa.String(10), nullable=True, unique=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("likert_score", sa.Float, nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.CheckConstraint(
            "likert_score >= 1.0 AND likert_score <= 5.0",
            name="ck_assets_likert_range",
        ),
    )

    # ── risk_scores ───────────────────────────────────────────────────────────
    op.create_table(
        "risk_scores",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "asset_id",
            sa.String(50),
            sa.ForeignKey("assets.asset_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("risk_score", sa.Float, nullable=False),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("impact", sa.Float, nullable=False),
        sa.Column("vulnerability", sa.Float, nullable=False),
        sa.Column("threat", sa.Float, nullable=False),
        sa.Column("t_new", sa.Float, nullable=False),
        sa.Column("t_previous", sa.Float, nullable=False),
        sa.Column("sca_pass_pct", sa.Float, nullable=False),
        sa.Column("alert_count_low", sa.Integer, nullable=False, server_default="0"),
        sa.Column("alert_count_medium", sa.Integer, nullable=False, server_default="0"),
        sa.Column("alert_count_high", sa.Integer, nullable=False, server_default="0"),
        sa.Column("alert_count_critical", sa.Integer, nullable=False, server_default="0"),
        sa.CheckConstraint(
            "risk_score >= 0.0 AND risk_score <= 100.0",
            name="ck_risk_score_range",
        ),
        sa.CheckConstraint(
            "severity IN ('Low', 'Medium', 'High', 'Critical')",
            name="ck_risk_severity_values",
        ),
    )
    op.create_index(
        "idx_risk_scores_asset_time",
        "risk_scores",
        ["asset_id", "timestamp"],
    )

    # ── threat_state ──────────────────────────────────────────────────────────
    op.create_table(
        "threat_state",
        sa.Column(
            "asset_id",
            sa.String(50),
            sa.ForeignKey("assets.asset_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("t_previous", sa.Float, nullable=False, server_default="0.0"),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
    )

    # ── sca_snapshots ─────────────────────────────────────────────────────────
    op.create_table(
        "sca_snapshots",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "asset_id",
            sa.String(50),
            sa.ForeignKey("assets.asset_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("policy_id", sa.String(100), nullable=False),
        sa.Column("policy_name", sa.String(200), nullable=False),
        sa.Column("pass_count", sa.Integer, nullable=False),
        sa.Column("fail_count", sa.Integer, nullable=False),
        sa.Column("not_applicable", sa.Integer, nullable=False, server_default="0"),
        sa.Column("total_checks", sa.Integer, nullable=False),
        sa.Column("pass_percentage", sa.Float, nullable=False),
        sa.Column("scanned_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "pass_percentage >= 0.0 AND pass_percentage <= 100.0",
            name="ck_sca_pass_range",
        ),
    )
    op.create_index(
        "idx_sca_asset_time",
        "sca_snapshots",
        ["asset_id", "scanned_at"],
    )


def downgrade() -> None:
    op.drop_index("idx_sca_asset_time", table_name="sca_snapshots")
    op.drop_table("sca_snapshots")
    op.drop_table("threat_state")
    op.drop_index("idx_risk_scores_asset_time", table_name="risk_scores")
    op.drop_table("risk_scores")
    op.drop_table("assets")
