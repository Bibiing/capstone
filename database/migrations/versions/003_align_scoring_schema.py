"""Align scoring schema with README: assets, risk_scores, alert_snapshots.

Revision ID: 003
Revises: 002
Create Date: 2026-03-27
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Drop legacy scoring tables and recreate README-aligned schema."""
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    # Drop legacy tables from revision 001.
    op.drop_index("idx_sca_asset_time", table_name="sca_snapshots")
    op.drop_table("sca_snapshots")
    op.drop_table("threat_state")
    op.drop_index("idx_risk_scores_asset_time", table_name="risk_scores")
    op.drop_table("risk_scores")
    op.drop_table("assets")

    # assets
    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("agent_id", sa.String(length=10), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("os_type", sa.String(length=50), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=True),
        sa.Column("impact_score", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("agent_id", name="uq_assets_agent_id"),
    )
    op.create_index("ix_assets_agent_id", "assets", ["agent_id"], unique=False)

    # risk_scores
    op.create_table(
        "risk_scores",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("score_i", sa.Float(), nullable=False),
        sa.Column("score_v", sa.Float(), nullable=False),
        sa.Column("score_t", sa.Float(), nullable=False),
        sa.Column("score_r", sa.Float(), nullable=False),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("calculated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("score_r >= 0.0 AND score_r <= 100.0", name="ck_risk_scores_r_range"),
    )
    op.create_index(
        "idx_risk_scores_asset_time",
        "risk_scores",
        ["asset_id", sa.text("calculated_at DESC")],
        unique=False,
    )

    # alert_snapshots
    op.create_table(
        "alert_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rule_level", sa.Integer(), nullable=False),
        sa.Column("rule_id", sa.String(length=20), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_alert_snapshots_asset_id", "alert_snapshots", ["asset_id"], unique=False)


def downgrade() -> None:
    """Restore legacy revision-001 scoring schema."""
    op.drop_index("ix_alert_snapshots_asset_id", table_name="alert_snapshots")
    op.drop_table("alert_snapshots")

    op.drop_index("idx_risk_scores_asset_time", table_name="risk_scores")
    op.drop_table("risk_scores")

    op.drop_index("ix_assets_agent_id", table_name="assets")
    op.drop_table("assets")

    # Recreate legacy assets
    op.create_table(
        "assets",
        sa.Column("asset_id", sa.String(50), primary_key=True),
        sa.Column("hostname", sa.String(100), nullable=False),
        sa.Column("wazuh_agent_id", sa.String(10), nullable=True, unique=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("likert_score", sa.Float, nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.CheckConstraint("likert_score >= 1.0 AND likert_score <= 5.0", name="ck_assets_likert_range"),
    )

    # Recreate legacy risk_scores
    op.create_table(
        "risk_scores",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("asset_id", sa.String(50), sa.ForeignKey("assets.asset_id", ondelete="CASCADE"), nullable=False),
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
        sa.CheckConstraint("risk_score >= 0.0 AND risk_score <= 100.0", name="ck_risk_score_range"),
        sa.CheckConstraint("severity IN ('Low', 'Medium', 'High', 'Critical')", name="ck_risk_severity_values"),
    )
    op.create_index("idx_risk_scores_asset_time", "risk_scores", ["asset_id", "timestamp"])

    # Recreate legacy threat_state and sca_snapshots
    op.create_table(
        "threat_state",
        sa.Column("asset_id", sa.String(50), sa.ForeignKey("assets.asset_id", ondelete="CASCADE"), primary_key=True),
        sa.Column("t_previous", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
    )

    op.create_table(
        "sca_snapshots",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("asset_id", sa.String(50), sa.ForeignKey("assets.asset_id", ondelete="CASCADE"), nullable=False),
        sa.Column("policy_id", sa.String(100), nullable=False),
        sa.Column("policy_name", sa.String(200), nullable=False),
        sa.Column("pass_count", sa.Integer, nullable=False),
        sa.Column("fail_count", sa.Integer, nullable=False),
        sa.Column("not_applicable", sa.Integer, nullable=False, server_default="0"),
        sa.Column("total_checks", sa.Integer, nullable=False),
        sa.Column("pass_percentage", sa.Float, nullable=False),
        sa.Column("scanned_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("pass_percentage >= 0.0 AND pass_percentage <= 100.0", name="ck_sca_pass_range"),
    )
    op.create_index("idx_sca_asset_time", "sca_snapshots", ["asset_id", "scanned_at"])
