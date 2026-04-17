"""Add asset_type and dashboard performance indexes.

Revision ID: 006
Revises: 005
Create Date: 2026-04-17
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "006"
down_revision: Union[str, None] = "005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Apply Phase 2 schema changes for dashboard asset intelligence."""
    op.add_column("assets", sa.Column("asset_type", sa.String(length=50), nullable=True))

    op.create_index(
        "idx_risk_scores_calculated_at_desc",
        "risk_scores",
        [sa.text("calculated_at DESC")],
        unique=False,
    )
    op.create_index(
        "idx_risk_scores_asset_period",
        "risk_scores",
        ["asset_id", sa.text("period_end DESC")],
        unique=False,
    )
    op.create_index(
        "idx_alert_snapshots_event_time_desc",
        "alert_snapshots",
        [sa.text("event_time DESC")],
        unique=False,
    )
    op.create_index(
        "idx_alert_snapshots_asset_time",
        "alert_snapshots",
        ["asset_id", sa.text("event_time DESC")],
        unique=False,
    )


def downgrade() -> None:
    """Rollback Phase 2 schema changes."""
    op.drop_index("idx_alert_snapshots_asset_time", table_name="alert_snapshots")
    op.drop_index("idx_alert_snapshots_event_time_desc", table_name="alert_snapshots")
    op.drop_index("idx_risk_scores_asset_period", table_name="risk_scores")
    op.drop_index("idx_risk_scores_calculated_at_desc", table_name="risk_scores")

    op.drop_column("assets", "asset_type")
