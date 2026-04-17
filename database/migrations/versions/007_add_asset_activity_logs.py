"""Add asset activity logs for dashboard reports.

Revision ID: 007
Revises: 006
Create Date: 2026-04-17
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "007"
down_revision: Union[str, None] = "006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create asset_activity_logs table for security reports."""
    op.create_table(
        "asset_activity_logs",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("asset_id", sa.dialects.postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("activity_type", sa.String(length=50), nullable=False),
        sa.Column("activity_detail", sa.Text(), nullable=True),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_asset_activity_logs_asset_id",
        "asset_activity_logs",
        ["asset_id"],
        unique=False,
    )
    op.create_index(
        "ix_asset_activity_logs_asset_time",
        "asset_activity_logs",
        ["asset_id", sa.text("event_time DESC")],
        unique=False,
    )


def downgrade() -> None:
    """Drop asset activity logs table."""
    op.drop_index("ix_asset_activity_logs_asset_time", table_name="asset_activity_logs")
    op.drop_index("ix_asset_activity_logs_asset_id", table_name="asset_activity_logs")
    op.drop_table("asset_activity_logs")
