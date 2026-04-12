"""Add Firebase auth mapping columns to users table.

Revision ID: 004
Revises: 003
Create Date: 2026-04-12
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add Firebase identity columns for provider-backed auth."""
    op.add_column("users", sa.Column("firebase_uid", sa.String(length=128), nullable=True))
    op.add_column("users", sa.Column("auth_provider", sa.String(length=30), nullable=True))
    op.add_column("users", sa.Column("display_name", sa.String(length=100), nullable=True))
    op.add_column("users", sa.Column("avatar_url", sa.Text(), nullable=True))

    op.create_index("ix_users_firebase_uid", "users", ["firebase_uid"], unique=False)
    op.create_unique_constraint("uq_users_firebase_uid", "users", ["firebase_uid"])


def downgrade() -> None:
    """Remove Firebase identity columns."""
    op.drop_constraint("uq_users_firebase_uid", "users", type_="unique")
    op.drop_index("ix_users_firebase_uid", table_name="users")

    op.drop_column("users", "avatar_url")
    op.drop_column("users", "display_name")
    op.drop_column("users", "auth_provider")
    op.drop_column("users", "firebase_uid")
