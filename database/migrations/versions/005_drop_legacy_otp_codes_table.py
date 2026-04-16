"""Drop legacy otp_codes table after Firebase-first auth migration.

Revision ID: 005
Revises: 004
Create Date: 2026-04-16
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "005"
down_revision: Union[str, None] = "004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Remove unused OTP table from legacy auth flow."""
    op.execute("DROP TABLE IF EXISTS otp_codes CASCADE")


def downgrade() -> None:
    """Restore otp_codes table for backward compatibility."""
    op.create_table(
        "otp_codes",
        sa.Column("otp_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False, comment="FK to user account."),
        sa.Column("code", sa.String(length=10), nullable=False, comment="OTP code (e.g., 6-digit numeric string)."),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False, comment="Timestamp when this OTP becomes invalid."),
        sa.Column("is_used", sa.Boolean(), nullable=False, server_default="false", comment="True once this OTP has been successfully verified."),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0", comment="Count of failed verification attempts."),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["user_id"], ["users.user_id"], name="fk_otp_codes_user_id_users", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("otp_id", name="pk_otp_codes"),
    )
    op.create_index("ix_otp_codes_user_id", "otp_codes", ["user_id"], unique=False)
