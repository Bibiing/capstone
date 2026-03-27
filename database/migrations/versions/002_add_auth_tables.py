"""Create users and otp_codes tables for authentication.

Revision ID: 002
Revises: 001_initial_schema
Create Date: 2026-03-13 10:00:00.000000

"""

import enum as python_enum

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


class UserRole(str, python_enum.Enum):
    """User role enumeration."""
    CISO = "CISO"
    MANAJEMEN = "Manajemen"


def upgrade() -> None:
    """Create users and otp_codes tables."""
    
    # Create ENUM type for user role (PostgreSQL specific)
    # Note: For other databases, use String(10) instead
    user_role_enum = sa.Enum(UserRole, name="user_role", native_enum=False)
    user_role_enum.create(op.get_bind(), checkfirst=True)

    # ========================================================================
    # TABLE: users
    # ========================================================================
    op.create_table(
        "users",
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column(
            "username",
            sa.String(length=50),
            nullable=False,
            comment="Unique username for login.",
        ),
        sa.Column(
            "email",
            sa.String(length=100),
            nullable=False,
            comment="Unique email address (used for OTP verification).",
        ),
        sa.Column(
            "password_hash",
            sa.String(length=255),
            nullable=False,
            comment="bcrypt-hashed password. Never store plain text.",
        ),
        sa.Column(
            "role",
            user_role_enum,
            nullable=False,
            server_default="Manajemen",
            comment="User permission level: CISO, Manajemen.",
        ),
        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=False,
            server_default="false",
            comment="Account enabled after email verification.",
        ),
        sa.Column(
            "is_verified",
            sa.Boolean(),
            nullable=False,
            server_default="false",
            comment="Email address verified via OTP.",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("user_id", name=op.f("pk_users")),
        sa.UniqueConstraint("username", name=op.f("uq_users_username")),
        sa.UniqueConstraint("email", name=op.f("uq_users_email")),
    )

    # Create indexes on username and email for fast lookups
    op.create_index(
        op.f("ix_users_username"),
        "users",
        ["username"],
        unique=False,
    )
    op.create_index(
        op.f("ix_users_email"),
        "users",
        ["email"],
        unique=False,
    )

    # ========================================================================
    # TABLE: otp_codes
    # ========================================================================
    op.create_table(
        "otp_codes",
        sa.Column("otp_id", sa.Integer(), nullable=False),
        sa.Column(
            "user_id",
            sa.Integer(),
            nullable=False,
            comment="FK to user account.",
        ),
        sa.Column(
            "code",
            sa.String(length=10),
            nullable=False,
            comment="OTP code (e.g., 6-digit numeric string).",
        ),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
            comment="Timestamp when this OTP becomes invalid.",
        ),
        sa.Column(
            "is_used",
            sa.Boolean(),
            nullable=False,
            server_default="false",
            comment="True once this OTP has been successfully verified.",
        ),
        sa.Column(
            "attempts",
            sa.Integer(),
            nullable=False,
            server_default="0",
            comment="Count of failed verification attempts.",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.user_id"],
            name=op.f("fk_otp_codes_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("otp_id", name=op.f("pk_otp_codes")),
    )

    # Create index on user_id for fast OTP lookups
    op.create_index(
        op.f("ix_otp_codes_user_id"),
        "otp_codes",
        ["user_id"],
        unique=False,
    )


def downgrade() -> None:
    """Drop users and otp_codes tables."""
    
    # Drop indexes
    op.drop_index(op.f("ix_otp_codes_user_id"), table_name="otp_codes")
    op.drop_index(op.f("ix_users_email"), table_name="users")
    op.drop_index(op.f("ix_users_username"), table_name="users")

    # Drop tables (reverse order of creation due to FK constraints)
    op.drop_table("otp_codes")
    op.drop_table("users")

    # Drop ENUM type (PostgreSQL specific)
    # Note: This only works on PostgreSQL; other databases ignore it safely
    try:
        op.execute("DROP TYPE user_role")
    except Exception:
        # Type might not exist or database might not support it
        pass
