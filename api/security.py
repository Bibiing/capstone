"""
Authentication utilities for password hashing, JWT tokens, and OTP handling.

Includes:
    - Password hashing with bcrypt
    - JWT token generation and validation
    - OTP code generation
    - Token payload models
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from config.settings import get_settings

# ============================================================================
# Configuration
# ============================================================================

# Password hashing context (bcrypt)
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12,  # Computational cost (higher = slower but more secure)
)


# ============================================================================
# Token Models
# ============================================================================
class TokenPayload(BaseModel):
    """JWT token payload structure."""

    user_id: int
    username: str
    email: str
    role: str
    exp: datetime  # Expiration time
    iat: datetime  # Issued at


# ============================================================================
# Password Hashing
# ============================================================================
def hash_password(password: str) -> str:
    """
    Hash a plain text password using bcrypt.

    Args:
        password: Plain text password

    Returns:
        bcrypt-hashed password string
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    """
    Verify a plain text password against a bcrypt hash.

    Args:
        plain_password: Plain text password to verify
        password_hash: bcrypt-hashed password from database

    Returns:
        True if password matches, False otherwise
    """
    return pwd_context.verify(plain_password, password_hash)


# ============================================================================
# JWT Token Management
# ============================================================================
def create_access_token(
    user_id: int,
    username: str,
    email: str,
    role: str,
    expires_in_hours: Optional[int] = None,
) -> tuple[str, int]:
    """
    Create a JWT access token.

    Args:
        user_id: User ID
        username: Username
        email: User email
        role: User role (admin, analyst, viewer)
        expires_in_hours: Token expiration time (defaults from settings)

    Returns:
        Tuple of (token_string, expires_in_seconds)
    """
    settings = get_settings()

    if expires_in_hours is None:
        expires_in_hours = settings.jwt_expiration_hours

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=expires_in_hours)

    payload = {
        "user_id": user_id,
        "username": username,
        "email": email,
        "role": role,
        "exp": expires_at,
        "iat": now,
    }

    token = jwt.encode(
        payload,
        settings.api_secret_key.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )

    expires_in_seconds = expires_in_hours * 3600
    return token, expires_in_seconds


def verify_token(token: str) -> Optional[TokenPayload]:
    """
    Verify and decode a JWT token.

    Args:
        token: JWT token string

    Returns:
        TokenPayload if valid, None if invalid or expired
    """
    settings = get_settings()

    try:
        payload = jwt.decode(
            token,
            settings.api_secret_key.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
        )
        return TokenPayload(**payload)
    except JWTError:
        return None


# ============================================================================
# OTP Management
# ============================================================================
def generate_otp(length: int = 6) -> str:
    """
    Generate a random OTP code.

    Args:
        length: OTP code length (default: 6 digits)

    Returns:
        Random numeric string of specified length
    """
    return "".join(str(secrets.randbelow(10)) for _ in range(length))


def get_otp_expiration_time() -> datetime:
    """
    Get the expiration time for a newly generated OTP.

    Returns:
        datetime object representing when OTP expires
    """
    settings = get_settings()
    return datetime.now(timezone.utc) + timedelta(
        minutes=settings.otp_expiration_minutes
    )


def is_otp_expired(expires_at: datetime) -> bool:
    """
    Check if an OTP code has expired.

    Args:
        expires_at: OTP expiration datetime (can be naive or aware)

    Returns:
        True if expired, False otherwise
    """
    now = datetime.now(timezone.utc)
    
    # If expires_at is naive (from SQLite), assume it's UTC and make it aware
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    
    return now > expires_at
