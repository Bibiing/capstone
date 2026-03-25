"""
Authentication routes for user registration, login, and OTP verification.

Endpoints:
    POST   /auth/register          - Register new user
    POST   /auth/login             - Authenticate user with email/password
    POST   /auth/verify-otp        - Verify OTP code
    POST   /auth/resend-otp        - Request new OTP code
"""

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from api.schemas import (
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    RegisterResponse,
    ResendOTPRequest,
    ResendOTPResponse,
    VerifyOTPRequest,
    VerifyOTPResponse,
)
from api.security import (
    create_access_token,
    generate_otp,
    get_otp_expiration_time,
    hash_password,
    is_otp_expired,
    verify_password,
)
from config.settings import get_settings
from database.models import OTPCode, User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# For now, we'll use a dependency that will be injected with async DB session later
# Placeholder for DB session dependency
async def get_db_session() -> Session:
    """Database session dependency (will be configured with async SQLAlchemy)."""
    # This will be properly implemented when database integration is complete
    raise NotImplementedError("Database session not configured yet")


# ============================================================================
# Register Route
# ============================================================================

@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register new user",
    description="Create a new user account. User must verify email via OTP before login.",
)
async def register(
    request: RegisterRequest,
    # db: Session = Depends(get_db_session),  # Will be uncommented when DB ready
) -> RegisterResponse:
    """
    Register a new user account.

    The user will receive an OTP code via email (mocked for now).
    User must verify the email before they can login.

    Args:
        request: Registration request with username, email, password
        db: Database session

    Returns:
        RegisterResponse with user ID and confirmation message

    Raises:
        HTTPException 400: If username or email already exists
        HTTPException 400: If password doesn't meet requirements
    """
    settings = get_settings()

    # Validate password strength
    password = request.password
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    if not (has_upper and has_lower and has_digit and has_special):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Password must contain: uppercase, lowercase, digit, and special character. "
                "Example: SecurePass123!"
            ),
        )

    # TODO: In production, integrate with database:
    # 1. Check if username exists
    # 2. Check if email exists
    # 3. Create user with is_active=False, is_verified=False
    # 4. Generate OTP
    # 5. Save OTP to database
    # 6. Send OTP via email (using service like SendGrid, etc)

    # Mock response for now
    mock_user_id = 1
    mock_otp = "123456"

    logger.info(
        "User registered (mock) | username=%s | email=%s | otp=%s",
        request.username,
        request.email,
        mock_otp,
    )

    return RegisterResponse(
        user_id=mock_user_id,
        username=request.username,
        email=request.email,
        message=(
            "Registration successful. "
            "A verification code has been sent to your email. "
            f"[MOCK] Code: {mock_otp}"
        ),
        verification_required=True,
    )


# ============================================================================
# Login Route
# ============================================================================

@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="User login",
    description="Authenticate user with email and password. User must have verified email first.",
)
async def login(
    request: LoginRequest,
    # db: Session = Depends(get_db_session),  # Will be uncommented when DB ready
) -> LoginResponse:
    """
    Authenticate a user and return JWT access token.

    Args:
        request: Login request with email and password
        db: Database session

    Returns:
        LoginResponse with access token and user info

    Raises:
        HTTPException 401: If email not found or password incorrect
        HTTPException 403: If email not verified
    """
    settings = get_settings()

    # TODO: In production, integrate with database:
    # 1. Find user by email
    # 2. If not found → 401
    # 3. If found, verify password
    # 4. If password incorrect → 401
    # 5. If not verified → 403 Forbidden
    # 6. Generate JWT token
    # 7. Return token + user info

    # Mock Implementation (demonstrates flow)
    mock_user_found = False
    if not mock_user_found:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # This is what would happen after DB integration:
    # (Keeping for reference)
    # user = db.query(User).filter(User.email == request.email).first()
    # if not user or not verify_password(request.password, user.password_hash):
    #     raise HTTPException(401, detail="Invalid credentials")
    # if not user.is_verified:
    #     raise HTTPException(403, detail="Email not verified. Check your inbox for OTP.")

    # Mock response
    access_token, expires_in = create_access_token(
        user_id=1,
        username="john_doe",
        email=request.email,
        role="analyst",
    )

    logger.info("User logged in (mock) | email=%s", request.email)

    return LoginResponse(
        user_id=1,
        username="john_doe",
        email=request.email,
        role="analyst",
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in,
    )


# ============================================================================
# Verify OTP Route
# ============================================================================

@router.post(
    "/verify-otp",
    response_model=VerifyOTPResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify OTP code",
    description="Verify the OTP code sent to user's email during registration.",
)
async def verify_otp(
    request: VerifyOTPRequest,
    # db: Session = Depends(get_db_session),  # Will be uncommented when DB ready
) -> VerifyOTPResponse:
    """
    Verify OTP code sent to user's email.

    Args:
        request: OTP verification request with email and code
        db: Database session

    Returns:
        VerifyOTPResponse confirming email verification

    Raises:
        HTTPException 404: If user not found
        HTTPException 400: If OTP invalid or expired
        HTTPException 429: If max attempts exceeded
    """
    settings = get_settings()

    # TODO: In production, integrate with database:
    # 1. Find user by email
    # 2. If not found → 404
    # 3. Find latest OTP for user (where is_used=False)
    # 4. If not found → 400 "No pending OTP"
    # 5. If expired → 400 "OTP expired"
    # 6. If attempts >= max_attempts → 429 "Too many attempts"
    # 7. If code doesn't match → increment attempts, return 400
    # 8. If code matches:
    #    a. Mark user.is_verified = True
    #    b. Mark user.is_active = True
    #    c. Mark otp.is_used = True
    #    d. Return 200 with success message

    # Mock Implementation
    mock_user_found = False
    if not mock_user_found:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Mock response
    logger.info("OTP verified (mock) | email=%s", request.email)

    return VerifyOTPResponse(
        message="Email verified successfully. Account is now active.",
        is_verified=True,
        user_id=1,
    )


# ============================================================================
# Resend OTP Route
# ============================================================================

@router.post(
    "/resend-otp",
    response_model=ResendOTPResponse,
    status_code=status.HTTP_200_OK,
    summary="Resend OTP code",
    description="Request a new OTP code if the previous one expired or was lost.",
)
async def resend_otp(
    request: ResendOTPRequest,
    # db: Session = Depends(get_db_session),  # Will be uncommented when DB ready
) -> ResendOTPResponse:
    """
    Resend OTP code to user's email.

    Args:
        request: Resend OTP request with email
        db: Database session

    Returns:
        ResendOTPResponse with expiration time

    Raises:
        HTTPException 404: If user not found
        HTTPException 409: If user is already verified
    """
    settings = get_settings()

    # TODO: In production, integrate with database:
    # 1. Find user by email
    # 2. If not found → 404
    # 3. If user.is_verified → 409 "User already verified"
    # 4. Generate new OTP
    # 5. Mark old OTPs as expired or delete them
    # 6. Save new OTP to database
    # 7. Send OTP via email

    # Mock Implementation
    mock_user_found = False
    if not mock_user_found:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    mock_otp = generate_otp()
    logger.info("OTP resent (mock) | email=%s | code=%s", request.email, mock_otp)

    return ResendOTPResponse(
        message=f"OTP has been resent to {request.email}. [MOCK] Code: {mock_otp}",
        expires_in_minutes=settings.otp_expiration_minutes,
    )
