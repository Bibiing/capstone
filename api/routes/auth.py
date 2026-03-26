"""
Authentication routes for user registration, login, and OTP verification.

Endpoints:
    POST   /auth/register          - Register new user
    POST   /auth/login             - Authenticate user with email/password
    POST   /auth/verify-otp        - Verify OTP code
    POST   /auth/resend-otp        - Request new OTP code
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from api.email import send_otp_email, send_otp_resend_notification
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
from database.connection import get_session
from database.models import OTPCode, User, UserRole
from database import queries

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Database session dependency
def get_db() -> Session:
    """Get database session from connection pool."""
    with get_session() as session:
        yield session


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
    db: Session = Depends(get_db),
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

    # Check if username already exists
    existing_user = queries.get_user_by_username(db, request.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists",
        )

    # Check if email already exists
    existing_email = queries.get_user_by_email(db, request.email)
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    # Create new user (not verified yet)
    password_hash = hash_password(request.password)
    new_user = User(
        username=request.username,
        email=request.email,
        password_hash=password_hash,
        role=UserRole.ANALYST,  # Default role
        is_active=False,  # Not active until verified
        is_verified=False,
    )

    # Save user to database
    user = queries.create_user(db, new_user)
    db.commit()  # Commit to get user_id

    # Generate OTP code
    otp_code = generate_otp()
    otp_expiration = get_otp_expiration_time()

    # Create and save OTP
    new_otp = OTPCode(
        user_id=user.user_id,
        code=otp_code,
        expires_at=otp_expiration,
        is_used=False,
        attempts=0,
    )
    queries.create_otp(db, new_otp)
    db.commit()

    # Send OTP via Resend API
    email_sent = await send_otp_email(
        to_email=request.email,
        otp_code=otp_code,
        settings=settings,
        username=request.username,
    )

    # Log the registration attempt
    logger.info(
        "User registered | username=%s | email=%s | user_id=%d | otp_sent=%s",
        request.username,
        request.email,
        user.user_id,
        email_sent,
    )

    # Build response message
    if email_sent:
        message = (
            "Registration successful! "
            "A verification code has been sent to your email. "
            "Please check your inbox and verify within 15 minutes."
        )
    else:
        # Email failed to send, but still show success for UX
        # In production, this should trigger a retry mechanism
        logger.warning(
            "OTP email failed but user created | user_id=%d | email=%s",
            user.user_id,
            request.email,
        )
        message = (
            "Registration successful, but there was an issue sending the verification email. "
            "Please check your spam folder or request a new code."
        )

    return RegisterResponse(
        user_id=user.user_id,
        username=request.username,
        email=request.email,
        message=message,
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
    db: Session = Depends(get_db),
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
    # Find user by email
    user = queries.get_user_by_email(db, request.email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify password
    if not verify_password(request.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if email verified
    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email not verified. Please check your inbox for OTP code.",
        )

    # Create JWT token
    access_token, expires_in = create_access_token(
        user_id=user.user_id,
        username=user.username,
        email=user.email,
        role=user.role.value if isinstance(user.role, UserRole) else str(user.role),
    )

    logger.info("User logged in | user_id=%d | email=%s", user.user_id, user.email)

    return LoginResponse(
        user_id=user.user_id,
        username=user.username,
        email=user.email,
        role=user.role.value if isinstance(user.role, UserRole) else str(user.role),
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
    db: Session = Depends(get_db)
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

    # Find user by email
    user = queries.get_user_by_email(db, request.email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Get pending OTP for this user
    otp = queries.get_pending_otp(db, user.user_id)
    if not otp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending OTP found. Request a new code to continue.",
        )

    # Check if OTP is expired
    if is_otp_expired(otp.expires_at):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP code has expired. Request a new code to continue.",
        )

    # Check if max attempts exceeded
    if otp.attempts >= settings.otp_max_attempts:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Request a new code to continue.",
        )

    # Verify OTP code
    if otp.code != request.otp_code:
        queries.increment_otp_attempts(db, otp.otp_id)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP code. Please check and try again.",
        )

    # Mark OTP as used and user as verified
    queries.mark_otp_as_used(db, otp.otp_id)
    queries.update_user_verified(db, user.user_id)
    db.commit()

    logger.info(
        "OTP verified successfully | user_id=%d | email=%s",
        user.user_id,
        user.email,
    )

    return VerifyOTPResponse(
        message="Email verified successfully. Account is now active. You can now login.",
        is_verified=True,
        user_id=user.user_id,
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
    db: Session = Depends(get_db)
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

    # Find user by email
    user = queries.get_user_by_email(db, request.email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Check if user already verified
    if user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already verified. You can now login.",
        )

    # Generate new OTP
    new_otp_code = generate_otp()
    otp_expiration = get_otp_expiration_time()

    # Create and save new OTP
    new_otp = OTPCode(
        user_id=user.user_id,
        code=new_otp_code,
        expires_at=otp_expiration,
        is_used=False,
        attempts=0,
    )
    queries.create_otp(db, new_otp)
    db.commit()

    # Send OTP via Resend API
    email_sent = await send_otp_email(
        to_email=request.email,
        otp_code=new_otp_code,
        settings=settings,
        username=user.username,
    )

    logger.info(
        "OTP resent | user_id=%d | email=%s | sent=%s",
        user.user_id,
        request.email,
        email_sent,
    )

    if email_sent:
        message = f"A new verification code has been sent to {request.email}"
    else:
        message = (
            f"Verification code generation failed. "
            f"Please try again or contact support."
        )

    return ResendOTPResponse(
        message=message,
        expires_in_minutes=settings.otp_expiration_minutes,
    )
