"""
Authentication routes for user registration, login, and OTP verification.

Endpoints:
    POST   /auth/register          - Register new user
    POST   /auth/login             - Authenticate user with email/password
    POST   /auth/verify-otp        - Verify OTP code
    POST   /auth/resend-otp        - Request new OTP code
"""

import logging

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from api.dependencies.auth import get_auth_service
from api.dependencies.db import get_db_session
from api.services.auth_service import AuthService
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

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


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
    db: Session = Depends(get_db_session),
    auth_service: AuthService = Depends(get_auth_service),
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
    response = await auth_service.register(db=db, request=request)
    logger.info("User registered | username=%s | email=%s", response.username, response.email)
    return response


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
    db: Session = Depends(get_db_session),
    auth_service: AuthService = Depends(get_auth_service),
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
    response = await auth_service.login(db=db, request=request)
    logger.info("User logged in | email=%s | user_id=%s", response.email, response.user_id)
    return response


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
    db: Session = Depends(get_db_session),
    auth_service: AuthService = Depends(get_auth_service),
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
    response = await auth_service.verify_otp(db=db, request=request)
    logger.info("OTP verified | user_id=%s", response.user_id)
    return response


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
    db: Session = Depends(get_db_session),
    auth_service: AuthService = Depends(get_auth_service),
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
    response = await auth_service.resend_otp(db=db, request=request)
    logger.info("OTP resent | email=%s", request.email)
    return response
