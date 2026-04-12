"""Firebase-backed authentication routes.

Auth ownership model:
- Firebase handles credential providers (email/password and Google).
- Backend verifies Firebase ID tokens and maps identities to local User records.
- Local role onboarding remains in PostgreSQL and is mandatory on first sign-in.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from api.dependencies.auth import get_auth_service
from api.dependencies.db import get_db_session
from api.schemas import (
    FirebaseActionResponse,
    FirebaseCompleteProfileRequest,
    FirebasePasswordResetRequest,
    FirebaseSessionResponse,
    FirebaseSignInRequest,
)
from api.services.auth_service import AuthService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/firebase/sign-in",
    response_model=FirebaseSessionResponse,
    status_code=status.HTTP_200_OK,
    summary="Exchange Firebase ID token for backend session",
    description=(
        "Verify Firebase ID token (email/password or Google), sync user to PostgreSQL, "
        "and return backend session payload."
    ),
)
async def firebase_sign_in(
    request: FirebaseSignInRequest,
    db: Session = Depends(get_db_session),
    auth_service: AuthService = Depends(get_auth_service),
) -> FirebaseSessionResponse:
    response = await auth_service.firebase_sign_in(db=db, request=request)
    logger.info("Firebase sign-in success | uid=%s | role_required=%s", response.firebase_uid, response.role_required)
    return response


@router.post(
    "/firebase/complete-profile",
    response_model=FirebaseSessionResponse,
    status_code=status.HTTP_200_OK,
    summary="Complete post-verification profile",
    description="Set role after email verification. Required once before full access is granted.",
)
async def firebase_complete_profile(
    request: FirebaseCompleteProfileRequest,
    db: Session = Depends(get_db_session),
    auth_service: AuthService = Depends(get_auth_service),
) -> FirebaseSessionResponse:
    response = await auth_service.complete_profile(db=db, request=request)
    logger.info("Firebase profile completed | uid=%s | role=%s", response.firebase_uid, response.role)
    return response


@router.post(
    "/firebase/send-email-verification",
    response_model=FirebaseActionResponse,
    status_code=status.HTTP_200_OK,
    summary="Send Firebase email verification",
    description="Ask Firebase Identity Toolkit to send an email verification message.",
)
async def send_email_verification(
    request: FirebaseSignInRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> FirebaseActionResponse:
    return await auth_service.send_email_verification(request=request)


@router.post(
    "/firebase/password-reset",
    response_model=FirebaseActionResponse,
    status_code=status.HTTP_200_OK,
    summary="Send Firebase password reset email",
    description="Trigger Firebase password reset for email/password accounts.",
)
async def firebase_password_reset(
    request: FirebasePasswordResetRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> FirebaseActionResponse:
    return await auth_service.send_password_reset(email=request.email)
