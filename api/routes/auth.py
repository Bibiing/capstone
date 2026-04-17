"""Firebase-backed authentication routes.

Auth ownership model:
- Firebase handles credential providers (email/password and Google).
- Backend verifies Firebase ID tokens and maps identities to local User records.
- Account role is captured at register and account activation is automatic after email verification.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from api.dependencies.auth import get_auth_service
from api.dependencies.db import get_db_session
from api.schemas import (
    FirebaseActionResponse,
    FirebasePasswordResetRequest,
    FirebaseRegisterRequest,
    FirebaseRegisterResponse,
    FirebaseSessionResponse,
    FirebaseSignInRequest,
)
from api.services.auth_service import AuthService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/firebase/register",
    response_model=FirebaseRegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register new Firebase email/password account",
    description=(
        "Create Firebase user with email/password and persist initial local profile "
        "(name, username, role) in PostgreSQL."
    ),
)
async def firebase_register(
    request: FirebaseRegisterRequest,
    db: Session = Depends(get_db_session),
    auth_service: AuthService = Depends(get_auth_service),
) -> FirebaseRegisterResponse:
    response = await auth_service.firebase_register(db=db, request=request)
    logger.info("Firebase register success | uid=%s | email=%s", response.firebase_uid, response.email)
    return response


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
    logger.info(
        "Firebase sign-in success | uid=%s | account_activated=%s",
        response.firebase_uid,
        response.account_activated,
    )
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
