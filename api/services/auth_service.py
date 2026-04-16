"""Business logic for Firebase-backed authentication workflows."""

from __future__ import annotations

import logging
import re
from uuid import uuid4

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from api.schemas import (
    AuthRole,
    FirebaseActionResponse,
    FirebaseRegisterRequest,
    FirebaseRegisterResponse,
    FirebaseSessionResponse,
    FirebaseSignInRequest,
    LoginResponse,
)
from api.security import create_access_token
from api.services.firebase_auth_service import FirebaseAuthService
from api.services.rate_limiter import InMemoryRateLimiter
from config.settings import Settings
from database.models import User, UserRole
from database.repositories.auth_repository import AuthRepository

_FIREBASE_SENTINEL_PASSWORD_HASH = "FIREBASE_MANAGED"
logger = logging.getLogger(__name__)


class AuthService:
    """Use-case service for Firebase-backed registration and sign-in."""

    def __init__(
        self,
        settings: Settings,
        repository: AuthRepository,
        rate_limiter: InMemoryRateLimiter,
    ) -> None:
        self._settings = settings
        self._repo = repository
        self._rate_limiter = rate_limiter
        self._firebase = FirebaseAuthService(settings)

    @staticmethod
    def _normalize_email(email: str) -> str:
        return email.lower().strip()

    def _ensure_firebase_config(self) -> None:
        if not self._settings.firebase_project_id:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="FIREBASE_PROJECT_ID is not configured.",
            )

    def _build_unique_username(self, db: Session, email: str, display_name: str | None) -> str:
        base = display_name or email.split("@")[0]
        base = re.sub(r"[^a-zA-Z0-9_]", "_", base).strip("_").lower() or "user"
        base = base[:40]

        candidate = base
        if not self._repo.username_exists(db, candidate):
            return candidate

        for _ in range(10):
            candidate = f"{base}_{uuid4().hex[:6]}"
            if not self._repo.username_exists(db, candidate):
                return candidate

        return f"user_{uuid4().hex[:10]}"

    @staticmethod
    def _normalize_username(username: str) -> str:
        return username.strip().lower()

    def _sign_app_token(self, user: User) -> LoginResponse:
        access_token, expires_in = create_access_token(
            user_id=user.user_id,
            username=user.username,
            email=user.email,
            role=user.role.value,
        )
        return LoginResponse(
            user_id=user.user_id,
            username=user.username,
            email=user.email,
            role=AuthRole(user.role.value),
            access_token=access_token,
            token_type="bearer",
            expires_in=expires_in,
        )

    def _upsert_user_from_firebase_claims(self, db: Session, claims: dict) -> User:
        uid = claims.get("uid")
        email_raw = claims.get("email")

        if not uid or not email_raw:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Firebase token missing required uid/email claims.",
            )

        email = self._normalize_email(email_raw)
        firebase_meta = claims.get("firebase", {}) or {}
        provider = firebase_meta.get("sign_in_provider", "unknown")
        display_name = claims.get("name")
        avatar_url = claims.get("picture")
        email_verified = bool(claims.get("email_verified", False))

        user = self._repo.get_user_by_firebase_uid(db, uid)

        if user is None:
            user = self._repo.get_user_by_email(db, email)
            if user is not None and user.firebase_uid and user.firebase_uid != uid:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Email is already linked to another Firebase identity.",
                )

        if user is None:
            user = User(
                username=self._build_unique_username(db, email=email, display_name=display_name),
                email=email,
                password_hash=_FIREBASE_SENTINEL_PASSWORD_HASH,
                role=UserRole.MANAJEMEN,
                is_active=False,
                is_verified=email_verified,
                firebase_uid=uid,
                auth_provider=provider,
                display_name=display_name,
                avatar_url=avatar_url,
            )
            self._repo.add_user(db, user)
            db.flush()
            return user

        # Existing user: synchronize provider metadata but never downgrade verification status.
        user.firebase_uid = uid
        user.auth_provider = provider
        user.display_name = display_name or user.display_name
        user.avatar_url = avatar_url or user.avatar_url
        user.is_verified = user.is_verified or email_verified
        return user

    async def firebase_register(self, db: Session, request: FirebaseRegisterRequest) -> FirebaseRegisterResponse:
        """Register new account using Firebase email/password and persist local profile."""
        self._ensure_firebase_config()

        email = self._normalize_email(request.email)
        username = self._normalize_username(request.username)

        if not self._rate_limiter.allow(
            key=f"auth:firebase:register:{email}",
            limit=self._settings.auth_register_limit_per_hour,
            window_seconds=3600,
        ):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many registration attempts. Please try again later.",
            )

        if request.password != request.confirm_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password and confirm password do not match.",
            )

        existing = self._repo.get_user_by_username_or_email(db, username=username, email=email)
        if existing is not None:
            if existing.email == email:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Email is already registered.",
                )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username is already taken.",
            )

        firebase_user = self._firebase.create_email_password_user(
            email=email,
            password=request.password,
            display_name=request.name.strip(),
        )

        try:
            user = User(
                username=username,
                email=email,
                password_hash=_FIREBASE_SENTINEL_PASSWORD_HASH,
                role=UserRole(request.role.value),
                is_active=False,
                is_verified=False,
                firebase_uid=firebase_user.uid,
                auth_provider="password",
                display_name=request.name.strip(),
                avatar_url=None,
            )
            self._repo.add_user(db, user)
            db.flush()
            db.commit()
            db.refresh(user)
        except Exception:
            db.rollback()
            self._firebase.delete_user(firebase_user.uid)
            raise

        email_verification_sent = False
        try:
            await self._firebase.send_email_verification_for_new_user(
                email=email,
                password=request.password,
            )
            email_verification_sent = True
        except HTTPException:
            # Registration remains successful; frontend can trigger resend later.
            logger.warning(
                "Auto verification email send failed after register | uid=%s | email=%s",
                firebase_user.uid,
                email,
            )

        return FirebaseRegisterResponse(
            user_id=user.user_id,
            firebase_uid=firebase_user.uid,
            email=user.email,
            username=user.username,
            role=AuthRole(user.role.value),
            email_verified=False,
            email_verification_sent=email_verification_sent,
            role_required=False,
            message=(
                "Account created successfully. Check your email for verification before first sign-in."
            ),
        )

    async def firebase_sign_in(self, db: Session, request: FirebaseSignInRequest) -> FirebaseSessionResponse:
        self._ensure_firebase_config()

        token_key = request.id_token[:24]
        if not self._rate_limiter.allow(
            key=f"auth:firebase:signin:{token_key}",
            limit=self._settings.auth_login_limit_per_15m,
            window_seconds=900,
        ):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many authentication attempts. Please try again later.",
            )

        claims = self._firebase.verify_id_token(request.id_token)
        email_verified = bool(claims.get("email_verified", False))

        if self._settings.firebase_require_verified_email and not email_verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "Email is not verified in Firebase. "
                    "Please verify your email before accessing this backend."
                ),
            )

        user = self._upsert_user_from_firebase_claims(db, claims)

        was_activated_now = False
        if not user.is_active and email_verified:
            user.is_verified = True
            user.is_active = True
            was_activated_now = True

        is_active = bool(user.is_active)
        response = FirebaseSessionResponse(
            user_id=user.user_id,
            firebase_uid=user.firebase_uid or "",
            email=user.email,
            username=user.username,
            role=AuthRole(user.role.value),
            provider=user.auth_provider or "unknown",
            email_verified=user.is_verified,
            account_activated=is_active,
            role_required=False,
            message=(
                "Account activated successfully. Please sign in again to continue."
                if was_activated_now
                else "Authentication successful."
            ),
        )

        if is_active and not was_activated_now:
            response.session = self._sign_app_token(user)

        return response

    async def send_email_verification(self, request: FirebaseSignInRequest) -> FirebaseActionResponse:
        self._ensure_firebase_config()
        await self._firebase.send_email_verification(request.id_token)
        return FirebaseActionResponse(message="Verification email request accepted.")

    async def send_password_reset(self, email: str) -> FirebaseActionResponse:
        self._ensure_firebase_config()

        normalized_email = self._normalize_email(email)
        if not self._rate_limiter.allow(
            key=f"auth:firebase:reset:{normalized_email}",
            limit=self._settings.auth_password_reset_limit_per_hour,
            window_seconds=3600,
        ):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many password reset requests. Please try again later.",
            )

        # Do not reveal if email exists; return generic success for anti-enumeration.
        try:
            await self._firebase.send_password_reset_email(normalized_email)
        except HTTPException as exc:
            if exc.status_code == status.HTTP_400_BAD_REQUEST:
                return FirebaseActionResponse(
                    message="If the account exists, a password reset email will be sent shortly.",
                )
            raise

        return FirebaseActionResponse(
            message="If the account exists, a password reset email will be sent shortly.",
        )
