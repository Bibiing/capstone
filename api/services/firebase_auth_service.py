"""Firebase Auth integration helpers.

This service centralizes Firebase Admin initialization, ID token verification,
and Firebase Identity Toolkit email actions (verify email, password reset).
"""

from __future__ import annotations

import json
import logging

import firebase_admin
import httpx
from firebase_admin import auth, credentials
from firebase_admin.exceptions import FirebaseError
from fastapi import HTTPException, status

from config.settings import Settings

logger = logging.getLogger(__name__)

_FIREBASE_APP: firebase_admin.App | None = None


class FirebaseAuthService:
    """Wrapper around Firebase Admin SDK and Identity Toolkit operations."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._app: firebase_admin.App | None = None

    @property
    def app(self) -> firebase_admin.App:
        if self._app is None:
            self._app = _get_firebase_app(self._settings)
        return self._app

    def verify_id_token(self, id_token: str) -> dict:
        """Validate and decode Firebase ID token."""
        try:
            decoded = auth.verify_id_token(id_token, app=self.app, check_revoked=True)
        except auth.RevokedIdTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Firebase token has been revoked. Please sign in again.",
            )
        except auth.ExpiredIdTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Firebase token has expired. Please refresh and retry.",
            )
        except (auth.InvalidIdTokenError, ValueError):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Firebase ID token.",
            )
        except FirebaseError:
            logger.exception("Firebase token verification failed")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication provider temporarily unavailable.",
            )

        if decoded.get("aud") != self._settings.firebase_project_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token audience mismatch for this Firebase project.",
            )

        return decoded

    async def send_password_reset_email(self, email: str) -> None:
        """Trigger Firebase password reset email via Identity Toolkit."""
        payload = {
            "requestType": "PASSWORD_RESET",
            "email": email,
        }
        await self._send_oob_code(payload)

    async def send_email_verification(self, id_token: str) -> None:
        """Trigger Firebase email verification message for current user."""
        payload = {
            "requestType": "VERIFY_EMAIL",
            "idToken": id_token,
        }
        await self._send_oob_code(payload)

    async def _send_oob_code(self, payload: dict) -> None:
        if not self._settings.firebase_web_api_key:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="FIREBASE_WEB_API_KEY is not configured.",
            )

        url = (
            "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode"
            f"?key={self._settings.firebase_web_api_key}"
        )

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(url, json=payload)
        except httpx.HTTPError:
            logger.exception("Identity Toolkit request failed")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Failed to contact Firebase Identity Toolkit.",
            )

        if resp.status_code == status.HTTP_200_OK:
            return

        # Avoid leaking internal provider details to callers.
        logger.warning("Identity Toolkit error | status=%s body=%s", resp.status_code, resp.text)
        if resp.status_code in (400, 401):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unable to process Firebase email action request.",
            )

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Firebase email action is temporarily unavailable.",
        )


def _get_firebase_app(settings: Settings) -> firebase_admin.App:
    """Initialize and cache Firebase app instance for this process."""
    global _FIREBASE_APP

    if _FIREBASE_APP is not None:
        return _FIREBASE_APP

    if firebase_admin._apps:
        _FIREBASE_APP = firebase_admin.get_app()
        return _FIREBASE_APP

    cert_data = None
    if settings.firebase_service_account_json:
        try:
            cert_data = json.loads(settings.firebase_service_account_json)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Invalid FIREBASE_SERVICE_ACCOUNT_JSON value") from exc

    if cert_data:
        cred = credentials.Certificate(cert_data)
    elif settings.firebase_service_account_path:
        cred = credentials.Certificate(settings.firebase_service_account_path)
    else:
        cred = credentials.ApplicationDefault()

    _FIREBASE_APP = firebase_admin.initialize_app(
        cred,
        options={"projectId": settings.firebase_project_id},
    )
    return _FIREBASE_APP
