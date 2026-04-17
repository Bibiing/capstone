"""Authentication dependency wiring.

Provides both the Firebase-backed auth service singleton and request-time
bearer token validation for protected backend endpoints.
"""

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.services.auth_service import AuthService
from api.services.rate_limiter import InMemoryRateLimiter
from api.schemas import AuthRole, AuthenticatedUser
from config.settings import get_settings
from api.security import verify_token
from api.dependencies.db import get_db_session
from database.models import User, UserRole
from database.repositories.auth_repository import AuthRepository

_auth_rate_limiter = InMemoryRateLimiter()
_auth_repository = AuthRepository()
_bearer_scheme = HTTPBearer(auto_error=False)


def get_auth_service() -> AuthService:
    """Return configured AuthService singleton dependencies."""
    return AuthService(
        settings=get_settings(),
        repository=_auth_repository,
        rate_limiter=_auth_rate_limiter,
    )


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    db: Session = Depends(get_db_session),
) -> AuthenticatedUser:
    """Resolve the authenticated user from the backend bearer token."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = verify_token(credentials.credentials)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.execute(select(User).where(User.user_id == payload.user_id)).scalar_one_or_none()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account not found.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive.",
        )

    if user.email.lower().strip() != payload.email.lower().strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token subject mismatch.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.role.value != payload.role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token role mismatch.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    authenticated_user = AuthenticatedUser(
        user_id=user.user_id,
        username=user.username,
        email=user.email,
        role=AuthRole(user.role.value),
        firebase_uid=user.firebase_uid,
    )

    request.state.authenticated_user = authenticated_user

    return authenticated_user


def require_roles(*allowed_roles: AuthRole):
    """Return a dependency that enforces one of the allowed roles."""

    def _dependency(current_user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role for this action.",
            )
        return current_user

    return _dependency
