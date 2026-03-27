"""Authentication service dependency wiring."""

from api.services.auth_service import AuthService
from api.services.rate_limiter import InMemoryRateLimiter
from config.settings import get_settings
from database.repositories.auth_repository import AuthRepository

_auth_rate_limiter = InMemoryRateLimiter()
_auth_repository = AuthRepository()


def get_auth_service() -> AuthService:
    """Return configured AuthService singleton dependencies."""
    return AuthService(
        settings=get_settings(),
        repository=_auth_repository,
        rate_limiter=_auth_rate_limiter,
    )
