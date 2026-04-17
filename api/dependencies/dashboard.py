"""Dependency wiring for dashboard module."""

from fastapi import HTTPException, Request, status

from api.services.dashboard_service import DashboardService
from api.services.rate_limiter import InMemoryRateLimiter
from config.settings import get_settings
from database.repositories.dashboard_repository import DashboardRepository

_dashboard_repository = DashboardRepository()
_dashboard_service = DashboardService(repository=_dashboard_repository)
_dashboard_rate_limiter = InMemoryRateLimiter()


def get_dashboard_service() -> DashboardService:
    """Return singleton dashboard service for request handlers."""
    return _dashboard_service


def get_dashboard_rate_limiter() -> InMemoryRateLimiter:
    """Return singleton dashboard limiter."""
    return _dashboard_rate_limiter


def enforce_dashboard_rate_limit(
    request: Request,
) -> None:
    """Apply per-user+IP dashboard read rate limiting."""
    settings = get_settings()

    forwarded_for = request.headers.get("x-forwarded-for", "")
    client_ip = forwarded_for.split(",")[0].strip() if forwarded_for else (request.client.host if request.client else "unknown")
    auth_header = request.headers.get("authorization", "")
    token_fingerprint = auth_header[-24:] if auth_header else "anonymous"
    key = f"dashboard:{token_fingerprint}:{client_ip}"

    allowed = _dashboard_rate_limiter.allow(
        key=key,
        limit=settings.dashboard_rate_limit_per_minute,
        window_seconds=settings.dashboard_rate_limit_window_seconds,
    )
    if allowed:
        return

    retry_after = _dashboard_rate_limiter.retry_after_seconds(
        key=key,
        window_seconds=settings.dashboard_rate_limit_window_seconds,
    )
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Dashboard rate limit exceeded.",
        headers={"Retry-After": str(retry_after)},
    )
