"""Operational observability endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from api.dependencies.auth import get_current_user, require_roles
from api.dependencies.observability import get_metrics_service
from api.schemas import AuthRole, MetricsSnapshotResponse
from api.services.metrics_service import MetricsService
from config.settings import get_settings

router = APIRouter(
    prefix="/metrics",
    tags=["Observability"],
    dependencies=[Depends(get_current_user)],
)


@router.get(
    "",
    response_model=MetricsSnapshotResponse,
    status_code=status.HTTP_200_OK,
    summary="Get in-memory API metrics snapshot",
)
async def get_metrics_snapshot(
    _current_user=Depends(require_roles(AuthRole.CISO)),
    metrics_service: MetricsService = Depends(get_metrics_service),
) -> MetricsSnapshotResponse:
    settings = get_settings()
    if not settings.metrics_enabled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Metrics endpoint is disabled.",
        )

    return MetricsSnapshotResponse(**metrics_service.snapshot())
