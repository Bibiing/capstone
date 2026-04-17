"""Dashboard aggregation endpoints for scoring UI."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from api.dependencies.auth import get_current_user, require_roles
from api.dependencies.dashboard import enforce_dashboard_rate_limit, get_dashboard_service
from api.dependencies.db import get_db_session
from api.schemas import (
    AuthRole,
    DashboardAssetsSortBy,
    DashboardAssetsTableResponse,
    DashboardAssetDetailResponse,
    DashboardAssetSecurityReportResponse,
    DashboardLatestAlertsResponse,
    DashboardRiskLevel,
    DashboardRiskTrendResponse,
    DashboardSortOrder,
    DashboardSummaryResponse,
    DashboardTrendPeriod,
)
from api.services.dashboard_service import DashboardService

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"],
    dependencies=[Depends(get_current_user), Depends(enforce_dashboard_rate_limit)],
)


@router.get(
    "/summary",
    response_model=DashboardSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Get dashboard summary cards",
)
async def get_dashboard_summary(
    request: Request,
    _current_user=Depends(require_roles(AuthRole.CISO, AuthRole.MANAJEMEN)),
    db: Session = Depends(get_db_session),
    dashboard_service: DashboardService = Depends(get_dashboard_service),
) -> DashboardSummaryResponse:
    request_id = getattr(request.state, "request_id", None)
    return dashboard_service.get_summary(db=db, request_id=request_id)


@router.get(
    "/risk-trend",
    response_model=DashboardRiskTrendResponse,
    status_code=status.HTTP_200_OK,
    summary="Get dashboard risk trend",
)
async def get_dashboard_risk_trend(
    request: Request,
    period: DashboardTrendPeriod = DashboardTrendPeriod.WEEKLY,
    _current_user=Depends(require_roles(AuthRole.CISO, AuthRole.MANAJEMEN)),
    db: Session = Depends(get_db_session),
    dashboard_service: DashboardService = Depends(get_dashboard_service),
) -> DashboardRiskTrendResponse:
    request_id = getattr(request.state, "request_id", None)
    return dashboard_service.get_risk_trend(db=db, period=period, request_id=request_id)


@router.get(
    "/latest-alerts",
    response_model=DashboardLatestAlertsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get latest dashboard alerts",
)
async def get_dashboard_latest_alerts(
    request: Request,
    limit: int = Query(20, ge=1, le=100),
    _current_user=Depends(require_roles(AuthRole.CISO)),
    db: Session = Depends(get_db_session),
    dashboard_service: DashboardService = Depends(get_dashboard_service),
) -> DashboardLatestAlertsResponse:
    request_id = getattr(request.state, "request_id", None)
    return dashboard_service.get_latest_alerts(db=db, limit=limit, request_id=request_id)


@router.get(
    "/assets-table",
    response_model=DashboardAssetsTableResponse,
    status_code=status.HTTP_200_OK,
    summary="Get dashboard assets table",
)
async def get_dashboard_assets_table(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    sort_by: DashboardAssetsSortBy = DashboardAssetsSortBy.RISK_SCORE,
    order: DashboardSortOrder = DashboardSortOrder.DESC,
    status_filter: str | None = None,
    risk_level: DashboardRiskLevel | None = None,
    _current_user=Depends(require_roles(AuthRole.CISO)),
    db: Session = Depends(get_db_session),
    dashboard_service: DashboardService = Depends(get_dashboard_service),
) -> DashboardAssetsTableResponse:
    request_id = getattr(request.state, "request_id", None)
    return dashboard_service.get_assets_table(
        db=db,
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        sort_order=order,
        asset_status=status_filter,
        risk_level=risk_level,
        request_id=request_id,
    )


@router.get(
    "/assets/{asset_id}/detail",
    response_model=DashboardAssetDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get asset detail popup data",
)
async def get_dashboard_asset_detail(
    asset_id: str,
    request: Request,
    _current_user=Depends(require_roles(AuthRole.CISO)),
    db: Session = Depends(get_db_session),
    dashboard_service: DashboardService = Depends(get_dashboard_service),
) -> DashboardAssetDetailResponse:
    request_id = getattr(request.state, "request_id", None)

    try:
        asset_uuid = UUID(asset_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid asset UUID")

    try:
        return dashboard_service.get_asset_detail(db=db, asset_id=asset_uuid, request_id=request_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.get(
    "/assets/{asset_id}/security-report",
    response_model=DashboardAssetSecurityReportResponse,
    status_code=status.HTTP_200_OK,
    summary="Get asset security report",
)
async def get_dashboard_asset_security_report(
    asset_id: str,
    request: Request,
    _current_user=Depends(require_roles(AuthRole.CISO)),
    db: Session = Depends(get_db_session),
    dashboard_service: DashboardService = Depends(get_dashboard_service),
) -> DashboardAssetSecurityReportResponse:
    request_id = getattr(request.state, "request_id", None)

    try:
        asset_uuid = UUID(asset_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid asset UUID")

    try:
        return dashboard_service.get_asset_security_report(db=db, asset_id=asset_uuid, request_id=request_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
