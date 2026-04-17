"""Asset routes backed by database and Wazuh synchronization.

Assets are sourced from Wazuh Manager API and persisted in PostgreSQL.
No in-memory seed or mock asset store is used.
"""

from __future__ import annotations

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from api.dependencies.auth import get_current_user, require_roles
from api.dependencies.db import get_db_session
from api.schemas import AssetListResponse, AssetResponse, AuthRole
from api.services.wazuh_service import WazuhService
from database import queries

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/assets",
    tags=["Assets"],
    dependencies=[Depends(get_current_user)],
)


@router.post(
    "/sync/agents",
    response_model=dict,
    status_code=status.HTTP_200_OK,
    summary="Sync assets from Wazuh",
    description="Pull agents from Wazuh Manager API and upsert into assets table.",
)
async def sync_assets_from_wazuh(
    db: Session = Depends(get_db_session),
    _current_user=Depends(require_roles(AuthRole.CISO)),
) -> dict:
    service = WazuhService()

    try:
        agents = await service.get_all_agents()
    except Exception as exc:
        logger.exception("Failed to sync assets from Wazuh: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to fetch agents from Wazuh",
        )

    synced = 0
    for agent in agents:
        queries.upsert_asset_by_agent_id(
            db,
            {
                "agent_id": str(agent.get("agent_id")),
                "name": agent.get("name") or f"agent-{agent.get('agent_id')}",
                "ip_address": agent.get("ip_address"),
                "os_type": agent.get("os_type"),
                "status": agent.get("status"),
                "impact_score": 0.5,
            },
        )
        synced += 1

    logger.info("Asset sync completed | upserted=%d", synced)
    return {"message": "Assets synchronized from Wazuh", "synced": synced}


@router.get(
    "",
    response_model=AssetListResponse,
    status_code=status.HTTP_200_OK,
    summary="List assets",
    description="List assets stored in database (source: Wazuh sync).",
)
async def list_assets(
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    limit: int = Query(20, ge=1, le=200, description="Number of items to return"),
    db: Session = Depends(get_db_session),
) -> AssetListResponse:
    assets = queries.get_all_assets(db)
    sliced = assets[skip : skip + limit]
    responses = [_asset_to_response(asset) for asset in sliced]
    return AssetListResponse(total=len(assets), assets=responses)


@router.get(
    "/{asset_id}",
    response_model=AssetResponse,
    status_code=status.HTTP_200_OK,
    summary="Get one asset",
    description="Get one asset by UUID.",
)
async def get_asset(
    asset_id: str,
    db: Session = Depends(get_db_session),
) -> AssetResponse:
    try:
        asset_uuid = UUID(asset_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid asset UUID")

    asset = queries.get_asset_by_id(db, asset_uuid)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    return _asset_to_response(asset)


def _asset_to_response(asset) -> AssetResponse:
    return AssetResponse(
        asset_id=str(asset.id),
        agent_id=asset.agent_id,
        name=asset.name,
        asset_type=asset.asset_type,
        ip_address=asset.ip_address,
        os_type=asset.os_type,
        status=asset.status,
        impact_score=asset.impact_score,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
    )
