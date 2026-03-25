"""
Asset management routes for CRUD operations on IT assets.

Endpoints:
    GET    /assets                 - List all assets
    POST   /assets                 - Create new asset
    GET    /assets/{asset_id}      - Get asset details
    PUT    /assets/{asset_id}      - Update asset
    DELETE /assets/{asset_id}      - Delete asset
"""

import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Query, status

from api.schemas import AssetCreate, AssetListResponse, AssetResponse, AssetUpdate
from database.models import Asset

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/assets", tags=["Assets"])

# Mock in-memory asset store (will be replaced with database)
_asset_store: dict[str, Asset] = {}

# Bootstrap with sample assets
def _bootstrap_assets():
    """Initialize with sample assets."""
    now = datetime.now(timezone.utc)
    
    sample_assets = [
        {
            "asset_id": "asset-001",
            "hostname": "db-prod-01",
            "wazuh_agent_id": "001",
            "ip_address": "192.168.1.10",
            "likert_score": 5.0,
            "description": "Production customer database (critical)",
        },
        {
            "asset_id": "asset-002",
            "hostname": "web-prod-01",
            "wazuh_agent_id": "002",
            "ip_address": "192.168.1.20",
            "likert_score": 4.5,
            "description": "Web server frontend (important)",
        },
        {
            "asset_id": "asset-003",
            "hostname": "app-server-01",
            "wazuh_agent_id": None,
            "ip_address": "192.168.1.30",
            "likert_score": 4.0,
            "description": "Application server",
        },
    ]

    for asset_data in sample_assets:
        asset = Asset(
            asset_id=asset_data["asset_id"],
            hostname=asset_data["hostname"],
            wazuh_agent_id=asset_data["wazuh_agent_id"],
            ip_address=asset_data["ip_address"],
            likert_score=asset_data["likert_score"],
            description=asset_data["description"],
            created_at=now,
            updated_at=now,
        )
        _asset_store[asset.asset_id] = asset


# Initialize on module load
_bootstrap_assets()


# ============================================================================
# List Assets
# ============================================================================

@router.get(
    "",
    response_model=AssetListResponse,
    status_code=status.HTTP_200_OK,
    summary="List all assets",
    description="Retrieve a paginated list of all registered IT assets.",
)
async def list_assets(
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    limit: int = Query(10, ge=1, le=100, description="Number of items to return"),
) -> AssetListResponse:
    """
    List all registered IT assets with optional pagination.

    Args:
        skip: Number of assets to skip
        limit: Maximum number of assets to return

    Returns:
        AssetListResponse with total count and asset list
    """
    all_assets = list(_asset_store.values())
    total = len(all_assets)
    paginated = all_assets[skip : skip + limit]

    logger.debug(
        "Listed assets | total=%d | skip=%d | limit=%d | returned=%d",
        total,
        skip,
        limit,
        len(paginated),
    )

    asset_responses = [_asset_to_response(asset) for asset in paginated]

    return AssetListResponse(total=total, assets=asset_responses)


# ============================================================================
# Create Asset
# ============================================================================

@router.post(
    "",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create new asset",
    description="Register a new IT asset into the system.",
)
async def create_asset(request: AssetCreate) -> AssetResponse:
    """
    Create a new IT asset.

    Args:
        request: Asset creation request

    Returns:
        AssetResponse with created asset details

    Raises:
        HTTPException 400: If hostname already exists
    """
    # Check for duplicate hostname
    for asset in _asset_store.values():
        if asset.hostname == request.hostname:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Hostname '{request.hostname}' already exists",
            )

    # Generate new asset ID
    asset_id = f"asset-{str(uuid4())[:8]}"
    now = datetime.now(timezone.utc)

    # Create asset
    asset = Asset(
        asset_id=asset_id,
        hostname=request.hostname,
        wazuh_agent_id=request.wazuh_agent_id,
        ip_address=request.ip_address,
        likert_score=request.likert_score,
        description=request.description,
        created_at=now,
        updated_at=now,
    )

    _asset_store[asset_id] = asset

    logger.info(
        "Asset created | asset_id=%s | hostname=%s | likert=%.1f",
        asset_id,
        request.hostname,
        request.likert_score,
    )

    return _asset_to_response(asset)


# ============================================================================
# Get Asset
# ============================================================================

@router.get(
    "/{asset_id}",
    response_model=AssetResponse,
    status_code=status.HTTP_200_OK,
    summary="Get asset details",
    description="Retrieve details of a specific asset.",
)
async def get_asset(asset_id: str) -> AssetResponse:
    """
    Retrieve details of a specific asset.

    Args:
        asset_id: Asset identifier

    Returns:
        AssetResponse with asset details

    Raises:
        HTTPException 404: If asset not found
    """
    asset = _asset_store.get(asset_id)
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset '{asset_id}' not found",
        )

    logger.debug("Asset retrieved | asset_id=%s", asset_id)
    return _asset_to_response(asset)


# ============================================================================
# Update Asset
# ============================================================================

@router.put(
    "/{asset_id}",
    response_model=AssetResponse,
    status_code=status.HTTP_200_OK,
    summary="Update asset",
    description="Update properties of an existing asset.",
)
async def update_asset(asset_id: str, request: AssetUpdate) -> AssetResponse:
    """
    Update an existing asset.

    Args:
        asset_id: Asset identifier
        request: Asset update request (all fields optional)

    Returns:
        AssetResponse with updated asset details

    Raises:
        HTTPException 404: If asset not found
        HTTPException 400: If new hostname conflicts with existing asset
    """
    asset = _asset_store.get(asset_id)
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset '{asset_id}' not found",
        )

    # Check for hostname conflicts
    if request.hostname and request.hostname != asset.hostname:
        for other_asset in _asset_store.values():
            if other_asset.hostname == request.hostname:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Hostname '{request.hostname}' already exists",
                )

    # Update fields
    if request.hostname is not None:
        asset.hostname = request.hostname
    if request.ip_address is not None:
        asset.ip_address = request.ip_address
    if request.likert_score is not None:
        asset.likert_score = request.likert_score
    if request.description is not None:
        asset.description = request.description

    # Update timestamp
    asset.updated_at = datetime.now(timezone.utc)

    logger.info("Asset updated | asset_id=%s | hostname=%s", asset_id, asset.hostname)
    return _asset_to_response(asset)


# ============================================================================
# Delete Asset
# ============================================================================

@router.delete(
    "/{asset_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete asset",
    description="Delete an asset from the system.",
)
async def delete_asset(asset_id: str) -> None:
    """
    Delete an asset.

    Args:
        asset_id: Asset identifier

    Raises:
        HTTPException 404: If asset not found
    """
    if asset_id not in _asset_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset '{asset_id}' not found",
        )

    del _asset_store[asset_id]
    logger.info("Asset deleted | asset_id=%s", asset_id)


# ============================================================================
# Helper Functions
# ============================================================================

def _asset_to_response(asset: Asset) -> AssetResponse:
    """Convert Asset ORM model to response schema."""
    return AssetResponse(
        asset_id=asset.asset_id,
        hostname=asset.hostname,
        wazuh_agent_id=asset.wazuh_agent_id,
        ip_address=asset.ip_address,
        likert_score=asset.likert_score,
        impact=asset.impact,
        description=asset.description,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
    )
