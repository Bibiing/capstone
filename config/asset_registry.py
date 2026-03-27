"""
Asset Registry Configuration

Defines:
- Asset criticality levels
- Asset type classification
- Risk weighting for scoring engine
- Default fallback values
"""

from enum import Enum
from typing import Dict, Any


# ============================================================================
# ENUMS
# ============================================================================

class CriticalityLevel(str, Enum):
    """Asset criticality levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AssetType(str, Enum):
    """Types of assets in the system."""
    SERVER = "server"
    DATABASE = "database"
    ENDPOINT = "endpoint"
    NETWORK = "network"
    APPLICATION = "application"
    CLOUD = "cloud"
    UNKNOWN = "unknown"


# ============================================================================
# CRITICALITY WEIGHT (CORE FOR RISK SCORING)
# ============================================================================

ASSET_CRITICALITY: Dict[str, CriticalityLevel] = {
    # Servers
    "prod-server": CriticalityLevel.CRITICAL,
    "production-server": CriticalityLevel.CRITICAL,
    "web-server": CriticalityLevel.HIGH,
    "api-server": CriticalityLevel.HIGH,
    "staging-server": CriticalityLevel.MEDIUM,
    "dev-server": CriticalityLevel.LOW,

    # Database
    "primary-db": CriticalityLevel.CRITICAL,
    "database": CriticalityLevel.CRITICAL,
    "replica-db": CriticalityLevel.HIGH,
    "test-db": CriticalityLevel.LOW,

    # Network
    "firewall": CriticalityLevel.CRITICAL,
    "router": CriticalityLevel.HIGH,
    "switch": CriticalityLevel.MEDIUM,

    # Endpoint
    "employee-laptop": CriticalityLevel.MEDIUM,
    "admin-laptop": CriticalityLevel.HIGH,
    "user-device": CriticalityLevel.LOW,

    # Cloud
    "cloud-prod": CriticalityLevel.CRITICAL,
    "cloud-dev": CriticalityLevel.LOW,
}


# ============================================================================
# NUMERIC WEIGHT (USED IN SCORING)
# ============================================================================

CRITICALITY_SCORES: Dict[CriticalityLevel, float] = {
    CriticalityLevel.LOW: 1.0,
    CriticalityLevel.MEDIUM: 2.0,
    CriticalityLevel.HIGH: 3.0,
    CriticalityLevel.CRITICAL: 5.0,
}


# ============================================================================
# ASSET TYPE MAPPING
# ============================================================================

ASSET_TYPE_MAPPING: Dict[str, AssetType] = {
    "server": AssetType.SERVER,
    "db": AssetType.DATABASE,
    "database": AssetType.DATABASE,
    "endpoint": AssetType.ENDPOINT,
    "laptop": AssetType.ENDPOINT,
    "network": AssetType.NETWORK,
    "firewall": AssetType.NETWORK,
    "app": AssetType.APPLICATION,
    "application": AssetType.APPLICATION,
    "cloud": AssetType.CLOUD,
}


# ============================================================================
# DEFAULTS
# ============================================================================

DEFAULT_CRITICALITY = CriticalityLevel.MEDIUM
DEFAULT_ASSET_TYPE = AssetType.UNKNOWN


# ============================================================================
# HELPER FUNCTIONS (IMPORTANT 🔥)
# ============================================================================

def get_asset_criticality(asset_name: str) -> CriticalityLevel:
    """
    Determine asset criticality based on asset name.

    Args:
        asset_name: Name of the asset

    Returns:
        CriticalityLevel
    """
    asset_name = asset_name.lower()

    for key, value in ASSET_CRITICALITY.items():
        if key in asset_name:
            return value

    return DEFAULT_CRITICALITY


def get_criticality_score(level: CriticalityLevel) -> float:
    """
    Convert criticality level to numeric score.

    Args:
        level: CriticalityLevel

    Returns:
        float score
    """
    return CRITICALITY_SCORES.get(level, 1.0)


def get_asset_type(asset_name: str) -> AssetType:
    """
    Determine asset type from name.

    Args:
        asset_name: Name of asset

    Returns:
        AssetType
    """
    asset_name = asset_name.lower()

    for key, value in ASSET_TYPE_MAPPING.items():
        if key in asset_name:
            return value

    return DEFAULT_ASSET_TYPE


def normalize_asset(asset_name: str) -> Dict[str, Any]:
    """
    Normalize asset into structured metadata.

    Returns:
        dict with:
        - name
        - type
        - criticality
        - score
    """
    criticality = get_asset_criticality(asset_name)
    asset_type = get_asset_type(asset_name)

    return {
        "name": asset_name,
        "type": asset_type.value,
        "criticality": criticality.value,
        "criticality_score": get_criticality_score(criticality),
    }