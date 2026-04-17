"""
Pydantic schemas for request/response validation and documentation.

Organized by feature:
    - Auth schemas: Firebase sign-in/register and backend session
    - Asset schemas: Asset CRUD
    - Score schemas: Risk score queries and responses
    - Error schemas: Standard error response format
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


class AuthRole(str, Enum):
    """Allowed roles for authentication."""

    CISO = "CISO"
    MANAJEMEN = "Manajemen"


# =============================================================================
# Error Response (Global)
# =============================================================================
class ErrorResponse(BaseModel):
    """Standard error response across all API endpoints."""

    status_code: int = Field(..., description="HTTP status code")
    message: str = Field(..., description="Human-readable error message")
    detail: Optional[str] = Field(None, description="Additional error details")
    request_id: Optional[str] = Field(None, description="Correlation ID for tracing")

    class Config:
        json_schema_extra = {
            "example": {
                "status_code": 400,
                "message": "Invalid input",
                "detail": "Email format is invalid",
                "request_id": "req_123abc",
            }
        }


class LoginResponse(BaseModel):
    """Response after successful login."""

    user_id: int
    username: str
    email: str
    role: AuthRole = Field(..., description="User role: CISO or Manajemen")
    access_token: str = Field(..., description="JWT bearer token for API authentication")
    token_type: str = Field(default="bearer", description="Token type (always 'bearer')")
    expires_in: int = Field(..., description="Token expiration time in seconds")

    class Config:
        json_schema_extra = {
            "example": {
                "user_id": 1,
                "username": "jane_manager",
                "email": "jane.doe@bank.com",
                "role": "Manajemen",
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 86400,
            }
        }



class FirebaseSignInRequest(BaseModel):
    """Request carrying Firebase ID token from client SDK."""

    id_token: str = Field(
        ...,
        min_length=20,
        description="Firebase ID token obtained from client SDK after sign-in.",
    )


class FirebaseRegisterRequest(BaseModel):
    """Request payload for backend-assisted Firebase email/password sign-up."""

    name: str = Field(..., min_length=2, max_length=100, description="Full display name.")
    username: str = Field(..., min_length=3, max_length=50, description="Unique application username.")
    email: EmailStr = Field(..., description="Email address for Firebase account.")
    role: AuthRole = Field(..., description="Initial business role selected by user.")
    password: str = Field(..., min_length=8, max_length=128, description="Account password.")
    confirm_password: str = Field(..., min_length=8, max_length=128, description="Password confirmation.")


class FirebaseRegisterResponse(BaseModel):
    """Response after successful Firebase account registration."""

    user_id: int
    firebase_uid: str
    email: str
    username: str
    role: AuthRole
    email_verified: bool
    email_verification_sent: bool = Field(
        ...,
        description="True if backend successfully requested Firebase verification email.",
    )
    role_required: bool
    message: str


class FirebasePasswordResetRequest(BaseModel):
    """Request for Firebase password reset flow."""

    email: EmailStr = Field(..., description="Email for password reset delivery.")


class FirebaseActionResponse(BaseModel):
    """Generic response for Firebase auth side effects."""

    message: str


class FirebaseSessionResponse(BaseModel):
    """Backend auth response derived from verified Firebase identity."""

    user_id: int
    firebase_uid: str
    email: str
    username: str
    role: AuthRole
    provider: str = Field(..., description="Firebase provider, e.g. password or google.com")
    email_verified: bool
    account_activated: bool = Field(
        ...,
        description="True if account is active for backend access (or just activated on this sign-in).",
    )
    role_required: bool = Field(
        ...,
        description="Legacy compatibility flag kept for backward-compatible frontend contracts.",
    )
    message: str
    session: Optional[LoginResponse] = Field(
        default=None,
        description="App session token payload. Null when account was just activated and user must sign in once more.",
    )


class AuthenticatedUser(BaseModel):
    """Identity extracted from a verified backend bearer token."""

    user_id: int
    username: str
    email: str
    role: AuthRole
    firebase_uid: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "user_id": 1,
                "username": "security.manager",
                "email": "security.manager@example.com",
                "role": "Manajemen",
                "firebase_uid": "firebase-uid-example",
            }
        }


# =============================================================================
# Asset Schemas
# =============================================================================
class AssetCreate(BaseModel):
    """Deprecated: asset creation is handled by Wazuh sync."""

    name: str

    class Config:
        json_schema_extra = {
            "example": {
                "hostname": "db-prod-01",
                "wazuh_agent_id": "001",
                "ip_address": "192.168.1.100",
                "likert_score": 5.0,
                "description": "Production customer database (critical)",
            }
        }


class AssetUpdate(BaseModel):
    """Request to update mutable asset properties."""

    impact_score: Optional[float] = Field(None, ge=0.0, le=1.0)

    class Config:
        json_schema_extra = {
            "example": {
                "likert_score": 4.8,
                "description": "Updated description",
            }
        }


class AssetResponse(BaseModel):
    """Response containing asset information."""

    asset_id: str
    agent_id: str
    name: str
    asset_type: Optional[str]
    ip_address: Optional[str]
    os_type: Optional[str]
    status: Optional[str]
    impact_score: Optional[float]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "asset_id": "asset-001",
                "agent_id": "001",
                "name": "db-prod-01",
                "ip_address": "192.168.1.100",
                "os_type": "linux",
                "status": "active",
                "impact_score": 1.0,
                "created_at": "2026-03-13T08:00:00Z",
                "updated_at": "2026-03-13T08:00:00Z",
            }
        }


class AssetListResponse(BaseModel):
    """Response containing list of assets."""

    total: int = Field(..., description="Total number of assets")
    assets: list[AssetResponse]

    class Config:
        json_schema_extra = {
            "example": {
                "total": 7,
                "assets": [
                    {
                        "asset_id": "d4a298af-7db9-4b89-85e3-a9ab5814120f",
                        "agent_id": "001",
                        "name": "db-prod-01",
                    }
                ],
            }
        }


# =============================================================================
# Risk Score Schemas
# =============================================================================
class RiskScoreBreakdown(BaseModel):
    """Breakdown of risk score components."""

    impact: float = Field(..., description="I = likert_score / 5.0")
    vulnerability: float = Field(..., description="V = 100 - SCA_pass_percentage")
    threat: float = Field(..., description="T_now = T_new + (T_prev × decay)")
    w1: float = Field(default=0.3, description="Vulnerability weight")
    w2: float = Field(default=0.7, description="Threat weight")
    formula: str = Field(
        default="R = I × (w1×V + w2×T)",
        description="Formula explanation",
    )

    class Config:
        json_schema_extra = {
            "example": {
                "impact": 1.0,
                "vulnerability": 61.0,
                "threat": 78.0,
                "w1": 0.3,
                "w2": 0.7,
                "formula": "R = 1.0 × (0.3×61 + 0.7×78) = 72.9",
            }
        }


class RiskScoreResponse(BaseModel):
    """Response containing risk score for a single asset."""

    asset_id: str
    hostname: str
    timestamp: datetime
    risk_score: float = Field(..., ge=0.0, le=100.0)
    severity: str = Field(
        ...,
        description="Severity level: Low (<40) | Medium (<70) | High (<90) | Critical (>=90)",
    )
    breakdown: RiskScoreBreakdown

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "asset_id": "asset-001",
                "hostname": "db-prod-01",
                "timestamp": "2026-03-13T08:00:00Z",
                "risk_score": 72.5,
                "severity": "High",
                "breakdown": {
                    "impact": 1.0,
                    "vulnerability": 61.0,
                    "threat": 78.0,
                    "w1": 0.3,
                    "w2": 0.7,
                },
            }
        }


class LatestScoresResponse(BaseModel):
    """Response containing latest risk scores for all assets."""

    timestamp: datetime
    total_assets: int
    scores: list[RiskScoreResponse]
    summary: Optional[dict] = Field(
        None,
        description="Summary statistics (avg score, severity distribution, etc)",
        example={
            "average_score": 45.3,
            "critical_count": 0,
            "high_count": 2,
            "medium_count": 3,
            "low_count": 2,
        },
    )

    class Config:
        json_schema_extra = {
            "example": {
                "timestamp": "2026-03-13T09:00:00Z",
                "total_assets": 7,
                "scores": [
                    {
                        "asset_id": "asset-001",
                        "hostname": "db-prod-01",
                        "risk_score": 72.5,
                        "severity": "High",
                    }
                ],
                "summary": {
                    "average_score": 45.3,
                    "critical_count": 0,
                    "high_count": 2,
                },
            }
        }


class TrendPointResponse(BaseModel):
    """Single data point in a risk score trend."""

    timestamp: datetime
    risk_score: float
    severity: str

    class Config:
        from_attributes = True


class TrendResponse(BaseModel):
    """Response containing risk score trend for an asset."""

    asset_id: str
    hostname: str
    period: str = Field(..., description="Time period (e.g., '7d', '30d')")
    total_points: int
    trend_data: list[TrendPointResponse]

    class Config:
        json_schema_extra = {
            "example": {
                "asset_id": "asset-001",
                "hostname": "db-prod-01",
                "period": "7d",
                "total_points": 168,
                "trend_data": [
                    {"timestamp": "2026-03-06T08:00:00Z", "risk_score": 45.2, "severity": "Medium"},
                    {"timestamp": "2026-03-06T09:00:00Z", "risk_score": 46.1, "severity": "Medium"},
                ],
            }
        }


# =============================================================================
# Dashboard Schemas
# =============================================================================
class DashboardTrendPeriod(str, Enum):
    """Supported period filters for dashboard trend endpoint."""

    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    YEARLY = "yearly"


class DashboardSortOrder(str, Enum):
    """Sort direction for dashboard list endpoints."""

    ASC = "asc"
    DESC = "desc"


class DashboardAssetsSortBy(str, Enum):
    """Sortable columns for dashboard assets table."""

    ASSET_NAME = "asset_name"
    ASSET_TYPE = "asset_type"
    RISK_SCORE = "risk_score"
    STATUS = "status"
    LAST_UPDATED = "last_updated"


class DashboardRiskLevel(str, Enum):
    """Risk level filter for dashboard assets table."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DashboardMetaResponse(BaseModel):
    """Metadata for dashboard responses."""

    generated_at: datetime
    request_id: Optional[str] = None
    page: Optional[int] = None
    page_size: Optional[int] = None
    total_items: Optional[int] = None
    total_pages: Optional[int] = None


class DashboardRiskDistribution(BaseModel):
    """Asset distribution by risk severity."""

    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0


class DashboardSummaryData(BaseModel):
    """Summary cards for dashboard header."""

    total_assets: int
    risk_distribution: DashboardRiskDistribution


class DashboardSummaryResponse(BaseModel):
    """Response model for dashboard summary endpoint."""

    data: DashboardSummaryData
    meta: DashboardMetaResponse


class DashboardRiskTrendPoint(BaseModel):
    """One aggregated point in dashboard risk trend."""

    timestamp: datetime
    average_risk: float
    low_count: int
    medium_count: int
    high_count: int
    critical_count: int
    total_samples: int


class DashboardRiskTrendData(BaseModel):
    """Trend payload for dashboard line chart."""

    period: DashboardTrendPeriod
    total_points: int
    points: list[DashboardRiskTrendPoint]


class DashboardRiskTrendResponse(BaseModel):
    """Response model for dashboard risk trend endpoint."""

    data: DashboardRiskTrendData
    meta: DashboardMetaResponse


class DashboardLatestAlertItem(BaseModel):
    """Latest alert item for dashboard alert feed."""

    asset_id: str
    asset_name: str
    risk_status: str
    event_time: datetime
    alert_summary: Optional[str] = None
    rule_level: int


class DashboardLatestAlertsResponse(BaseModel):
    """Response model for latest alerts endpoint."""

    data: list[DashboardLatestAlertItem]
    meta: DashboardMetaResponse


class DashboardAssetsTableItem(BaseModel):
    """One row in dashboard assets table."""

    asset_id: str
    asset_name: str
    asset_type: Optional[str] = None
    risk_score: Optional[float] = None
    risk_status: str
    status: Optional[str] = None
    last_updated: datetime


class DashboardAssetsTableResponse(BaseModel):
    """Response model for dashboard assets table endpoint."""

    data: list[DashboardAssetsTableItem]
    meta: DashboardMetaResponse


class DashboardAssetProfile(BaseModel):
    """Normalized asset profile used by detail/report endpoints."""

    asset_id: str
    asset_name: str
    asset_type: Optional[str] = None
    asset_status: Optional[str] = None
    ip_address: Optional[str] = None
    last_updated: datetime


class DashboardRiskSummary(BaseModel):
    """Current risk summary for an asset."""

    current_risk_score: float
    risk_status: str
    risk_description: str
    impact_score: Optional[float] = None
    vulnerability_score: Optional[float] = None
    threat_score: Optional[float] = None


class DashboardVulnerabilityItem(BaseModel):
    """Vulnerability item shown in asset detail/report sections."""

    name: str
    score: float
    status: str
    detail: Optional[str] = None


class DashboardSecurityAlertItem(BaseModel):
    """Security alert item for dashboard detail/report endpoints."""

    event_time: datetime
    rule_level: int
    rule_id: Optional[str] = None
    description: Optional[str] = None


class DashboardActivityLogItem(BaseModel):
    """Asset activity log item."""

    event_time: datetime
    activity_type: str
    activity_detail: Optional[str] = None


class DashboardRiskHistoryItem(BaseModel):
    """7-day risk history entry."""

    date: datetime
    risk_score: float
    status: str
    detail: Optional[str] = None


class DashboardAssetDetailData(BaseModel):
    """Payload for the asset detail popup endpoint."""

    asset_profile: DashboardAssetProfile
    risk_summary: DashboardRiskSummary
    vulnerabilities: list[DashboardVulnerabilityItem]
    security_alerts: list[DashboardSecurityAlertItem]
    activity_log: list[DashboardActivityLogItem]
    last_updated: datetime


class DashboardAssetDetailResponse(BaseModel):
    """Response model for dashboard asset detail endpoint."""

    data: DashboardAssetDetailData
    meta: DashboardMetaResponse


class DashboardAssetSecurityReportData(BaseModel):
    """Payload for the asset security report endpoint."""

    asset_profile: DashboardAssetProfile
    risk_summary: DashboardRiskSummary
    risk_history_7d: list[DashboardRiskHistoryItem]
    vulnerabilities: list[DashboardVulnerabilityItem]
    security_alerts: list[DashboardSecurityAlertItem]


class DashboardAssetSecurityReportResponse(BaseModel):
    """Response model for dashboard asset security report endpoint."""

    data: DashboardAssetSecurityReportData
    meta: DashboardMetaResponse


# =============================================================================
# Observability Schemas
# =============================================================================
class MetricsLatency(BaseModel):
    """Latency percentile and average metrics."""

    avg: float
    p50: float
    p95: float
    p99: float
    count: int


class MetricsSnapshotResponse(BaseModel):
    """In-memory API metrics snapshot for operations monitoring."""

    total_requests: int
    success_count: int
    client_error_count: int
    server_error_count: int
    error_rate_5xx: float
    latency_ms: MetricsLatency
    latency_histogram_ms: dict[str, int]
    status_classes: dict[str, int]
    requests_by_endpoint: dict[str, int]
    requests_by_role: dict[str, int]


# =============================================================================
# Simulation Schemas
# =============================================================================
class SimulateSpikeRequest(BaseModel):
    """Request to simulate a security threat spike."""

    asset_ids: list[str] = Field(
        ...,
        min_items=1,
        description="Asset IDs to inject threat spike into",
    )
    threat_value: float = Field(
        default=100.0,
        ge=0.0,
        le=100.0,
        description="Threat value to inject (0-100)",
    )
    reason: Optional[str] = Field(
        None,
        max_length=200,
        description="Reason for the spike (for audit trail)",
    )

    class Config:
        json_schema_extra = {
            "example": {
                "asset_ids": ["asset-001", "asset-002"],
                "threat_value": 85.0,
                "reason": "Simulated brute force attack on Database server",
            }
        }


class SimulateSpikeResponse(BaseModel):
    """Response after simulating a spike."""

    message: str
    affected_assets: int
    new_scores: list[RiskScoreResponse]

    class Config:
        json_schema_extra = {
            "example": {
                "message": "Threat spike simulated successfully",
                "affected_assets": 2,
                "new_scores": [
                    {
                        "asset_id": "asset-001",
                        "risk_score": 88.5,
                        "severity": "High",
                    }
                ],
            }
        }


class SimulateRemediationRequest(BaseModel):
    """Request to simulate threat remediation."""

    asset_ids: list[str] = Field(
        ...,
        min_items=1,
        description="Asset IDs to remediate",
    )

    class Config:
        json_schema_extra = {
            "example": {
                "asset_ids": ["asset-001", "asset-002"],
            }
        }


class SimulateRemediationResponse(BaseModel):
    """Response after simulating remediation."""

    message: str
    affected_assets: int
    new_scores: list[RiskScoreResponse]

    class Config:
        json_schema_extra = {
            "example": {
                "message": "Threat remediation simulated successfully",
                "affected_assets": 2,
                "new_scores": [
                    {
                        "asset_id": "asset-001",
                        "risk_score": 25.3,
                        "severity": "Low",
                    }
                ],
            }
        }


# =============================================================================
# Health Check & Metadata
# =============================================================================
class HealthCheckResponse(BaseModel):
    """Health check response."""

    status: str = Field(..., description="System status: 'healthy' or 'degraded'")
    timestamp: datetime
    version: str = Field(..., description="API version")
    database: str = Field(..., description="Database connection status")

    class Config:
        json_schema_extra = {
            "example": {
                "status": "healthy",
                "timestamp": "2026-03-13T08:00:00Z",
                "version": "1.0.0",
                "database": "connected",
            }
        }
