"""
Pydantic schemas for request/response validation and documentation.

Organized by feature:
    - Auth schemas: Register, Login, Verify OTP
    - Asset schemas: Asset CRUD
    - Score schemas: Risk score queries and responses
    - Error schemas: Standard error response format
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


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


# =============================================================================
# Authentication Schemas
# =============================================================================
class RegisterRequest(BaseModel):
    """User registration request."""

    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        description="Unique username (alphanumeric, 3-50 chars)",
        example="john_doe",
    )
    email: EmailStr = Field(
        ...,
        description="Email address (must be unique and valid)",
        example="john@example.com",
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=100,
        description="Password (min 8 chars; must include uppercase, lowercase, digit, special char)",
        example="SecurePass123!",
    )

    class Config:
        json_schema_extra = {
            "example": {
                "username": "analyst_jane",
                "email": "jane.doe@bank.com",
                "password": "MySecurePassword123!",
            }
        }


class RegisterResponse(BaseModel):
    """Response after successful registration."""

    user_id: int = Field(..., description="Newly created user ID")
    username: str
    email: str
    message: str = Field(default="Registration successful. Please verify your email using the OTP sent.")
    verification_required: bool = Field(default=True)

    class Config:
        json_schema_extra = {
            "example": {
                "user_id": 1,
                "username": "analyst_jane",
                "email": "jane.doe@bank.com",
                "message": "Registration successful. Please verify your email using the OTP sent.",
                "verification_required": True,
            }
        }


class LoginRequest(BaseModel):
    """User login request."""

    email: EmailStr = Field(..., description="Email or username", example="john@example.com")
    password: str = Field(..., description="Account password")

    class Config:
        json_schema_extra = {
            "example": {
                "email": "john@example.com",
                "password": "SecurePass123!",
            }
        }


class LoginResponse(BaseModel):
    """Response after successful login."""

    user_id: int
    username: str
    email: str
    role: str = Field(..., description="User role: admin, analyst, viewer")
    access_token: str = Field(..., description="JWT bearer token for API authentication")
    token_type: str = Field(default="bearer", description="Token type (always 'bearer')")
    expires_in: int = Field(..., description="Token expiration time in seconds")

    class Config:
        json_schema_extra = {
            "example": {
                "user_id": 1,
                "username": "analyst_jane",
                "email": "jane.doe@bank.com",
                "role": "analyst",
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 86400,
            }
        }


class VerifyOTPRequest(BaseModel):
    """Request to verify OTP code."""

    email: EmailStr = Field(..., description="User email address")
    otp_code: str = Field(
        ...,
        min_length=6,
        max_length=10,
        description="OTP code received via email",
        example="123456",
    )

    class Config:
        json_schema_extra = {
            "example": {
                "email": "jane.doe@bank.com",
                "otp_code": "123456",
            }
        }


class VerifyOTPResponse(BaseModel):
    """Response after successful OTP verification."""

    message: str = Field(default="Email verified successfully. Account is now active.")
    is_verified: bool = Field(default=True)
    user_id: int

    class Config:
        json_schema_extra = {
            "example": {
                "message": "Email verified successfully. Account is now active.",
                "is_verified": True,
                "user_id": 1,
            }
        }


class ResendOTPRequest(BaseModel):
    """Request to resend OTP code."""

    email: EmailStr = Field(..., description="User email address")

    class Config:
        json_schema_extra = {
            "example": {
                "email": "jane.doe@bank.com",
            }
        }


class ResendOTPResponse(BaseModel):
    """Response after OTP resend."""

    message: str = Field(default="OTP has been resent to your email address.")
    expires_in_minutes: int = Field(..., description="OTP expiration time in minutes")

    class Config:
        json_schema_extra = {
            "example": {
                "message": "OTP has been resent to your email address.",
                "expires_in_minutes": 15,
            }
        }


# =============================================================================
# Asset Schemas
# =============================================================================
class AssetCreate(BaseModel):
    """Request to create a new asset."""

    hostname: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Asset hostname",
        example="db-server-01",
    )
    wazuh_agent_id: Optional[str] = Field(
        None,
        max_length=10,
        description="Wazuh agent ID (if linked)",
        example="001",
    )
    ip_address: Optional[str] = Field(
        None,
        max_length=45,
        description="IPv4 or IPv6 address",
        example="192.168.1.10",
    )
    likert_score: float = Field(
        ...,
        ge=1.0,
        le=5.0,
        description="Business impact score (1.0=not critical, 5.0=most critical)",
        example=4.5,
    )
    description: Optional[str] = Field(
        None,
        max_length=500,
        description="Asset description",
        example="Primary database server for customer accounts",
    )

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
    """Request to update an asset (all fields optional)."""

    hostname: Optional[str] = Field(None, max_length=100)
    ip_address: Optional[str] = Field(None, max_length=45)
    likert_score: Optional[float] = Field(None, ge=1.0, le=5.0)
    description: Optional[str] = Field(None, max_length=500)

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
    hostname: str
    wazuh_agent_id: Optional[str]
    ip_address: Optional[str]
    likert_score: float
    impact: float = Field(..., description="Normalized impact (I = likert_score / 5.0)")
    description: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "asset_id": "asset-001",
                "hostname": "db-prod-01",
                "wazuh_agent_id": "001",
                "ip_address": "192.168.1.100",
                "likert_score": 5.0,
                "impact": 1.0,
                "description": "Production customer database (critical)",
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
                        "asset_id": "asset-001",
                        "hostname": "db-prod-01",
                        "likert_score": 5.0,
                        "impact": 1.0,
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
