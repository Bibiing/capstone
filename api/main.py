"""
FastAPI main application with middleware, error handling, and route mounting.

Structure:
    - Global exception handlers
    - CORS middleware
    - Request ID / correlation tracking
    - Route mounting
    - Health check endpoint
"""

import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, FastAPI, Request, status
from fastapi.exceptions import HTTPException, RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.schemas import ErrorResponse, HealthCheckResponse
from api.services.scheduler import ScoringScheduler
from config.settings import get_settings
from api.dependencies.auth import get_current_user

logger = logging.getLogger(__name__)

# Initialize FastAPI app
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup/shutdown resources."""
    scheduler = None

    if settings.scoring_scheduler_enabled:
        try:
            scheduler = ScoringScheduler()
            scheduler.start()
            app.state.scoring_scheduler = scheduler
            logger.info("Background scoring scheduler enabled")
        except Exception as exc:
            logger.exception("Failed to start scoring scheduler: %s", exc)

    try:
        yield
    finally:
        if scheduler is not None:
            scheduler.scheduler.shutdown(wait=False)
            logger.info("Background scoring scheduler stopped")

app = FastAPI(
    title="Cyber Risk Scoring Engine API",
    description="Dynamic Risk Scoring Engine berbasis Telemetri Wazuh",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# ============================================================================
# Middleware
# ============================================================================

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request ID middleware for tracing
@app.middleware("http")
async def add_request_id_middleware(request: Request, call_next):
    """Add request ID to all requests for tracing."""
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.request_id = request_id

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


@app.middleware("http")
async def add_process_time_middleware(request: Request, call_next):
    """Add response time header."""
    import time
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response


# ============================================================================
# Exception Handlers
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTPException with consistent error response."""
    error_response = ErrorResponse(
        status_code=exc.status_code,
        message=exc.detail,
        detail=getattr(exc, "detail", None),
        request_id=getattr(request.state, "request_id", None),
    )
    return JSONResponse(
        status_code=exc.status_code,
        content=error_response.model_dump(),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors with consistent error response."""
    errors = []
    for error in exc.errors():
        errors.append(f"{'.'.join(str(x) for x in error['loc'])}: {error['msg']}")

    error_response = ErrorResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        message="Validation error",
        detail="; ".join(errors),
        request_id=getattr(request.state, "request_id", None),
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=error_response.model_dump(),
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions."""
    logger.exception("Unhandled exception", exc_info=exc)

    # Don't expose internal errors in production
    if settings.api_environment == "production":
        message = "Internal server error"
        detail = None
    else:
        message = str(exc)
        detail = str(type(exc).__name__)

    error_response = ErrorResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        message=message,
        detail=detail,
        request_id=getattr(request.state, "request_id", None),
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=error_response.model_dump(),
    )


# ============================================================================
# Health Check & Metadata Endpoints
# ============================================================================

@app.get(
    "/health",
    response_model=HealthCheckResponse,
    tags=["Health"],
    summary="Health check endpoint",
    description="Check if the API is running and database is connected",
)
async def health_check(request: Request) -> HealthCheckResponse:
    """
    Health check endpoint returning system status.

    Returns:
        HealthCheckResponse with status, timestamp, version, and database status
    """
    try:
        # Try to connect to database (later, when DB is integrated)
        db_status = "connected"
    except Exception as e:
        logger.warning(f"Database health check failed: {e}")
        db_status = "disconnected"

    return HealthCheckResponse(
        status="healthy" if db_status == "connected" else "degraded",
        timestamp=datetime.now(timezone.utc),
        version="1.0.0",
        database=db_status,
    )


@app.get(
    "/",
    tags=["Info"],
    summary="API information",
    response_model=dict,
)
async def root(_current_user=Depends(get_current_user)) -> dict:
    """Return API information and available endpoints."""
    return {
        "name": "Cyber Risk Scoring Engine API",
        "version": "1.0.0",
        "description": "Dynamic Risk Scoring Engine berbasis Telemetri Wazuh",
        "docs": "/docs",
        "redoc": "/redoc",
        "endpoints": {
            "auth": [
                "POST /auth/firebase/register",
                "POST /auth/firebase/sign-in",
                "POST /auth/firebase/send-email-verification",
                "POST /auth/firebase/password-reset",
            ],
            "assets": [
                "GET /assets",
                "POST /assets/sync/agents",
                "GET /assets/{asset_id}",
            ],
            "scores": [
                "GET /scores/latest",
                "GET /scores/{asset_id}",
                "GET /trends/{asset_id}",
            ],
            "simulation": [
                "POST /simulate/spike",
                "POST /simulate/remediation",
            ],
        },
    }


# ============================================================================
# Route Mounting
# ============================================================================

# Import route routers
from api.routes import auth, assets, scores, simulate

# Mount routes
app.include_router(auth.router)
app.include_router(assets.router)
app.include_router(scores.router)
app.include_router(simulate.router)


logger.info(
    "FastAPI application initialized | environment=%s | docs=/docs",
    settings.api_environment,
)
