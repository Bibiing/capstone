from fastapi import APIRouter

from app.repositories.auth_repository import AuthRepository
from app.schemas.auth import AuthResponse, FirebaseTokenRequest
from app.services.auth_service import AuthService
from app.services.firebase_auth_service import FirebaseAuthService

router = APIRouter(prefix="/auth", tags=["auth"])

firebase_auth_service = FirebaseAuthService()
auth_repository = AuthRepository()
auth_service = AuthService(
    firebase_auth_service=firebase_auth_service,
    auth_repository=auth_repository,
)


@router.post("/login", response_model=AuthResponse)
async def login(payload: FirebaseTokenRequest) -> AuthResponse:
    return auth_service.login(payload.id_token)


@router.post("/register", response_model=AuthResponse)
async def register(payload: FirebaseTokenRequest) -> AuthResponse:
    return auth_service.register(payload.id_token)