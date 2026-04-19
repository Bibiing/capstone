from app.repositories.auth_repository import AuthRepository
from app.schemas.auth import AuthResponse, AuthUserResponse
from app.services.firebase_auth_service import FirebaseAuthService


class AuthService:
    def __init__(
        self,
        firebase_auth_service: FirebaseAuthService,
        auth_repository: AuthRepository,
    ) -> None:
        self._firebase_auth_service = firebase_auth_service
        self._auth_repository = auth_repository

    def register(self, id_token: str) -> AuthResponse:
        claims = self._firebase_auth_service.verify_id_token(id_token)
        user, is_new_user = self._auth_repository.upsert_from_firebase_claims(claims)
        self._auth_repository.mark_last_login(user.firebase_uid)

        message = "Registration successful" if is_new_user else "User already registered"

        return AuthResponse(
            message=message,
            is_new_user=is_new_user,
            user=AuthUserResponse(
                firebase_uid=user.firebase_uid,
                email=user.email,
                display_name=user.display_name,
                photo_url=user.photo_url,
                provider=user.provider,
            ),
        )

    def login(self, id_token: str) -> AuthResponse:
        claims = self._firebase_auth_service.verify_id_token(id_token)
        user, is_new_user = self._auth_repository.upsert_from_firebase_claims(claims)
        self._auth_repository.mark_last_login(user.firebase_uid)

        return AuthResponse(
            message="Login successful",
            is_new_user=is_new_user,
            user=AuthUserResponse(
                firebase_uid=user.firebase_uid,
                email=user.email,
                display_name=user.display_name,
                photo_url=user.photo_url,
                provider=user.provider,
            ),
        )
