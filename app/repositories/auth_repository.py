from threading import Lock

from app.models.user import UserModel, utc_now
from app.services.firebase_auth_service import FirebaseUserClaims


class AuthRepository:
    def __init__(self) -> None:
        self._users_by_uid: dict[str, UserModel] = {}
        self._lock = Lock()

    def upsert_from_firebase_claims(
        self,
        claims: FirebaseUserClaims,
    ) -> tuple[UserModel, bool]:
        with self._lock:
            current_user = self._users_by_uid.get(claims.uid)

            if current_user is None:
                user = UserModel(
                    firebase_uid=claims.uid,
                    email=claims.email,
                    display_name=claims.display_name,
                    photo_url=claims.photo_url,
                    provider=claims.provider,
                )
                self._users_by_uid[user.firebase_uid] = user
                return user, True

            current_user.email = claims.email or current_user.email
            current_user.display_name = claims.display_name or current_user.display_name
            current_user.photo_url = claims.photo_url or current_user.photo_url
            current_user.provider = claims.provider
            return current_user, False

    def mark_last_login(self, firebase_uid: str) -> None:
        with self._lock:
            user = self._users_by_uid.get(firebase_uid)
            if user is not None:
                user.last_login_at = utc_now()
