import json
import os
from dataclasses import dataclass
from typing import Any

import firebase_admin
from fastapi import HTTPException, status
from firebase_admin import auth, credentials


@dataclass
class FirebaseUserClaims:
    uid: str
    email: str | None
    display_name: str | None
    photo_url: str | None
    provider: str


class FirebaseAuthService:
    def __init__(self) -> None:
        self._service_account_json = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON")
        self._project_id = os.getenv("FIREBASE_PROJECT_ID")

    def _build_service_account_from_env_fields(self) -> dict[str, str] | None:
        raw_private_key = os.getenv("FIREBASE_PRIVATE_KEY")
        client_email = os.getenv("FIREBASE_CLIENT_EMAIL")
        private_key_id = os.getenv("FIREBASE_PRIVATE_KEY_ID")
        client_id = os.getenv("FIREBASE_CLIENT_ID")

        has_split_fields = any(
            [
                raw_private_key,
                client_email,
                private_key_id,
                client_id,
            ]
        )
        if not has_split_fields:
            return None

        project_id = self._project_id
        missing_fields = [
            key
            for key, value in {
                "FIREBASE_PROJECT_ID": project_id,
                "FIREBASE_PRIVATE_KEY_ID": private_key_id,
                "FIREBASE_PRIVATE_KEY": raw_private_key,
                "FIREBASE_CLIENT_EMAIL": client_email,
                "FIREBASE_CLIENT_ID": client_id,
            }.items()
            if not value
        ]
        if missing_fields:
            raise RuntimeError(
                "Missing Firebase env fields: " + ", ".join(missing_fields)
            )

        private_key = raw_private_key.replace("\\n", "\n")

        return {
            "type": os.getenv("FIREBASE_ACCOUNT_TYPE", "service_account"),
            "project_id": project_id,
            "private_key_id": private_key_id,
            "private_key": private_key,
            "client_email": client_email,
            "client_id": client_id,
            "auth_uri": os.getenv(
                "FIREBASE_AUTH_URI",
                "https://accounts.google.com/o/oauth2/auth",
            ),
            "token_uri": os.getenv(
                "FIREBASE_TOKEN_URI",
                "https://oauth2.googleapis.com/token",
            ),
            "auth_provider_x509_cert_url": os.getenv(
                "FIREBASE_AUTH_PROVIDER_X509_CERT_URL",
                "https://www.googleapis.com/oauth2/v1/certs",
            ),
            "client_x509_cert_url": os.getenv(
                "FIREBASE_CLIENT_X509_CERT_URL",
                f"https://www.googleapis.com/robot/v1/metadata/x509/"
                f"{client_email.replace('@', '%40')}",
            ),
            "universe_domain": os.getenv("FIREBASE_UNIVERSE_DOMAIN", "googleapis.com"),
        }

    def _build_credentials(self) -> Any:
        if self._service_account_json:
            try:
                raw_service_account = json.loads(self._service_account_json)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    "FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON."
                ) from exc

            if not isinstance(raw_service_account, dict):
                raise RuntimeError(
                    "FIREBASE_SERVICE_ACCOUNT_JSON must be a JSON object."
                )

            private_key = raw_service_account.get("private_key")
            if isinstance(private_key, str):
                raw_service_account["private_key"] = private_key.replace("\\n", "\n")

            return credentials.Certificate(raw_service_account)

        service_account = self._build_service_account_from_env_fields()
        if service_account:
            return credentials.Certificate(service_account)

        return credentials.ApplicationDefault()

    def _get_app(self) -> Any:
        try:
            return firebase_admin.get_app()
        except ValueError:
            cred = self._build_credentials()

            options: dict[str, str] = {}
            if self._project_id:
                options["projectId"] = self._project_id

            return firebase_admin.initialize_app(cred, options)

    def verify_id_token(self, id_token: str) -> FirebaseUserClaims:
        try:
            decoded_token = auth.verify_id_token(
                id_token=id_token,
                app=self._get_app(),
                check_revoked=True,
            )
        except auth.ExpiredIdTokenError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Firebase token is expired.",
            ) from exc
        except auth.RevokedIdTokenError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Firebase token has been revoked.",
            ) from exc
        except auth.InvalidIdTokenError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Firebase token is invalid.",
            ) from exc
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(exc),
            ) from exc
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to validate Firebase token.",
            ) from exc

        provider = decoded_token.get("firebase", {}).get("sign_in_provider", "firebase")

        return FirebaseUserClaims(
            uid=decoded_token["uid"],
            email=decoded_token.get("email"),
            display_name=decoded_token.get("name"),
            photo_url=decoded_token.get("picture"),
            provider=provider,
        )
