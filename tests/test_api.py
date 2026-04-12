"""Focused tests for Firebase auth and bearer-protected API routes."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from uuid import uuid4

from api.main import app
from api.security import create_access_token, hash_password, verify_password, verify_token


auth_client = TestClient(app)
auth_client.headers.update(
    {
        "Authorization": (
            "Bearer "
            + create_access_token(
                user_id=1,
                username="testuser",
                email="test@example.com",
                role="CISO",
            )[0]
        )
    }
)

public_client = TestClient(app)


class TestPasswordHashing:
    def test_hash_password(self):
        password = "SecurePass123!"
        hashed = hash_password(password)

        assert hashed != password
        assert hashed.startswith("$2b$")

    def test_verify_password(self):
        password = "SecurePass123!"
        hashed = hash_password(password)

        assert verify_password(password, hashed)
        assert not verify_password("WrongPassword", hashed)


class TestJWTToken:
    def test_create_access_token(self):
        token, expires_in = create_access_token(
            user_id=1,
            username="testuser",
            email="test@example.com",
            role="Manajemen",
        )

        assert isinstance(token, str)
        assert token
        assert isinstance(expires_in, int)
        assert expires_in > 0

    def test_verify_token_valid(self):
        token, _ = create_access_token(
            user_id=1,
            username="testuser",
            email="test@example.com",
            role="Manajemen",
        )

        payload = verify_token(token)
        assert payload is not None
        assert payload.user_id == 1
        assert payload.username == "testuser"
        assert payload.email == "test@example.com"
        assert payload.role == "Manajemen"

    def test_verify_token_invalid(self):
        assert verify_token("invalid.token.here") is None

    def test_token_expiration_does_not_crash(self):
        token, _ = create_access_token(
            user_id=1,
            username="testuser",
            email="test@example.com",
            role="Manajemen",
            expires_in_hours=0,
        )

        verify_token(token)


class TestAuthAPI:
    @pytest.fixture(autouse=True)
    def _mock_firebase(self, monkeypatch):
        email = f"firebase-user-{uuid4().hex[:8]}@example.com"
        claims = {
            "uid": f"firebase-uid-{uuid4().hex[:12]}",
            "email": email,
            "email_verified": True,
            "name": "Firebase User",
            "picture": "https://example.com/avatar.png",
            "firebase": {"sign_in_provider": "password"},
        }

        async def _noop_async(*args, **kwargs):
            return None

        monkeypatch.setattr(
            "api.services.firebase_auth_service.FirebaseAuthService.verify_id_token",
            lambda self, id_token: claims,
        )
        monkeypatch.setattr(
            "api.services.firebase_auth_service.FirebaseAuthService.send_email_verification",
            _noop_async,
        )
        monkeypatch.setattr(
            "api.services.firebase_auth_service.FirebaseAuthService.send_password_reset_email",
            _noop_async,
        )

        return claims

    def test_firebase_sign_in_creates_pending_user(self):
        response = auth_client.post(
            "/auth/firebase/sign-in",
            json={"id_token": "firebase-id-token-1234567890"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["role_required"] is True
        assert data["firebase_uid"].startswith("firebase-uid-")
        assert data["email_verified"] is True
        assert data["session"] is None

    def test_firebase_complete_profile_returns_session(self):
        response = auth_client.post(
            "/auth/firebase/complete-profile",
            json={"id_token": "firebase-id-token-1234567890", "role": "Manajemen"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["role_required"] is False
        assert data["role"] == "Manajemen"
        assert data["session"] is not None
        assert data["session"]["token_type"] == "bearer"

    def test_firebase_email_verification_action(self):
        response = auth_client.post(
            "/auth/firebase/send-email-verification",
            json={"id_token": "firebase-id-token-1234567890"},
        )

        assert response.status_code == 200
        assert "Verification email" in response.json()["message"]

    def test_firebase_password_reset_action(self):
        response = auth_client.post(
            "/auth/firebase/password-reset",
            json={"email": "firebase-user@example.com"},
        )

        assert response.status_code == 200
        assert "password reset email" in response.json()["message"].lower()


class TestProtectedRoutes:
    def test_assets_require_authentication(self):
        assert public_client.get("/assets").status_code == 401
        assert public_client.get("/assets/asset-001").status_code == 401

    def test_scores_require_authentication(self):
        assert public_client.get("/scores/latest").status_code == 401
        assert public_client.get("/scores/asset-001").status_code == 401
        assert public_client.get("/trends/asset-001?period=7d").status_code == 401

    def test_simulation_requires_authentication(self):
        assert public_client.post(
            "/simulate/spike",
            json={"asset_ids": ["asset-001"], "threat_value": 85.0},
        ).status_code == 401
        assert public_client.post(
            "/simulate/remediation",
            json={"asset_ids": ["asset-001"]},
        ).status_code == 401