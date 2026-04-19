from pydantic import BaseModel, Field


class FirebaseTokenRequest(BaseModel):
    id_token: str = Field(
        ...,
        min_length=10,
        description="Firebase ID token issued by the client SDK.",
    )


class AuthUserResponse(BaseModel):
    firebase_uid: str
    email: str | None = None
    display_name: str | None = None
    photo_url: str | None = None
    provider: str = "firebase"


class AuthResponse(BaseModel):
    message: str
    user: AuthUserResponse
    is_new_user: bool
