from dataclasses import dataclass, field
from datetime import datetime, timezone


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class UserModel:
    firebase_uid: str
    email: str | None = None
    display_name: str | None = None
    photo_url: str | None = None
    provider: str = "firebase"
    created_at: datetime = field(default_factory=utc_now)
    last_login_at: datetime | None = None
