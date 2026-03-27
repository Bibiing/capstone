"""Business logic for authentication and OTP workflows."""

from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.email import send_otp_email, send_otp_resend_notification
from api.schemas import AuthRole, LoginRequest, LoginResponse, RegisterRequest, RegisterResponse
from api.schemas import ResendOTPRequest, ResendOTPResponse, VerifyOTPRequest, VerifyOTPResponse
from api.security import (
    create_access_token,
    generate_otp,
    get_otp_expiration_time,
    hash_password,
    is_otp_expired,
    verify_password,
)
from config.settings import Settings
from database.models import OTPCode, User, UserRole
from database.repositories.auth_repository import AuthRepository
from api.services.rate_limiter import InMemoryRateLimiter


class AuthService:
    """Use-case service for user auth flows."""

    def __init__(
        self,
        settings: Settings,
        repository: AuthRepository,
        rate_limiter: InMemoryRateLimiter,
    ) -> None:
        self._settings = settings
        self._repo = repository
        self._rate_limiter = rate_limiter

    @staticmethod
    def _normalize_email(email: str) -> str:
        return email.lower().strip()

    @staticmethod
    def _validate_password_strength(password: str) -> None:
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        if not (has_upper and has_lower and has_digit and has_special):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Password must contain: uppercase, lowercase, digit, and special character. "
                    "Example: SecurePass123!"
                ),
            )

    async def register(self, db: Session, request: RegisterRequest) -> RegisterResponse:
        self._validate_password_strength(request.password)

        normalized_email = self._normalize_email(request.email)
        if not self._rate_limiter.allow(
            key=f"auth:register:{normalized_email}",
            limit=self._settings.auth_register_limit_per_hour,
            window_seconds=3600,
        ):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many registration attempts. Please try again later.",
            )

        existing_user = self._repo.get_user_by_username_or_email(
            db=db,
            username=request.username,
            email=normalized_email,
        )

        if existing_user is not None:
            detail = (
                "Username is already registered"
                if existing_user.username == request.username
                else "Email is already registered"
            )
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)

        new_user = User(
            username=request.username,
            email=normalized_email,
            password_hash=hash_password(request.password),
            role=UserRole(request.role.value),
            is_active=False,
            is_verified=False,
        )

        self._repo.add_user(db, new_user)
        try:
            db.flush()
        except IntegrityError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username or email is already registered",
            )

        otp_code = generate_otp()
        self._repo.add_otp(
            db,
            OTPCode(
                user_id=new_user.user_id,
                code=otp_code,
                expires_at=get_otp_expiration_time(),
                is_used=False,
                attempts=0,
            ),
        )

        email_sent = await send_otp_email(
            to_email=request.email,
            otp_code=otp_code,
            settings=self._settings,
            username=request.username,
        )

        if email_sent:
            message = (
                "Registration successful! "
                "A verification code has been sent to your email. "
                "Please check your inbox and verify within 15 minutes."
            )
        else:
            message = (
                "Registration successful, but there was an issue sending the verification email. "
                "Please check your spam folder or request a new code."
            )

        return RegisterResponse(
            user_id=new_user.user_id,
            username=request.username,
            email=normalized_email,
            role=request.role,
            message=message,
            verification_required=True,
        )

    async def login(self, db: Session, request: LoginRequest) -> LoginResponse:
        normalized_email = self._normalize_email(request.email)
        if not self._rate_limiter.allow(
            key=f"auth:login:{normalized_email}",
            limit=self._settings.auth_login_limit_per_15m,
            window_seconds=900,
        ):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many login attempts. Please try again later.",
            )

        user = self._repo.get_user_by_email(db, normalized_email)

        if user is None or not verify_password(request.password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Email not verified. Please verify your OTP first.",
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is inactive. Contact administrator.",
            )

        access_token, expires_in = create_access_token(
            user_id=user.user_id,
            username=user.username,
            email=user.email,
            role=user.role.value,
        )

        return LoginResponse(
            user_id=user.user_id,
            username=user.username,
            email=user.email,
            role=AuthRole(user.role.value),
            access_token=access_token,
            token_type="bearer",
            expires_in=expires_in,
        )

    async def verify_otp(self, db: Session, request: VerifyOTPRequest) -> VerifyOTPResponse:
        normalized_email = self._normalize_email(request.email)
        if not self._rate_limiter.allow(
            key=f"auth:verify:{normalized_email}",
            limit=self._settings.auth_verify_limit_per_15m,
            window_seconds=900,
        ):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many OTP verification attempts. Please try again later.",
            )

        user = self._repo.get_user_by_email(db, normalized_email)

        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        if user.is_verified:
            return VerifyOTPResponse(
                message="Email already verified.",
                is_verified=True,
                user_id=user.user_id,
            )

        latest_otp = self._repo.get_latest_pending_otp(db, user.user_id)
        if latest_otp is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No pending OTP found. Please request a new OTP.",
            )

        if is_otp_expired(latest_otp.expires_at):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OTP has expired. Please request a new OTP.",
            )

        if latest_otp.attempts >= self._settings.otp_max_attempts:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Maximum OTP attempts exceeded. Please request a new OTP.",
            )

        if latest_otp.code != request.otp_code:
            latest_otp.attempts += 1
            remaining_attempts = max(self._settings.otp_max_attempts - latest_otp.attempts, 0)
            if latest_otp.attempts >= self._settings.otp_max_attempts:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Maximum OTP attempts exceeded. Please request a new OTP.",
                )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid OTP code. Remaining attempts: {remaining_attempts}",
            )

        latest_otp.is_used = True
        user.is_verified = True
        user.is_active = True

        return VerifyOTPResponse(
            message="Email verified successfully. Account is now active.",
            is_verified=True,
            user_id=user.user_id,
        )

    async def resend_otp(self, db: Session, request: ResendOTPRequest) -> ResendOTPResponse:
        normalized_email = self._normalize_email(request.email)
        if not self._rate_limiter.allow(
            key=f"auth:resend:{normalized_email}",
            limit=self._settings.auth_resend_limit_per_hour,
            window_seconds=3600,
        ):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many OTP resend attempts. Please try again later.",
            )

        user = self._repo.get_user_by_email(db, normalized_email)

        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        if user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User is already verified",
            )

        for otp in self._repo.get_pending_otps(db, user.user_id):
            otp.is_used = True

        new_otp = generate_otp()
        self._repo.add_otp(
            db,
            OTPCode(
                user_id=user.user_id,
                code=new_otp,
                expires_at=get_otp_expiration_time(),
                is_used=False,
                attempts=0,
            ),
        )

        email_sent = await send_otp_resend_notification(
            to_email=request.email,
            otp_code=new_otp,
            settings=self._settings,
            attempt_number=1,
        )

        if not email_sent:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Failed to send verification email. Please try again later.",
            )

        return ResendOTPResponse(
            message=f"A new verification code has been sent to {request.email}",
            expires_in_minutes=self._settings.otp_expiration_minutes,
        )
