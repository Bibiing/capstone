"""
Email service for sending OTP codes via Resend API.

This module provides email delivery functionality for one-time passwords (OTP)
used in user registration and email verification workflows.

Usage:
    from api.email import send_otp_email
    from config.settings import get_settings

    settings = get_settings()
    await send_otp_email(
        to_email="user@example.com",
        otp_code="123456",
        settings=settings
    )
"""

import logging
from asyncio import sleep, to_thread
from typing import Optional

import resend

logger = logging.getLogger(__name__)


async def _send_email_with_retry(payload: dict, settings, event: str) -> bool:
    """Send email with bounded retries and exponential backoff."""
    max_attempts = settings.otp_email_max_retries
    base_delay = settings.otp_email_retry_delay_seconds

    for attempt in range(1, max_attempts + 1):
        try:
            response = await to_thread(resend.Emails.send, payload)
            email_id = getattr(response, "id", None)
            logger.info(
                "Email delivery success | event=%s | to=%s | attempt=%d | email_id=%s",
                event,
                payload.get("to"),
                attempt,
                email_id,
            )
            return True
        except Exception as exc:
            logger.warning(
                "Email delivery failed | event=%s | to=%s | attempt=%d/%d | error=%s",
                event,
                payload.get("to"),
                attempt,
                max_attempts,
                str(exc),
            )
            if attempt < max_attempts:
                await sleep(base_delay * (2 ** (attempt - 1)))

    return False


async def send_otp_email(
    to_email: str,
    otp_code: str,
    settings,
    username: Optional[str] = None,
) -> bool:
    """
    Send OTP code via email using Resend API.

    Args:
        to_email: Recipient email address
        otp_code: 6-digit OTP code to send
        settings: Settings instance (contains API key, sender email, etc)
        username: Optional username for personalization

    Returns:
        True if email sent successfully, False otherwise

    Raises:
        No exceptions raised; failures are logged and return False
    """
    try:
        # Initialize Resend client with API key
        resend.api_key = settings.resend_api_key.get_secret_value()

        # Prepare email subject and HTML content
        subject = "Email Verification - OTP Code"
        greeting = f"Hi {username}," if username else "Hi,"

        html_content = f"""
        <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ color: #333; margin-bottom: 20px; }}
                    .code-box {{
                        background-color: #f0f0f0;
                        border: 2px solid #007bff;
                        padding: 20px;
                        text-align: center;
                        margin: 30px 0;
                        border-radius: 5px;
                    }}
                    .code {{ font-size: 32px; font-weight: bold; color: #007bff; letter-spacing: 5px; }}
                    .footer {{ color: #666; font-size: 12px; margin-top: 30px; }}
                    .warning {{ color: #d9534f; font-weight: bold; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h2>Email Verification Required</h2>
                    </div>

                    <p>{greeting}</p>

                    <p>
                        Your account registration is almost complete! 
                        Please verify your email address by entering the code below:
                    </p>

                    <div class="code-box">
                        <div class="code">{otp_code}</div>
                    </div>

                    <p>
                        <strong>This code will expire in 15 minutes.</strong>
                    </p>

                    <p>
                        <span class="warning">⚠️ Do not share this code with anyone.</span>
                        Cyber Risk Scoring Engine administrators will never ask for this code.
                    </p>

                    <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0;">

                    <div class="footer">
                        <p>
                            If you did not request this verification code, 
                            please ignore this email or contact support immediately.
                        </p>
                        <p>
                            Cyber Risk Scoring Engine<br>
                            Dynamic Risk Scoring Platform
                        </p>
                    </div>
                </div>
            </body>
        </html>
        """

        payload = {
            "from": settings.otp_from_email,
            "to": to_email,
            "subject": subject,
            "html": html_content,
        }

        return await _send_email_with_retry(payload, settings, event="otp_register")

    except Exception as e:
        # Log error details for debugging
        logger.error(
            "Failed to send OTP email | to=%s | error=%s | type=%s",
            to_email,
            str(e),
            type(e).__name__,
            exc_info=True,
        )
        return False


async def send_otp_resend_notification(
    to_email: str,
    otp_code: str,
    settings,
    attempt_number: int = 1,
) -> bool:
    """
    Send OTP resend notification (when user requests new code).

    Args:
        to_email: Recipient email address
        otp_code: New 6-digit OTP code
        settings: Settings instance
        attempt_number: Which resend attempt (for logging)

    Returns:
        True if email sent successfully, False otherwise
    """
    try:
        resend.api_key = settings.resend_api_key.get_secret_value()

        subject = "New Verification Code - OTP Resent"

        html_content = f"""
        <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .code-box {{
                        background-color: #f0f0f0;
                        border: 2px solid #28a745;
                        padding: 20px;
                        text-align: center;
                        margin: 20px 0;
                        border-radius: 5px;
                    }}
                    .code {{ font-size: 32px; font-weight: bold; color: #28a745; letter-spacing: 5px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h2>New Verification Code</h2>
                    <p>Your new verification code is:</p>

                    <div class="code-box">
                        <div class="code">{otp_code}</div>
                    </div>

                    <p><strong>This code will expire in 15 minutes.</strong></p>

                    <p>Use this code to complete your email verification.</p>

                    <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0;">

                    <p style="color: #666; font-size: 12px;">
                        Cyber Risk Scoring Engine
                    </p>
                </div>
            </body>
        </html>
        """

        payload = {
            "from": settings.otp_from_email,
            "to": to_email,
            "subject": subject,
            "html": html_content,
        }

        return await _send_email_with_retry(payload, settings, event="otp_resend")

    except Exception as e:
        logger.error(
            "Failed to send OTP resend email | to=%s | attempt=%d | error=%s",
            to_email,
            attempt_number,
            str(e),
            exc_info=True,
        )
        return False
