"""
Custom exceptions for the ingestion layer.

Hierarchy:
    WazuhError
    ├── WazuhConnectionError      Cannot reach Wazuh API or Indexer
    ├── WazuhAuthenticationError  Invalid credentials / 401 / 403
    ├── WazuhAPIError             Unexpected API response (5xx, malformed JSON)
    └── WazuhRateLimitError       HTTP 429 — too many requests

    AssetRegistryError            Seed file load / DB upsert failures
"""


class WazuhError(Exception):
    """Base exception for all Wazuh-related errors."""


class WazuhConnectionError(WazuhError):
    """Raised when the HTTP connection to Wazuh API or Indexer fails."""


class WazuhAuthenticationError(WazuhError):
    """Raised on 401 / 403 responses — invalid credentials or permissions."""


class WazuhAPIError(WazuhError):
    """
    Raised for unexpected API error responses.

    Attributes:
        status_code: HTTP status code from the response, or None for parse errors.
    """

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class WazuhRateLimitError(WazuhError):
    """Raised when Wazuh returns HTTP 429 Too Many Requests."""


class AssetRegistryError(Exception):
    """Raised when loading or persisting the asset registry fails."""
