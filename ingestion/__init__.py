"""
Ingestion module — Wazuh data ingestion layer.

Public interface:
    WazuhClient       Low-level + facade HTTP client
    AlertFetcher      Fetch + classify Wazuh alerts per agent
    SCAFetcher        Fetch SCA scan results per agent
    AssetRegistry     CMDB management (seed, list, sync)
    AlertCounts       DTO returned by AlertFetcher
    SCAResult         DTO returned by SCAFetcher
    WazuhAgent        DTO for a Wazuh agent
    SCASummary        DTO for a raw SCA policy result
"""

from importlib import import_module
from typing import Any

__all__ = [
    # Clients
    "WazuhClient",
    "AlertFetcher",
    "SCAFetcher",
    "AssetRegistry",
    # DTOs
    "AlertCounts",
    "SCAResult",
    "WazuhAgent",
    "SCASummary",
    # Exceptions
    "WazuhError",
    "WazuhConnectionError",
    "WazuhAuthenticationError",
    "WazuhAPIError",
    "WazuhRateLimitError",
    "AssetRegistryError",
]


_SYMBOL_TO_MODULE = {
    # Clients
    "WazuhClient": "ingestion.wazuh_client",
    "AlertFetcher": "ingestion.alert_fetcher",
    "SCAFetcher": "ingestion.sca_fetcher",
    "AssetRegistry": "ingestion.asset_registry",
    # DTOs
    "AlertCounts": "ingestion.alert_fetcher",
    "SCAResult": "ingestion.sca_fetcher",
    "WazuhAgent": "ingestion.wazuh_client",
    "SCASummary": "ingestion.wazuh_client",
    # Exceptions
    "WazuhError": "ingestion.exceptions",
    "WazuhConnectionError": "ingestion.exceptions",
    "WazuhAuthenticationError": "ingestion.exceptions",
    "WazuhAPIError": "ingestion.exceptions",
    "WazuhRateLimitError": "ingestion.exceptions",
    "AssetRegistryError": "ingestion.exceptions",
}


def __getattr__(name: str) -> Any:
    """Lazy-load public symbols to avoid import side effects on `python -m ...`."""
    module_name = _SYMBOL_TO_MODULE.get(name)
    if module_name is None:
        raise AttributeError(f"module 'ingestion' has no attribute '{name}'")

    module = import_module(module_name)
    value = getattr(module, name)
    globals()[name] = value
    return value
