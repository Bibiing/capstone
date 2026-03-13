"""
Application configuration module.

Usage:
    from config.settings import get_settings
    settings = get_settings()
"""

from config.settings import Settings, get_settings

__all__ = ["Settings", "get_settings"]
