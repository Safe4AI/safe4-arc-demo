from __future__ import annotations


class ProviderIntegrationError(Exception):
    """Normalized provider integration failure."""

    def __init__(self, provider_name: str, code: str, message: str):
        super().__init__(message)
        self.provider_name = provider_name
        self.code = code
        self.message = message
