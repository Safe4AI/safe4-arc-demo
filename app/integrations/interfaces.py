from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ProviderRequestContext:
    provider_name: str
    environment: str
    timeout_seconds: float


class ExternalProviderClient(Protocol):
    """Common seam for future provider-backed integrations."""

    def get_provider_name(self) -> str:
        ...

    def check_health(self, context: ProviderRequestContext) -> "ProviderHealthStatus":
        ...
