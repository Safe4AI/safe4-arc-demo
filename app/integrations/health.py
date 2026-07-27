from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderHealthStatus:
    provider_name: str
    healthy: bool
    detail: str = ""
