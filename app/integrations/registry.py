from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


class IntegrationAdapter(Protocol):
    adapter_name: str
    provider_slug: str
    domain: str

    def describe(self) -> dict[str, Any]:
        ...


@dataclass
class IntegrationAdapterRegistry:
    _adapters: dict[str, IntegrationAdapter]

    def __init__(self) -> None:
        self._adapters = {}

    def register(self, adapter: IntegrationAdapter) -> None:
        self._adapters[adapter.adapter_name] = adapter

    def get(self, adapter_name: str) -> IntegrationAdapter | None:
        return self._adapters.get(adapter_name)

    def describe_all(self) -> list[dict[str, Any]]:
        return [adapter.describe() for adapter in self._adapters.values()]
