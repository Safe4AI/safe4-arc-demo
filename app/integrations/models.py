from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderCredentials:
    provider_name: str
    credential_kind: str
    key_id: str | None = None
    secret_ref: str | None = None
