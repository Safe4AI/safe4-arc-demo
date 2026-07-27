from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class ProviderEnvironment(StrEnum):
    SANDBOX = "sandbox"
    PRODUCTION = "production"


class CredentialSourceKind(StrEnum):
    ENV = "env"
    SECRET_REF = "secret_ref"
    INLINE = "inline"


@dataclass(frozen=True)
class ProviderCredentialRef:
    field_name: str
    source_kind: CredentialSourceKind
    source_value: str
    required: bool = True


@dataclass(frozen=True)
class ProviderEndpointConfig:
    base_url: str
    timeout_seconds: float = 5.0
    healthcheck_path: str | None = None


@dataclass(frozen=True)
class ProviderRuntimeConfig:
    provider_slug: str
    environment: ProviderEnvironment
    endpoint: ProviderEndpointConfig
    credential_refs: tuple[ProviderCredentialRef, ...] = field(default_factory=tuple)
    headers: tuple[tuple[str, str], ...] = field(default_factory=tuple)


def build_provider_env_var_name(provider_slug: str, field_name: str) -> str:
    normalized_provider = provider_slug.strip().upper().replace("-", "_")
    normalized_field = field_name.strip().upper().replace("-", "_")
    return f"SAFE4_PROVIDER_{normalized_provider}_{normalized_field}"


def default_api_key_ref(provider_slug: str, *, field_name: str = "api_key") -> ProviderCredentialRef:
    return ProviderCredentialRef(
        field_name=field_name,
        source_kind=CredentialSourceKind.ENV,
        source_value=build_provider_env_var_name(provider_slug, field_name),
    )
