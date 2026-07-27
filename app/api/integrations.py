from __future__ import annotations

from typing import Any, Callable

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..integrations.errors import ProviderIntegrationError
from ..integrations.range import RangeAddressRiskRequest, RangeRiskApiAdapter, RangeSanctionsRequest


router = APIRouter()

_get_current_identity = None
_ensure_scope: Callable[[Any, list[str]], Any] | None = None
_registry = None
_range_provider_config = None
_get_range_api_key: Callable[[], str | None] | None = None


class RangeAddressRiskRequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    address: str = Field(..., min_length=1)
    network: str = Field(..., min_length=1)

    @field_validator("address", "network")
    @classmethod
    def normalize_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("field cannot be empty")
        return normalized


class RangeSanctionsRequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    address: str = Field(..., min_length=1)
    network: str | None = Field(default=None)
    include_details: bool = Field(default=True)

    @field_validator("address", "network")
    @classmethod
    def normalize_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("field cannot be empty")
        return normalized


def setup_integrations_api(
    *,
    get_current_identity: Callable[..., Any],
    ensure_scope: Callable[[Any, list[str]], Any],
    registry: Any,
    range_provider_config: Any,
    get_range_api_key: Callable[[], str | None],
) -> None:
    global _get_current_identity, _ensure_scope, _registry, _range_provider_config, _get_range_api_key
    _get_current_identity = get_current_identity
    _ensure_scope = ensure_scope
    _registry = registry
    _range_provider_config = range_provider_config
    _get_range_api_key = get_range_api_key


def _require_admin_identity(authorization: str | None) -> Any:
    if _get_current_identity is None or _ensure_scope is None:
        raise RuntimeError("Integrations API not configured")
    identity = _get_current_identity(authorization)
    return _ensure_scope(identity, ["admin:all"])


def _get_range_adapter() -> RangeRiskApiAdapter:
    if _registry is None:
        raise RuntimeError("Integrations API not configured")
    adapter = _registry.get("range_risk_api")
    if not isinstance(adapter, RangeRiskApiAdapter):
        raise RuntimeError("Range adapter not configured")
    return adapter


def _raise_provider_http_error(exc: ProviderIntegrationError) -> None:
    status_code = 503 if exc.code == "RANGE_NOT_CONFIGURED" else 502
    raise HTTPException(
        status_code=status_code,
        detail={
            "error": exc.code,
            "message": exc.message,
            "provider_name": exc.provider_name,
        },
    ) from exc


@router.get("/integrations/providers")
def list_integration_providers(
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    _require_admin_identity(authorization)
    if _registry is None:
        raise RuntimeError("Integrations API not configured")
    return {"providers": _registry.describe_all()}


@router.post("/integrations/range/address-risk")
def get_range_address_risk(
    payload: RangeAddressRiskRequestModel,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    _require_admin_identity(authorization)
    adapter = _get_range_adapter()
    api_key = None if _get_range_api_key is None else _get_range_api_key()
    try:
        result = adapter.get_address_risk(
            RangeAddressRiskRequest(address=payload.address, network=payload.network),
            config=_range_provider_config,
            api_key=api_key or "",
        )
    except ProviderIntegrationError as exc:
        _raise_provider_http_error(exc)
    return {
        "provider_slug": adapter.provider_slug,
        "adapter_name": adapter.adapter_name,
        "result": result.to_dict(),
    }


@router.post("/integrations/range/sanctions")
def get_range_sanctions_check(
    payload: RangeSanctionsRequestModel,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    _require_admin_identity(authorization)
    adapter = _get_range_adapter()
    api_key = None if _get_range_api_key is None else _get_range_api_key()
    try:
        result = adapter.get_sanctions_check(
            RangeSanctionsRequest(
                address=payload.address,
                network=payload.network,
                include_details=payload.include_details,
            ),
            config=_range_provider_config,
            api_key=api_key or "",
        )
    except ProviderIntegrationError as exc:
        _raise_provider_http_error(exc)
    return {
        "provider_slug": adapter.provider_slug,
        "adapter_name": adapter.adapter_name,
        "result": result.to_dict(),
    }
