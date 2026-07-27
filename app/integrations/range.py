from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any, Callable, Protocol

from .catalog import ProviderDomain
from .config import ProviderRuntimeConfig
from .errors import ProviderIntegrationError
from .registry import IntegrationAdapterRegistry


@dataclass(frozen=True)
class RangeAddressRiskRequest:
    address: str
    network: str


@dataclass(frozen=True)
class RangeSanctionsRequest:
    address: str
    network: str | None = None
    include_details: bool = True


@dataclass(frozen=True)
class RangeAddressRiskResult:
    provider_slug: str
    risk_score: int | None
    risk_level: str | None
    num_hops: int | None
    malicious_addresses_found: list[dict[str, Any]]
    reasoning: str
    attribution: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RangeSanctionsResult:
    provider_slug: str
    address: str
    network: str | None
    is_token_blacklisted: bool
    is_ofac_sanctioned: bool
    checked_at: str | None
    token_status_summary: list[dict[str, Any]] | None
    blacklist_event_history: list[dict[str, Any]] | None
    ofac_info: dict[str, Any] | None
    attribution: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RangeHttpResponse:
    status_code: int
    payload: Any


class RangeHttpRequester(Protocol):
    def __call__(self, *, url: str, headers: dict[str, str], timeout_seconds: float) -> RangeHttpResponse:
        ...


def _parse_json_response(raw_body: bytes, *, provider_slug: str) -> Any:
    if not raw_body:
        return {}
    try:
        return json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProviderIntegrationError(provider_slug, "RANGE_INVALID_RESPONSE", "provider response was not valid JSON") from exc


def _default_range_requester(*, url: str, headers: dict[str, str], timeout_seconds: float) -> RangeHttpResponse:
    request = urllib.request.Request(url=url, method="GET")
    for header_name, header_value in headers.items():
        request.add_header(header_name, header_value)
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return RangeHttpResponse(status_code=response.status, payload=_parse_json_response(response.read(), provider_slug="range_risk"))
    except urllib.error.HTTPError as exc:
        return RangeHttpResponse(
            status_code=exc.code,
            payload=_parse_json_response(exc.read(), provider_slug="range_risk"),
        )
    except urllib.error.URLError as exc:
        raise ProviderIntegrationError("range_risk", "RANGE_REQUEST_FAILED", f"provider request failed: {exc.reason}") from exc


_range_requester: RangeHttpRequester = _default_range_requester


def set_range_requester_for_tests(requester: RangeHttpRequester) -> None:
    global _range_requester
    _range_requester = requester


def reset_range_requester_for_tests() -> None:
    global _range_requester
    _range_requester = _default_range_requester


class RangeRiskApiAdapter:
    adapter_name = "range_risk_api"
    provider_slug = "range_risk"
    domain = ProviderDomain.CRYPTO_SCREENING.value

    def __init__(self, requester: RangeHttpRequester | None = None) -> None:
        self._requester = requester

    def describe(self) -> dict[str, Any]:
        return {
            "adapter_name": self.adapter_name,
            "provider_slug": self.provider_slug,
            "domain": self.domain,
            "mode": "live_http",
            "supports": ["address_risk", "sanctions_screening"],
            "docs_url": "https://docs.range.org/risk-api/risk-introduction",
        }

    def get_address_risk(
        self,
        request: RangeAddressRiskRequest,
        *,
        config: ProviderRuntimeConfig,
        api_key: str,
    ) -> RangeAddressRiskResult:
        payload = self._execute_get(
            path="/v1/risk/address",
            query={"address": request.address, "network": request.network},
            config=config,
            api_key=api_key,
        )
        return RangeAddressRiskResult(
            provider_slug=self.provider_slug,
            risk_score=payload.get("riskScore"),
            risk_level=payload.get("riskLevel"),
            num_hops=payload.get("numHops"),
            malicious_addresses_found=list(payload.get("maliciousAddressesFound") or []),
            reasoning=str(payload.get("reasoning") or ""),
            attribution=payload.get("attribution"),
        )

    def get_sanctions_check(
        self,
        request: RangeSanctionsRequest,
        *,
        config: ProviderRuntimeConfig,
        api_key: str,
    ) -> RangeSanctionsResult:
        query: dict[str, str] = {"include_details": "true" if request.include_details else "false"}
        if request.network:
            query["network"] = request.network
        payload = self._execute_get(
            path=f"/v1/risk/sanctions/{urllib.parse.quote(request.address, safe='')}",
            query=query,
            config=config,
            api_key=api_key,
        )
        return RangeSanctionsResult(
            provider_slug=self.provider_slug,
            address=str(payload.get("address") or request.address),
            network=payload.get("network"),
            is_token_blacklisted=bool(payload.get("is_token_blacklisted", False)),
            is_ofac_sanctioned=bool(payload.get("is_ofac_sanctioned", False)),
            checked_at=payload.get("checked_at"),
            token_status_summary=payload.get("token_status_summary"),
            blacklist_event_history=payload.get("blacklist_event_history"),
            ofac_info=payload.get("ofac_info"),
            attribution=payload.get("attribution"),
        )

    def _execute_get(
        self,
        *,
        path: str,
        query: dict[str, str],
        config: ProviderRuntimeConfig,
        api_key: str,
    ) -> dict[str, Any]:
        if config.provider_slug != self.provider_slug:
            raise ProviderIntegrationError(self.provider_slug, "CONFIG_PROVIDER_MISMATCH", "provider slug mismatch")
        if not api_key.strip():
            raise ProviderIntegrationError(self.provider_slug, "RANGE_NOT_CONFIGURED", "Range API key is not configured")
        encoded_query = urllib.parse.urlencode(query)
        url = f"{config.endpoint.base_url.rstrip('/')}{path}"
        if encoded_query:
            url = f"{url}?{encoded_query}"
        requester = self._requester or _range_requester
        response = requester(
            url=url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
            },
            timeout_seconds=config.endpoint.timeout_seconds,
        )
        if response.status_code >= 400:
            payload = response.payload if isinstance(response.payload, dict) else {}
            code = str(payload.get("error") or f"HTTP_{response.status_code}").upper()
            message = str(payload.get("message") or payload.get("error") or f"provider returned HTTP {response.status_code}")
            raise ProviderIntegrationError(self.provider_slug, code, message)
        if not isinstance(response.payload, dict):
            raise ProviderIntegrationError(self.provider_slug, "RANGE_INVALID_RESPONSE", "provider response payload must be a JSON object")
        return response.payload


def register_default_range_adapters(registry: IntegrationAdapterRegistry) -> None:
    registry.register(RangeRiskApiAdapter())
