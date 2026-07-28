"""Agentic Payments Firewall MVP."""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit
import urllib.request
from uuid import uuid4

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .anomaly_api import anomaly_severity_is_stricter
from .ap2_api import AP2MandateReference
from .ap2_api import enforce_ap2_policy, router as ap2_router, setup_ap2_api
from .audit_api import router as audit_router
from .audit_api import setup_audit_api
from .api.integrations import router as integrations_router
from .api.integrations import setup_integrations_api
from .api.demo import router as demo_router, setup_demo_api
from .auth import (
    AgentIdentity,
    audit_infrastructure_identity_fields,
    assess_infrastructure_identity_posture,
    ensure_scope,
    get_current_identity,
    hash_token,
    issue_secret_token,
    list_infrastructure_identity_verifiers,
    normalize_scope_string,
    require_scopes,
    require_trusted_infrastructure_identity_for_admin,
    setup_auth,
    verify_pkce,
)
from .budgets_api import router as budgets_router
from .budgets_api import setup_budgets_api
from .hitl_api import router as hitl_router
from .hitl_api import setup_hitl_api
from .hitl_policy import enforce_direct_hitl_policy, setup_hitl_policy
from .mcp_api import router as mcp_router
from .mcp_api import setup_mcp_api
from .mcp_models import (
    ALLOWED_MCP_TOOL_ACTIONS,
)
from .ops_api import router as ops_router
from .ops_api import setup_ops_api
from .oauth_api import router as oauth_router
from .oauth_api import setup_oauth_api, compute_code_challenge
from .mcp_payment_policy import enforce_mcp_payment_policy, setup_mcp_payment_policy
from .phase3_api import router as phase3_router
from .phase3_api import setup_phase3_api
from .policy_api import router as policy_router
from .policy_api import setup_policy_api
from .payment_finalize import finalize_authorized_payment, setup_payment_finalize
from .payment_entry_checks import (
    check_payment_idempotency,
    setup_payment_entry_checks,
    validate_payment_receipt,
)
from .payment_flow import (
    deny_payment,
    payment_required_response,
    payment_request_summary,
    receipt_expired,
    setup_payment_flow,
)
from .receipts_api import router as receipts_router
from .receipts_api import setup_receipts_api
from .storage import FirewallStore, compute_audit_entry_hash, decimal_to_text
from .webhooks_api import dispatcher as webhook_dispatcher
from .webhooks_api import router as webhooks_router
from .webhooks_api import setup_webhooks_api
from .x402_api import (
    build_provider_receipt_token,
    build_x402_challenge,
    router as x402_router,
    setup_x402_api,
    verify_x402_receipt,
)
from .integrations.config import (
    ProviderEndpointConfig,
    ProviderEnvironment,
    ProviderRuntimeConfig,
    build_provider_env_var_name,
    default_api_key_ref,
)
from .integrations.kyc import register_default_kyc_sandbox_adapters
from .integrations.range import register_default_range_adapters
from .integrations.registry import IntegrationAdapterRegistry
from .core.config import (
    env_decimal as _env_decimal,
    env_positive_int as _env_positive_int,
    normalize_money,
    parse_ap2_signer_keys,
    parse_budget_alert_thresholds,
    parse_budget_alert_threshold_values,
    parse_decimal_input,
    parse_x402_network_recipient_addresses,
    parse_x402_provider_keys,
)
from .core.intent import IntentDecision, evaluate_payment_intent


MONEY_SCALE = Decimal("0.000001")
MAX_AMOUNT = Decimal("1000000")
MAX_BODY_BYTES = 64 * 1024
POLICY_VERSION = "mvp-0.4.0"
UUID4_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
TAG_PATTERN = re.compile(r"<[^>]+>")
SCRIPT_PATTERN = re.compile(r"<script.*?>.*?</script>", re.IGNORECASE | re.DOTALL)
ALLOWED_CURRENCIES = {"USD", "EUR", "GBP", "USDC"}
ALLOWED_SCOPES = {"payment:read", "payment:authorize", "budget:manage", "audit:read", "admin:all"}


def _env_positive_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        parsed = float(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a positive number") from exc
    if parsed <= 0:
        raise RuntimeError(f"{name} must be a positive number")
    return parsed

def _parse_optional_jwks_timestamp(
    value: Any,
    *,
    env_name: str,
    field_name: str,
    key_id: str,
) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise RuntimeError(f"{env_name} key {key_id} field {field_name} must be an ISO-8601 timestamp string")
    candidate = value.strip()
    if not candidate:
        raise RuntimeError(f"{env_name} key {key_id} field {field_name} cannot be empty")
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError(f"{env_name} key {key_id} field {field_name} must be a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def _parse_optional_jwks_metadata_text(
    value: Any,
    *,
    env_name: str,
    field_name: str,
    key_id: str,
) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise RuntimeError(f"{env_name} key {key_id} field {field_name} must be a string")
    candidate = value.strip()
    if not candidate:
        raise RuntimeError(f"{env_name} key {key_id} field {field_name} cannot be empty")
    return candidate


def _parse_optional_jwks_metadata_url(
    value: Any,
    *,
    env_name: str,
    field_name: str,
    key_id: str,
) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise RuntimeError(f"{env_name} key {key_id} field {field_name} must be a URL string")
    candidate = value.strip()
    if not candidate:
        raise RuntimeError(f"{env_name} key {key_id} field {field_name} cannot be empty")
    try:
        parsed = urlsplit(candidate)
    except ValueError as exc:
        raise RuntimeError(f"{env_name} key {key_id} field {field_name} must be a valid absolute URL") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise RuntimeError(f"{env_name} key {key_id} field {field_name} must be an absolute http(s) URL")
    if parsed.fragment:
        raise RuntimeError(f"{env_name} key {key_id} field {field_name} cannot include a fragment")
    normalized_path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), normalized_path, parsed.query, ""))


def parse_ap2_signer_jwks(raw: str) -> dict[str, dict[str, Any]]:
    env_name = "PAYMENT_FIREWALL_AP2_SIGNER_JWKS"
    keys = _parse_rs256_jwks(raw, env_name=env_name)
    document = json.loads(raw)
    keys_value = document.get("keys")
    for item in keys_value:
        key_id = str(item.get("kid") or "default").strip() or "default"
        signer_ids_raw = item.get("ap2_signer_ids")
        signer_ids: list[str] = []
        if signer_ids_raw is not None:
            if not isinstance(signer_ids_raw, list) or not signer_ids_raw:
                raise RuntimeError(f"{env_name} key {key_id} ap2_signer_ids must be a non-empty array when provided")
            for signer_id in signer_ids_raw:
                if not isinstance(signer_id, str) or not signer_id.strip():
                    raise RuntimeError(f"{env_name} key {key_id} ap2_signer_ids entries must be non-empty strings")
                signer_ids.append(signer_id.strip())

        status = str(item.get("status") or "active").strip().lower()
        if status not in {"active", "retired", "disabled"}:
            raise RuntimeError(f"{env_name} key {key_id} status must be active, retired, or disabled")
        not_before = _parse_optional_jwks_timestamp(
            item.get("not_before"),
            env_name=env_name,
            field_name="not_before",
            key_id=key_id,
        )
        not_after = _parse_optional_jwks_timestamp(
            item.get("not_after"),
            env_name=env_name,
            field_name="not_after",
            key_id=key_id,
        )
        trust_anchor_id = _parse_optional_jwks_metadata_text(
            item.get("trust_anchor_id"),
            env_name=env_name,
            field_name="trust_anchor_id",
            key_id=key_id,
        )
        issuer_url = _parse_optional_jwks_metadata_url(
            item.get("issuer_url"),
            env_name=env_name,
            field_name="issuer_url",
            key_id=key_id,
        )
        discovery_url = _parse_optional_jwks_metadata_url(
            item.get("discovery_url"),
            env_name=env_name,
            field_name="discovery_url",
            key_id=key_id,
        )
        if discovery_url and issuer_url is None:
            raise RuntimeError(f"{env_name} key {key_id} discovery_url requires issuer_url")
        if discovery_url:
            issuer_parts = urlsplit(issuer_url)
            discovery_parts = urlsplit(discovery_url)
            if (
                issuer_parts.scheme.lower(),
                issuer_parts.netloc.lower(),
            ) != (
                discovery_parts.scheme.lower(),
                discovery_parts.netloc.lower(),
            ):
                raise RuntimeError(f"{env_name} key {key_id} discovery_url must share the issuer_url origin")
            if not discovery_parts.path.startswith("/.well-known/"):
                raise RuntimeError(f"{env_name} key {key_id} discovery_url must use a .well-known path")
        if not_before and not_after and datetime.fromisoformat(not_before) >= datetime.fromisoformat(not_after):
            raise RuntimeError(f"{env_name} key {key_id} not_before must be earlier than not_after")
        keys[key_id].update(
            {
                "status": status,
                "ap2_signer_ids": signer_ids,
                "not_before": not_before,
                "not_after": not_after,
                "trust_anchor_id": trust_anchor_id,
                "issuer_url": issuer_url,
                "discovery_url": discovery_url,
            }
        )
    return keys


def parse_ap2_trust_anchors(raw: str) -> dict[str, dict[str, Any]]:
    env_name = "PAYMENT_FIREWALL_AP2_TRUST_ANCHORS"
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{env_name} must be valid JSON") from exc
    if not isinstance(document, dict):
        raise RuntimeError(f"{env_name} must be a JSON object")
    anchors_value = document.get("trust_anchors")
    if not isinstance(anchors_value, list):
        raise RuntimeError(f"{env_name} must contain a trust_anchors array")

    anchors: dict[str, dict[str, Any]] = {}
    for item in anchors_value:
        if not isinstance(item, dict):
            raise RuntimeError(f"{env_name} trust_anchors entries must be JSON objects")
        trust_anchor_id_raw = item.get("trust_anchor_id")
        if not isinstance(trust_anchor_id_raw, str) or not trust_anchor_id_raw.strip():
            raise RuntimeError(f"{env_name} trust_anchors entries must include trust_anchor_id")
        trust_anchor_id = trust_anchor_id_raw.strip()
        status = str(item.get("status") or "active").strip().lower()
        if status not in {"active", "retired", "disabled"}:
            raise RuntimeError(f"{env_name} trust anchor {trust_anchor_id} status must be active, retired, or disabled")
        issuer_url = _parse_optional_jwks_metadata_url(
            item.get("issuer_url"),
            env_name=env_name,
            field_name="issuer_url",
            key_id=trust_anchor_id,
        )
        discovery_url = _parse_optional_jwks_metadata_url(
            item.get("discovery_url"),
            env_name=env_name,
            field_name="discovery_url",
            key_id=trust_anchor_id,
        )
        if issuer_url is None or discovery_url is None:
            raise RuntimeError(
                f"{env_name} trust anchor {trust_anchor_id} must include issuer_url and discovery_url"
            )
        issuer_parts = urlsplit(issuer_url)
        discovery_parts = urlsplit(discovery_url)
        if (
            issuer_parts.scheme.lower(),
            issuer_parts.netloc.lower(),
        ) != (
            discovery_parts.scheme.lower(),
            discovery_parts.netloc.lower(),
        ):
            raise RuntimeError(
                f"{env_name} trust anchor {trust_anchor_id} discovery_url must share the issuer_url origin"
            )
        if not discovery_parts.path.startswith("/.well-known/"):
            raise RuntimeError(
                f"{env_name} trust anchor {trust_anchor_id} discovery_url must use a .well-known path"
            )

        signer_ids_raw = item.get("ap2_signer_ids")
        signer_ids: list[str] = []
        if signer_ids_raw is not None:
            if not isinstance(signer_ids_raw, list) or not signer_ids_raw:
                raise RuntimeError(
                    f"{env_name} trust anchor {trust_anchor_id} ap2_signer_ids must be a non-empty array when provided"
                )
            for signer_id in signer_ids_raw:
                if not isinstance(signer_id, str) or not signer_id.strip():
                    raise RuntimeError(
                        f"{env_name} trust anchor {trust_anchor_id} ap2_signer_ids entries must be non-empty strings"
                    )
                signer_ids.append(signer_id.strip())
        anchors[trust_anchor_id] = {
            "trust_anchor_id": trust_anchor_id,
            "status": status,
            "issuer_url": issuer_url,
            "discovery_url": discovery_url,
            "ap2_signer_ids": signer_ids,
        }
    return anchors


def parse_ap2_federation_discovery(raw: str) -> dict[str, dict[str, Any]]:
    env_name = "PAYMENT_FIREWALL_AP2_FEDERATION_DISCOVERY"
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{env_name} must be valid JSON") from exc
    if not isinstance(document, dict):
        raise RuntimeError(f"{env_name} must be a JSON object")
    documents_value = document.get("documents")
    if not isinstance(documents_value, list):
        raise RuntimeError(f"{env_name} must contain a documents array")

    discovery_documents: dict[str, dict[str, Any]] = {}
    for item in documents_value:
        if not isinstance(item, dict):
            raise RuntimeError(f"{env_name} documents entries must be JSON objects")
        discovery_url = _parse_optional_jwks_metadata_url(
            item.get("discovery_url"),
            env_name=env_name,
            field_name="discovery_url",
            key_id="document",
        )
        issuer_url = _parse_optional_jwks_metadata_url(
            item.get("issuer_url"),
            env_name=env_name,
            field_name="issuer_url",
            key_id=discovery_url or "document",
        )
        jwks_uri = _parse_optional_jwks_metadata_url(
            item.get("jwks_uri"),
            env_name=env_name,
            field_name="jwks_uri",
            key_id=discovery_url or "document",
        )
        refreshed_at = _parse_optional_jwks_timestamp(
            item.get("refreshed_at"),
            env_name=env_name,
            field_name="refreshed_at",
            key_id=discovery_url or "document",
        )
        if issuer_url is None or discovery_url is None or jwks_uri is None or refreshed_at is None:
            raise RuntimeError(
                f"{env_name} documents entries must include issuer_url, discovery_url, jwks_uri, and refreshed_at"
            )
        issuer_parts = urlsplit(issuer_url)
        discovery_parts = urlsplit(discovery_url)
        if (
            issuer_parts.scheme.lower(),
            issuer_parts.netloc.lower(),
        ) != (
            discovery_parts.scheme.lower(),
            discovery_parts.netloc.lower(),
        ):
            raise RuntimeError(
                f"{env_name} discovery document {discovery_url} must share the issuer_url origin"
            )
        if not discovery_parts.path.startswith("/.well-known/"):
            raise RuntimeError(
                f"{env_name} discovery document {discovery_url} must use a .well-known path"
            )

        status = str(item.get("status") or "active").strip().lower()
        if status not in {"active", "retired", "disabled"}:
            raise RuntimeError(
                f"{env_name} discovery document {discovery_url} status must be active, retired, or disabled"
            )
        trust_anchor_id = _parse_optional_jwks_metadata_text(
            item.get("trust_anchor_id"),
            env_name=env_name,
            field_name="trust_anchor_id",
            key_id=discovery_url,
        )
        keys_value = item.get("keys")
        if not isinstance(keys_value, list) or not keys_value:
            raise RuntimeError(f"{env_name} discovery document {discovery_url} must contain a non-empty keys array")
        resolved_keys = _parse_rs256_jwks(
            json.dumps({"keys": keys_value}, separators=(",", ":")),
            env_name=f"{env_name} discovery document {discovery_url}",
        )
        discovery_documents[discovery_url] = {
            "issuer_url": issuer_url,
            "discovery_url": discovery_url,
            "jwks_uri": jwks_uri,
            "refreshed_at": refreshed_at,
            "status": status,
            "trust_anchor_id": trust_anchor_id,
            "keys": resolved_keys,
        }
    return discovery_documents


def parse_optional_runtime_url(raw: str | None, *, env_name: str) -> str | None:
    if raw is None:
        return None
    candidate = raw.strip()
    if not candidate:
        return None
    return _parse_optional_jwks_metadata_url(
        candidate,
        env_name=env_name,
        field_name="url",
        key_id="runtime",
    )


def _fetch_ap2_federation_discovery_document(url: str, timeout_seconds: int) -> str:
    request = urllib.request.Request(url=url, headers={"Accept": "application/json"}, method="GET")
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        charset = response.headers.get_content_charset("utf-8") or "utf-8"
        return response.read().decode(charset)


class AP2FederationDiscoveryCache:
    def __init__(
        self,
        *,
        seed_documents: dict[str, dict[str, Any]],
        poll_url: str | None = None,
        poll_interval_seconds: int = 300,
        cache_max_age_seconds: int = 900,
        timeout_seconds: int = 5,
        fetcher: Any | None = None,
        now_utc: Any | None = None,
        monotonic: Any | None = None,
    ) -> None:
        if poll_interval_seconds < 1:
            raise ValueError("poll_interval_seconds must be at least 1")
        if cache_max_age_seconds < poll_interval_seconds:
            raise ValueError("cache_max_age_seconds must be greater than or equal to poll_interval_seconds")
        if timeout_seconds < 1:
            raise ValueError("timeout_seconds must be at least 1")
        self._seed_documents = copy.deepcopy(seed_documents)
        self._poll_url = poll_url
        self._poll_interval_seconds = poll_interval_seconds
        self._cache_max_age_seconds = cache_max_age_seconds
        self._timeout_seconds = timeout_seconds
        self._fetcher = fetcher or _fetch_ap2_federation_discovery_document
        self._now_utc = now_utc or (lambda: datetime.now(timezone.utc))
        self._monotonic = monotonic or time.monotonic
        self._lock = threading.Lock()
        self._documents: dict[str, dict[str, Any]] = {}
        self._next_poll_at: float | None = None
        self.reset()

    def _decorate_documents(
        self,
        documents: dict[str, dict[str, Any]],
        *,
        fetched_at: datetime,
    ) -> dict[str, dict[str, Any]]:
        resolved = copy.deepcopy(documents)
        if self._poll_url is None:
            return resolved
        cache_refreshed_at = fetched_at.isoformat()
        cache_expires_at = (fetched_at + timedelta(seconds=self._cache_max_age_seconds)).isoformat()
        for document in resolved.values():
            document["cache_refreshed_at"] = cache_refreshed_at
            document["cache_expires_at"] = cache_expires_at
        return resolved

    def _refresh_locked(self, now_monotonic: float) -> None:
        if self._poll_url is None:
            self._next_poll_at = None
            return
        raw_document = self._fetcher(self._poll_url, self._timeout_seconds)
        documents = parse_ap2_federation_discovery(raw_document)
        self._documents = self._decorate_documents(documents, fetched_at=self._now_utc())
        self._next_poll_at = now_monotonic + self._poll_interval_seconds

    def current_documents(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            now_monotonic = self._monotonic()
            if self._poll_url is not None and (self._next_poll_at is None or now_monotonic >= self._next_poll_at):
                try:
                    self._refresh_locked(now_monotonic)
                except Exception:
                    self._next_poll_at = now_monotonic + self._poll_interval_seconds
            return copy.deepcopy(self._documents)

    def reset(self) -> None:
        with self._lock:
            self._documents = self._decorate_documents(self._seed_documents, fetched_at=self._now_utc())
            self._next_poll_at = self._monotonic() if self._poll_url is not None else None


def parse_infrastructure_identity_jwt_keys(raw: str) -> dict[str, str]:
    keys: dict[str, str] = {}
    for item in raw.split(","):
        candidate = item.strip()
        if not candidate:
            continue
        if ":" not in candidate:
            raise RuntimeError("PAYMENT_FIREWALL_INFRA_K8S_JWT_KEYS entries must use key_id:secret format")
        key_id, secret = candidate.split(":", 1)
        key_id = key_id.strip()
        secret = secret.strip()
        if not key_id or not secret:
            raise RuntimeError("PAYMENT_FIREWALL_INFRA_K8S_JWT_KEYS entries must include both key_id and secret")
        keys[key_id] = secret
    if not keys:
        return {"default": "dev-k8s-service-account-jwt-secret"}
    return keys


def _base64url_to_int(value: str, *, env_name: str) -> int:
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.urlsafe_b64decode((value + padding).encode("utf-8"))
    except Exception as exc:  # pragma: no cover - defensive parse guard
        raise RuntimeError(f"{env_name} must contain base64url-encoded RSA key parameters") from exc
    if not decoded:
        raise RuntimeError(f"{env_name} must contain non-empty RSA key parameters")
    return int.from_bytes(decoded, "big")


def _parse_rs256_jwks(raw: str, *, env_name: str) -> dict[str, dict[str, Any]]:
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{env_name} must be valid JSON") from exc
    if not isinstance(document, dict):
        raise RuntimeError(f"{env_name} must be a JSON object")
    keys_value = document.get("keys")
    if not isinstance(keys_value, list) or not keys_value:
        raise RuntimeError(f"{env_name} must contain a non-empty keys array")

    keys: dict[str, dict[str, Any]] = {}
    for item in keys_value:
        if not isinstance(item, dict):
            raise RuntimeError(f"{env_name} keys entries must be JSON objects")
        key_type = str(item.get("kty") or "").strip().upper()
        algorithm = str(item.get("alg") or "RS256").strip().upper()
        key_use = str(item.get("use") or "sig").strip().lower()
        key_id = str(item.get("kid") or "default").strip() or "default"
        modulus = str(item.get("n") or "").strip()
        exponent = str(item.get("e") or "").strip()
        if key_type != "RSA":
            raise RuntimeError(f"{env_name} only supports RSA keys")
        if algorithm != "RS256":
            raise RuntimeError(f"{env_name} only supports RS256 keys")
        if key_use not in {"", "sig"}:
            raise RuntimeError(f"{env_name} only supports signature keys")
        if not modulus or not exponent:
            raise RuntimeError(f"{env_name} keys must include n and e")
        keys[key_id] = {
            "kid": key_id,
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "modulus": _base64url_to_int(modulus, env_name=env_name),
            "exponent": _base64url_to_int(exponent, env_name=env_name),
        }
    return keys


def parse_infrastructure_identity_oidc_jwks(raw: str) -> dict[str, dict[str, Any]]:
    return _parse_rs256_jwks(raw, env_name="PAYMENT_FIREWALL_INFRA_OIDC_JWKS")


def parse_x402_provider_jwks(raw: str) -> dict[str, dict[str, Any]]:
    env_name = "PAYMENT_FIREWALL_X402_PROVIDER_JWKS"
    keys = _parse_rs256_jwks(raw, env_name=env_name)
    document = json.loads(raw)
    keys_value = document.get("keys")
    for item in keys_value:
        key_id = str(item.get("kid") or "default").strip() or "default"
        status = str(item.get("status") or "active").strip().lower()
        if status not in {"active", "retired", "disabled"}:
            raise RuntimeError(f"{env_name} key {key_id} status must be active, retired, or disabled")
        not_before = _parse_optional_jwks_timestamp(
            item.get("not_before"),
            env_name=env_name,
            field_name="not_before",
            key_id=key_id,
        )
        not_after = _parse_optional_jwks_timestamp(
            item.get("not_after"),
            env_name=env_name,
            field_name="not_after",
            key_id=key_id,
        )
        provider_names_raw = item.get("provider_names")
        provider_names: list[str] = []
        if provider_names_raw is not None:
            if not isinstance(provider_names_raw, list) or not provider_names_raw:
                raise RuntimeError(f"{env_name} key {key_id} provider_names must be a non-empty array when provided")
            for provider_name in provider_names_raw:
                if not isinstance(provider_name, str) or not provider_name.strip():
                    raise RuntimeError(f"{env_name} key {key_id} provider_names entries must be non-empty strings")
                provider_names.append(provider_name.strip())
        issuer_url = _parse_optional_jwks_metadata_url(
            item.get("issuer_url"),
            env_name=env_name,
            field_name="issuer_url",
            key_id=key_id,
        )
        discovery_url = _parse_optional_jwks_metadata_url(
            item.get("discovery_url"),
            env_name=env_name,
            field_name="discovery_url",
            key_id=key_id,
        )
        trust_anchor_id = _parse_optional_jwks_metadata_text(
            item.get("trust_anchor_id"),
            env_name=env_name,
            field_name="trust_anchor_id",
            key_id=key_id,
        )
        if discovery_url and issuer_url is None:
            raise RuntimeError(f"{env_name} key {key_id} discovery_url requires issuer_url")
        if discovery_url:
            issuer_parts = urlsplit(issuer_url)
            discovery_parts = urlsplit(discovery_url)
            if (
                issuer_parts.scheme.lower(),
                issuer_parts.netloc.lower(),
            ) != (
                discovery_parts.scheme.lower(),
                discovery_parts.netloc.lower(),
            ):
                raise RuntimeError(f"{env_name} key {key_id} discovery_url must share the issuer_url origin")
            if not discovery_parts.path.startswith("/.well-known/"):
                raise RuntimeError(f"{env_name} key {key_id} discovery_url must use a .well-known path")
        if not_before and not_after and datetime.fromisoformat(not_before) >= datetime.fromisoformat(not_after):
            raise RuntimeError(f"{env_name} key {key_id} not_before must be earlier than not_after")
        keys[key_id].update(
            {
                "status": status,
                "not_before": not_before,
                "not_after": not_after,
                "provider_names": provider_names,
                "issuer_url": issuer_url,
                "discovery_url": discovery_url,
                "trust_anchor_id": trust_anchor_id,
            }
        )
    return keys


def parse_x402_provider_trust_anchors(raw: str) -> dict[str, dict[str, Any]]:
    env_name = "PAYMENT_FIREWALL_X402_PROVIDER_TRUST_ANCHORS"
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{env_name} must be valid JSON") from exc
    if not isinstance(document, dict):
        raise RuntimeError(f"{env_name} must be a JSON object")
    anchors_value = document.get("trust_anchors")
    if not isinstance(anchors_value, list):
        raise RuntimeError(f"{env_name} must contain a trust_anchors array")

    anchors: dict[str, dict[str, Any]] = {}
    for item in anchors_value:
        if not isinstance(item, dict):
            raise RuntimeError(f"{env_name} trust_anchors entries must be JSON objects")
        trust_anchor_id_raw = item.get("trust_anchor_id")
        if not isinstance(trust_anchor_id_raw, str) or not trust_anchor_id_raw.strip():
            raise RuntimeError(f"{env_name} trust_anchors entries must include trust_anchor_id")
        trust_anchor_id = trust_anchor_id_raw.strip()
        status = str(item.get("status") or "active").strip().lower()
        if status not in {"active", "retired", "disabled"}:
            raise RuntimeError(f"{env_name} trust anchor {trust_anchor_id} status must be active, retired, or disabled")
        issuer_url = _parse_optional_jwks_metadata_url(
            item.get("issuer_url"),
            env_name=env_name,
            field_name="issuer_url",
            key_id=trust_anchor_id,
        )
        discovery_url = _parse_optional_jwks_metadata_url(
            item.get("discovery_url"),
            env_name=env_name,
            field_name="discovery_url",
            key_id=trust_anchor_id,
        )
        if issuer_url is None or discovery_url is None:
            raise RuntimeError(f"{env_name} trust anchor {trust_anchor_id} must include issuer_url and discovery_url")
        provider_names_raw = item.get("provider_names")
        provider_names: list[str] = []
        if provider_names_raw is not None:
            if not isinstance(provider_names_raw, list) or not provider_names_raw:
                raise RuntimeError(f"{env_name} trust anchor {trust_anchor_id} provider_names must be a non-empty array when provided")
            for provider_name in provider_names_raw:
                if not isinstance(provider_name, str) or not provider_name.strip():
                    raise RuntimeError(f"{env_name} trust anchor {trust_anchor_id} provider_names entries must be non-empty strings")
                provider_names.append(provider_name.strip())
        anchors[trust_anchor_id] = {
            "trust_anchor_id": trust_anchor_id,
            "status": status,
            "issuer_url": issuer_url,
            "discovery_url": discovery_url,
            "provider_names": provider_names,
        }
    return anchors


def parse_x402_provider_discovery(raw: str) -> dict[str, dict[str, Any]]:
    env_name = "PAYMENT_FIREWALL_X402_PROVIDER_DISCOVERY"
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{env_name} must be valid JSON") from exc
    if not isinstance(document, dict):
        raise RuntimeError(f"{env_name} must be a JSON object")
    documents_value = document.get("documents")
    if not isinstance(documents_value, list):
        raise RuntimeError(f"{env_name} must contain a documents array")

    discovery_documents: dict[str, dict[str, Any]] = {}
    for item in documents_value:
        if not isinstance(item, dict):
            raise RuntimeError(f"{env_name} documents entries must be JSON objects")
        provider_name_raw = item.get("provider_name")
        if not isinstance(provider_name_raw, str) or not provider_name_raw.strip():
            raise RuntimeError(f"{env_name} documents entries must include provider_name")
        provider_name = provider_name_raw.strip()
        issuer_url = _parse_optional_jwks_metadata_url(
            item.get("issuer_url"),
            env_name=env_name,
            field_name="issuer_url",
            key_id=provider_name,
        )
        discovery_url = _parse_optional_jwks_metadata_url(
            item.get("discovery_url"),
            env_name=env_name,
            field_name="discovery_url",
            key_id=provider_name,
        )
        if discovery_url and issuer_url is None:
            raise RuntimeError(f"{env_name} provider {provider_name} discovery_url requires issuer_url")
        if discovery_url:
            issuer_parts = urlsplit(issuer_url)
            discovery_parts = urlsplit(discovery_url)
            if (
                issuer_parts.scheme.lower(),
                issuer_parts.netloc.lower(),
            ) != (
                discovery_parts.scheme.lower(),
                discovery_parts.netloc.lower(),
            ):
                raise RuntimeError(f"{env_name} provider {provider_name} discovery_url must share the issuer_url origin")
            if not discovery_parts.path.startswith("/.well-known/"):
                raise RuntimeError(f"{env_name} provider {provider_name} discovery_url must use a .well-known path")
        jwks_key_ids_raw = item.get("jwks_key_ids")
        jwks_key_ids: list[str] = []
        if jwks_key_ids_raw is not None:
            if not isinstance(jwks_key_ids_raw, list) or not jwks_key_ids_raw:
                raise RuntimeError(f"{env_name} provider {provider_name} jwks_key_ids must be a non-empty array when provided")
            for key_id in jwks_key_ids_raw:
                if not isinstance(key_id, str) or not key_id.strip():
                    raise RuntimeError(f"{env_name} provider {provider_name} jwks_key_ids entries must be non-empty strings")
                jwks_key_ids.append(key_id.strip())
        refreshed_at = _parse_optional_jwks_timestamp(
            item.get("refreshed_at"),
            env_name=env_name,
            field_name="refreshed_at",
            key_id=provider_name,
        )
        if refreshed_at is None:
            raise RuntimeError(f"{env_name} provider {provider_name} must include refreshed_at")
        discovery_documents[provider_name] = {
            "provider_name": provider_name,
            "issuer_url": issuer_url,
            "discovery_url": discovery_url,
            "jwks_key_ids": jwks_key_ids,
            "refreshed_at": refreshed_at,
        }
    return discovery_documents


APP_PORT = int(os.getenv("APP_PORT", "8090"))
PORT = int(os.getenv("PORT", str(APP_PORT)))
FEE_RATE = normalize_money(_env_decimal("PAYMENT_FIREWALL_FEE_RATE", "0.0025"))
MIN_DESCRIPTION_WORDS = int(os.getenv("MIN_DESCRIPTION_WORDS", "10"))
PAY_TO_ADDRESS = os.getenv("PAYMENT_FIREWALL_PAY_TO", "").strip()
DEFAULT_RECEIPT_TTL_SECONDS = int(os.getenv("PAYMENT_FIREWALL_RECEIPT_TTL_SECONDS", "300"))
ACCESS_TOKEN_TTL_SECONDS = int(os.getenv("PAYMENT_FIREWALL_ACCESS_TOKEN_TTL_SECONDS", "900"))
REFRESH_TOKEN_TTL_SECONDS = int(os.getenv("PAYMENT_FIREWALL_REFRESH_TOKEN_TTL_SECONDS", "86400"))
AUTH_CODE_TTL_SECONDS = int(os.getenv("PAYMENT_FIREWALL_AUTH_CODE_TTL_SECONDS", "600"))
OAUTH_ISSUER = os.getenv("PAYMENT_FIREWALL_OAUTH_ISSUER", "http://localhost:8090")
HITL_APPROVAL_TTL_SECONDS = int(os.getenv("PAYMENT_FIREWALL_HITL_APPROVAL_TTL_SECONDS", "300"))
SPEND_TOKEN_TTL_SECONDS = int(os.getenv("PAYMENT_FIREWALL_SPEND_TOKEN_TTL_SECONDS", "300"))
RECEIPT_SECRET = os.getenv("PAYMENT_FIREWALL_RECEIPT_SECRET", "dev-insecure-receipt-secret")
RECEIPT_ADMIN_SECRET = os.getenv("PAYMENT_FIREWALL_ADMIN_SECRET", "change-me")
RATE_LIMIT_REQUESTS = int(os.getenv("PAYMENT_FIREWALL_RATE_LIMIT_REQUESTS", "60"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("PAYMENT_FIREWALL_RATE_LIMIT_WINDOW_SECONDS", "60"))
PAYMENT_VELOCITY_LIMIT = int(os.getenv("PAYMENT_FIREWALL_VELOCITY_LIMIT", "3"))
PAYMENT_VELOCITY_WINDOW_SECONDS = int(os.getenv("PAYMENT_FIREWALL_VELOCITY_WINDOW_SECONDS", "60"))
BUDGET_ALERT_THRESHOLDS = parse_budget_alert_thresholds(
    os.getenv("PAYMENT_FIREWALL_BUDGET_ALERT_THRESHOLDS", "0.5,0.8,1.0")
)
MCP_UNKNOWN_SERVER_HITL_THRESHOLD = normalize_money(
    _env_decimal("PAYMENT_FIREWALL_MCP_UNKNOWN_SERVER_HITL_THRESHOLD", "10")
)
WEBHOOK_TIMEOUT_SECONDS = int(os.getenv("PAYMENT_FIREWALL_WEBHOOK_TIMEOUT_SECONDS", "5"))
WEBHOOK_DISPATCH_ENABLED = os.getenv("PAYMENT_FIREWALL_WEBHOOK_DISPATCH_ENABLED", "false").lower() == "true"
WEBHOOK_DISPATCH_INTERVAL_SECONDS = int(os.getenv("PAYMENT_FIREWALL_WEBHOOK_DISPATCH_INTERVAL_SECONDS", "30"))
WEBHOOK_MAX_ATTEMPTS = int(os.getenv("PAYMENT_FIREWALL_WEBHOOK_MAX_ATTEMPTS", "3"))
PHASE3_AP2_ENABLED = os.getenv("PAYMENT_FIREWALL_PHASE3_AP2_ENABLED", "false").lower() == "true"
PHASE3_ADVANCED_X402_ENABLED = os.getenv("PAYMENT_FIREWALL_PHASE3_X402_ADVANCED_ENABLED", "false").lower() == "true"
PHASE3_INFRASTRUCTURE_IDENTITY_ENABLED = (
    os.getenv("PAYMENT_FIREWALL_PHASE3_INFRASTRUCTURE_IDENTITY_ENABLED", "false").lower() == "true"
)
AP2_SHARED_SECRET = os.getenv("PAYMENT_FIREWALL_AP2_SHARED_SECRET", "dev-ap2-shared-secret")
AP2_SIGNER_KEYS = parse_ap2_signer_keys(
    os.getenv(
        "PAYMENT_FIREWALL_AP2_SIGNER_KEYS",
        f"default:{AP2_SHARED_SECRET},merchant_v1:{AP2_SHARED_SECRET}",
    )
)
X402_SUPPORTED_NETWORKS = [
    item.strip()
    for item in os.getenv(
        "PAYMENT_FIREWALL_X402_SUPPORTED_NETWORKS",
        "arc-testnet,base,solana,ethereum-l2",
    ).split(",")
    if item.strip()
]
X402_NETWORK_RECIPIENT_ADDRESSES = parse_x402_network_recipient_addresses(
    os.getenv("PAYMENT_FIREWALL_X402_NETWORK_RECIPIENTS"),
    supported_networks=X402_SUPPORTED_NETWORKS,
    default_pay_to=PAY_TO_ADDRESS,
)
X402_CHALLENGE_TTL_SECONDS = int(os.getenv("PAYMENT_FIREWALL_X402_CHALLENGE_TTL_SECONDS", "300"))
X402_PROVIDER_SHARED_SECRET = os.getenv("PAYMENT_FIREWALL_X402_PROVIDER_SHARED_SECRET", "dev-x402-provider-secret")
X402_PROVIDER_KEYS = parse_x402_provider_keys(
    os.getenv(
        "PAYMENT_FIREWALL_X402_PROVIDER_KEYS",
        f"default:{X402_PROVIDER_SHARED_SECRET},key_v1:{X402_PROVIDER_SHARED_SECRET},key_v2:{X402_PROVIDER_SHARED_SECRET}",
    )
)
INFRA_IDENTITY_SHARED_SECRET = os.getenv(
    "PAYMENT_FIREWALL_INFRA_IDENTITY_SHARED_SECRET",
    "dev-insecure-infra-identity-secret",
)
APP_ENV = os.getenv("PAYMENT_FIREWALL_ENV", "development").lower()
INFRA_K8S_JWT_ISSUER = os.getenv(
    "PAYMENT_FIREWALL_INFRA_K8S_JWT_ISSUER",
    "https://kubernetes.default.svc.cluster.local",
)
INFRA_K8S_JWT_ENVIRONMENT = os.getenv("PAYMENT_FIREWALL_INFRA_K8S_ENVIRONMENT", APP_ENV).strip() or APP_ENV
INFRA_K8S_JWT_KEYS = parse_infrastructure_identity_jwt_keys(
    os.getenv(
        "PAYMENT_FIREWALL_INFRA_K8S_JWT_KEYS",
        "default:dev-k8s-service-account-jwt-secret",
    )
)
DEFAULT_EMBEDDED_RSA_JWK = {
    "kty": "RSA",
    "alg": "RS256",
    "use": "sig",
    "n": "nhJj3cmwwaU15k3E7EoGILRLYZzHUYbJAcExiBqH4LEKTpfeFfnfu2-KtwTPiP5nbisjESt78jK2kZRGO0LTwXMdBVraO6TpNC2sVwfCcE4Pu3zzoODfm1OurmidMrLAivTxLDpibUT_tn_elIiT__ARvvz6zo9o3rQ3lgdKwh9ZwJPv2NQzK1y5xFS1CtB0EIjKLzKKI5O5ofoykl0paJ7Oyd-7iGZpdQVdIFSe1_h4r-d1s7PggZ4Yo4wGGfwqZ0w2BSqds4OFa7qwpHrgVlHp5bIPcD8xj_gbImYoeUn_VGYBqzkXmdF7BVfWUsyqcrvIa_Yuoh4ST3NvfRi9WQ",
    "e": "AQAB",
}
DEFAULT_INFRA_OIDC_JWKS = json.dumps(
    {
        "keys": [
            {
                "kid": "default",
                **DEFAULT_EMBEDDED_RSA_JWK,
            }
        ]
    },
    separators=(",", ":"),
)
DEFAULT_AP2_SIGNER_JWKS = json.dumps(
    {
        "keys": [
            {
                "kid": "default",
                **DEFAULT_EMBEDDED_RSA_JWK,
            },
            {
                "kid": "merchant_v1",
                **DEFAULT_EMBEDDED_RSA_JWK,
            },
        ]
    },
    separators=(",", ":"),
)
DEFAULT_AP2_TRUST_ANCHORS = json.dumps({"trust_anchors": []}, separators=(",", ":"))
DEFAULT_AP2_FEDERATION_DISCOVERY = json.dumps({"documents": []}, separators=(",", ":"))
AP2_SIGNER_JWKS = parse_ap2_signer_jwks(
    os.getenv("PAYMENT_FIREWALL_AP2_SIGNER_JWKS", DEFAULT_AP2_SIGNER_JWKS)
)
AP2_TRUST_ANCHORS = parse_ap2_trust_anchors(
    os.getenv("PAYMENT_FIREWALL_AP2_TRUST_ANCHORS", DEFAULT_AP2_TRUST_ANCHORS)
)
AP2_FEDERATION_DISCOVERY = parse_ap2_federation_discovery(
    os.getenv("PAYMENT_FIREWALL_AP2_FEDERATION_DISCOVERY", DEFAULT_AP2_FEDERATION_DISCOVERY)
)
AP2_FEDERATION_DISCOVERY_POLL_URL = parse_optional_runtime_url(
    os.getenv("PAYMENT_FIREWALL_AP2_FEDERATION_DISCOVERY_POLL_URL"),
    env_name="PAYMENT_FIREWALL_AP2_FEDERATION_DISCOVERY_POLL_URL",
)
AP2_FEDERATION_DISCOVERY_POLL_INTERVAL_SECONDS = _env_positive_int(
    "PAYMENT_FIREWALL_AP2_FEDERATION_DISCOVERY_POLL_INTERVAL_SECONDS",
    "300",
)
AP2_FEDERATION_DISCOVERY_CACHE_MAX_AGE_SECONDS = _env_positive_int(
    "PAYMENT_FIREWALL_AP2_FEDERATION_DISCOVERY_CACHE_MAX_AGE_SECONDS",
    "900",
)
AP2_FEDERATION_DISCOVERY_TIMEOUT_SECONDS = _env_positive_int(
    "PAYMENT_FIREWALL_AP2_FEDERATION_DISCOVERY_TIMEOUT_SECONDS",
    "5",
)
AP2_FEDERATION_DISCOVERY_CACHE = AP2FederationDiscoveryCache(
    seed_documents=AP2_FEDERATION_DISCOVERY,
    poll_url=AP2_FEDERATION_DISCOVERY_POLL_URL,
    poll_interval_seconds=AP2_FEDERATION_DISCOVERY_POLL_INTERVAL_SECONDS,
    cache_max_age_seconds=AP2_FEDERATION_DISCOVERY_CACHE_MAX_AGE_SECONDS,
    timeout_seconds=AP2_FEDERATION_DISCOVERY_TIMEOUT_SECONDS,
)
INTEGRATION_ADAPTER_REGISTRY = IntegrationAdapterRegistry()
register_default_kyc_sandbox_adapters(INTEGRATION_ADAPTER_REGISTRY)
register_default_range_adapters(INTEGRATION_ADAPTER_REGISTRY)
DEFAULT_X402_PROVIDER_JWKS = DEFAULT_INFRA_OIDC_JWKS
DEFAULT_X402_PROVIDER_DISCOVERY = json.dumps(
    {
        "documents": [
            {
                "provider_name": "mock_x402_provider_rs256",
                "issuer_url": "https://provider.example/x402",
                "discovery_url": "https://provider.example/.well-known/x402-receipts",
                "jwks_key_ids": ["default"],
                "refreshed_at": datetime.now(timezone.utc).isoformat(),
            }
        ]
    },
    separators=(",", ":"),
)
INFRA_OIDC_JWT_ISSUER = os.getenv(
    "PAYMENT_FIREWALL_INFRA_OIDC_JWT_ISSUER",
    "https://identity.safe4.example/workload",
)
INFRA_OIDC_ALLOWED_SUBJECT_PREFIXES = [
    item.strip()
    for item in os.getenv("PAYMENT_FIREWALL_INFRA_OIDC_ALLOWED_SUBJECT_PREFIXES", "spiffe://safe4/").split(",")
    if item.strip()
]
INFRA_OIDC_JWKS = parse_infrastructure_identity_oidc_jwks(
    os.getenv("PAYMENT_FIREWALL_INFRA_OIDC_JWKS", DEFAULT_INFRA_OIDC_JWKS)
)
X402_PROVIDER_JWKS = parse_x402_provider_jwks(
    os.getenv("PAYMENT_FIREWALL_X402_PROVIDER_JWKS", DEFAULT_X402_PROVIDER_JWKS)
)
DEFAULT_X402_PROVIDER_TRUST_ANCHORS = json.dumps({"trust_anchors": []}, separators=(",", ":"))
X402_PROVIDER_TRUST_ANCHORS = parse_x402_provider_trust_anchors(
    os.getenv("PAYMENT_FIREWALL_X402_PROVIDER_TRUST_ANCHORS", DEFAULT_X402_PROVIDER_TRUST_ANCHORS)
)
X402_PROVIDER_DISCOVERY = parse_x402_provider_discovery(
    os.getenv("PAYMENT_FIREWALL_X402_PROVIDER_DISCOVERY", DEFAULT_X402_PROVIDER_DISCOVERY)
)
X402_PROVIDER_DISCOVERY_MAX_AGE_SECONDS = _env_positive_int(
    "PAYMENT_FIREWALL_X402_PROVIDER_DISCOVERY_MAX_AGE_SECONDS",
    "86400",
)
RANGE_PROVIDER_SLUG = "range_risk"
RANGE_PROVIDER_CONFIG = ProviderRuntimeConfig(
    provider_slug=RANGE_PROVIDER_SLUG,
    environment=ProviderEnvironment.PRODUCTION,
    endpoint=ProviderEndpointConfig(
        base_url=os.getenv(build_provider_env_var_name(RANGE_PROVIDER_SLUG, "base_url"), "https://api.range.org"),
        timeout_seconds=_env_positive_float(build_provider_env_var_name(RANGE_PROVIDER_SLUG, "timeout_seconds"), 5.0),
    ),
    credential_refs=(default_api_key_ref(RANGE_PROVIDER_SLUG),),
)


def get_range_api_key() -> str | None:
    env_name = build_provider_env_var_name(RANGE_PROVIDER_SLUG, "api_key")
    value = os.getenv(env_name)
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


POSTGRES_DSN = os.getenv("PAYMENT_FIREWALL_POSTGRES_DSN")
SQLITE_PATH = os.getenv(
    "PAYMENT_FIREWALL_DB_PATH",
    str(Path(__file__).with_name("payment_firewall.db")),
)
DB_URL = POSTGRES_DSN or SQLITE_PATH
DEFAULT_POLICY_DOCUMENT = {
    "version": POLICY_VERSION,
    "description": "Default embedded MVP policy",
    "controls": {
        "allowed_currencies": sorted(ALLOWED_CURRENCIES),
        "fee_rate": "0.0025",
        "min_description_words": MIN_DESCRIPTION_WORDS,
        "rate_limit": {
            "requests": RATE_LIMIT_REQUESTS,
            "window_seconds": RATE_LIMIT_WINDOW_SECONDS,
        },
        "payment_velocity_limit": {
            "requests": PAYMENT_VELOCITY_LIMIT,
            "window_seconds": PAYMENT_VELOCITY_WINDOW_SECONDS,
        },
        "budget_alert_thresholds": [decimal_to_text(value) for value in BUDGET_ALERT_THRESHOLDS],
        "hitl_approval_ttl_seconds": HITL_APPROVAL_TTL_SECONDS,
        "spend_token_ttl_seconds": SPEND_TOKEN_TTL_SECONDS,
        "mcp_unknown_server_hitl_threshold": decimal_to_text(MCP_UNKNOWN_SERVER_HITL_THRESHOLD),
        "webhook_timeout_seconds": WEBHOOK_TIMEOUT_SECONDS,
        "webhook_max_attempts": WEBHOOK_MAX_ATTEMPTS,
        "infrastructure_identity_anomaly_alert_min_severity": "high",
        "infrastructure_identity_anomaly_hitl_min_severity": "disabled",
        "infrastructure_identity_anomaly_deny_min_severity": "disabled",
        "phase3_features": {
            "ap2_enabled": PHASE3_AP2_ENABLED,
            "advanced_x402_enabled": PHASE3_ADVANCED_X402_ENABLED,
            "infrastructure_identity_enabled": PHASE3_INFRASTRUCTURE_IDENTITY_ENABLED,
        },
        "ap2_lifecycle_policy": {
            "intent_retention_days": 30,
            "cart_retention_days": 30,
            "archived_redaction_delay_days": 30,
        },
        "infrastructure_identity_policy": {
            "require_trusted_workload_for_admin_mutations": False,
            "oauth_only_max_amount": "5.000000",
            "trusted_workload_max_amount": "25.000000",
            "trusted_provider_names": [],
            "trusted_environments": [APP_ENV],
            "trusted_namespaces": ["payments"],
            "trusted_service_accounts": ["agent-firewall"],
            "trusted_trust_tiers": ["verified_workload"],
        },
    },
}


def get_policy_controls() -> dict[str, Any]:
    current = store.get_current_policy_document()
    return current.get("document", {}).get("controls", {})


def get_runtime_min_description_words() -> int:
    controls = get_policy_controls()
    raw = controls.get("min_description_words", MIN_DESCRIPTION_WORDS)
    try:
        return max(1, int(raw))
    except (TypeError, ValueError):
        return MIN_DESCRIPTION_WORDS


def get_runtime_payment_velocity_limit() -> int:
    controls = get_policy_controls()
    velocity_control = controls.get("payment_velocity_limit") or {}
    if not isinstance(velocity_control, dict):
        velocity_control = {}
    raw = velocity_control.get("requests", PAYMENT_VELOCITY_LIMIT)
    try:
        return max(1, int(raw))
    except (TypeError, ValueError):
        return PAYMENT_VELOCITY_LIMIT


def get_runtime_budget_alert_thresholds() -> list[Decimal]:
    controls = get_policy_controls()
    raw = controls.get("budget_alert_thresholds", [decimal_to_text(value) for value in BUDGET_ALERT_THRESHOLDS])
    try:
        return parse_budget_alert_threshold_values(raw)
    except RuntimeError:
        return BUDGET_ALERT_THRESHOLDS


def get_runtime_unknown_server_hitl_threshold() -> Decimal:
    controls = get_policy_controls()
    raw = controls.get("mcp_unknown_server_hitl_threshold", decimal_to_text(MCP_UNKNOWN_SERVER_HITL_THRESHOLD))
    try:
        return normalize_money(Decimal(str(raw)))
    except (InvalidOperation, TypeError, ValueError):
        return MCP_UNKNOWN_SERVER_HITL_THRESHOLD


def get_runtime_hitl_approval_ttl_seconds() -> int:
    controls = get_policy_controls()
    raw = controls.get("hitl_approval_ttl_seconds", HITL_APPROVAL_TTL_SECONDS)
    try:
        return max(1, int(raw))
    except (TypeError, ValueError):
        return HITL_APPROVAL_TTL_SECONDS


def get_runtime_webhook_timeout_seconds() -> int:
    controls = get_policy_controls()
    raw = controls.get("webhook_timeout_seconds", WEBHOOK_TIMEOUT_SECONDS)
    try:
        return max(1, int(raw))
    except (TypeError, ValueError):
        return WEBHOOK_TIMEOUT_SECONDS


def get_runtime_webhook_max_attempts() -> int:
    controls = get_policy_controls()
    raw = controls.get("webhook_max_attempts", WEBHOOK_MAX_ATTEMPTS)
    try:
        return max(1, int(raw))
    except (TypeError, ValueError):
        return WEBHOOK_MAX_ATTEMPTS


def get_runtime_infrastructure_identity_anomaly_alert_min_severity() -> str:
    controls = get_policy_controls()
    raw = str(controls.get("infrastructure_identity_anomaly_alert_min_severity", "high")).strip().lower()
    if raw in {"disabled", "high", "medium", "low", "informational"}:
        return raw
    return "high"


def get_runtime_infrastructure_identity_anomaly_hitl_min_severity() -> str:
    controls = get_policy_controls()
    raw = str(controls.get("infrastructure_identity_anomaly_hitl_min_severity", "disabled")).strip().lower()
    if raw in {"disabled", "high", "medium", "low", "informational"}:
        return raw
    return "disabled"


def get_runtime_infrastructure_identity_anomaly_deny_min_severity() -> str:
    controls = get_policy_controls()
    raw = str(controls.get("infrastructure_identity_anomaly_deny_min_severity", "disabled")).strip().lower()
    if raw not in {"disabled", "high", "medium", "low", "informational"}:
        return "disabled"
    hitl_threshold = get_runtime_infrastructure_identity_anomaly_hitl_min_severity()
    if raw == "disabled" or not anomaly_severity_is_stricter(severity=raw, baseline=hitl_threshold):
        return "disabled"
    return raw


def get_runtime_spend_token_ttl_seconds() -> int:
    controls = get_policy_controls()
    raw = controls.get("spend_token_ttl_seconds", SPEND_TOKEN_TTL_SECONDS)
    try:
        return max(1, int(raw))
    except (TypeError, ValueError):
        return SPEND_TOKEN_TTL_SECONDS


def get_runtime_phase3_features() -> dict[str, bool]:
    controls = get_policy_controls()
    raw = controls.get("phase3_features", {})
    if not isinstance(raw, dict):
        raw = {}
    return {
        "ap2_enabled": bool(raw.get("ap2_enabled", PHASE3_AP2_ENABLED)),
        "advanced_x402_enabled": bool(raw.get("advanced_x402_enabled", PHASE3_ADVANCED_X402_ENABLED)),
        "infrastructure_identity_enabled": bool(
            raw.get("infrastructure_identity_enabled", PHASE3_INFRASTRUCTURE_IDENTITY_ENABLED)
        ),
    }


def get_runtime_infrastructure_identity_policy() -> dict[str, Any]:
    controls = get_policy_controls()
    raw = controls.get("infrastructure_identity_policy", {})
    if not isinstance(raw, dict):
        raw = {}
    default_policy = DEFAULT_POLICY_DOCUMENT["controls"]["infrastructure_identity_policy"]

    def _string_list(key: str) -> list[str]:
        values = raw.get(key, default_policy.get(key, []))
        if not isinstance(values, list):
            values = default_policy.get(key, [])
        return [str(item).strip() for item in values if str(item).strip()]

    def _decimal_value(key: str) -> Decimal | None:
        candidate = raw.get(key, default_policy.get(key))
        if candidate is None:
            return None
        try:
            return normalize_money(Decimal(str(candidate)))
        except (InvalidOperation, TypeError, ValueError):
            default_candidate = default_policy.get(key)
            if default_candidate is None:
                return None
            return normalize_money(Decimal(str(default_candidate)))

    return {
        "enabled": get_runtime_phase3_features().get("infrastructure_identity_enabled", False),
        "require_trusted_workload_for_admin_mutations": bool(
            raw.get(
                "require_trusted_workload_for_admin_mutations",
                default_policy.get("require_trusted_workload_for_admin_mutations", False),
            )
        ),
        "oauth_only_max_amount": _decimal_value("oauth_only_max_amount"),
        "trusted_workload_max_amount": _decimal_value("trusted_workload_max_amount"),
        "trusted_provider_names": _string_list("trusted_provider_names"),
        "trusted_environments": _string_list("trusted_environments"),
        "trusted_namespaces": _string_list("trusted_namespaces"),
        "trusted_service_accounts": _string_list("trusted_service_accounts"),
        "trusted_trust_tiers": _string_list("trusted_trust_tiers"),
    }


def get_runtime_ap2_lifecycle_policy() -> dict[str, int]:
    controls = get_policy_controls()
    raw = controls.get("ap2_lifecycle_policy", {})
    if not isinstance(raw, dict):
        raw = {}
    default_policy = DEFAULT_POLICY_DOCUMENT["controls"]["ap2_lifecycle_policy"]

    def _int_value(key: str, minimum: int) -> int:
        candidate = raw.get(key, default_policy.get(key))
        try:
            return max(minimum, int(candidate))
        except (TypeError, ValueError):
            return int(default_policy[key])

    return {
        "intent_retention_days": _int_value("intent_retention_days", 1),
        "cart_retention_days": _int_value("cart_retention_days", 1),
        "archived_redaction_delay_days": _int_value("archived_redaction_delay_days", 0),
    }


app = FastAPI(
    title="Agentic Payments Firewall",
    version="0.3.0",
    description=(
        "Payment firewall for AI agents with x402-like receipts, budgets, "
        "idempotency, persistence, rate limiting, and audit hooks."
    ),
)


def validate_startup_configuration() -> None:
    """Fail fast when production-critical configuration is missing or unsafe."""

    if APP_ENV != "production":
        return

    missing: list[str] = []
    if not POSTGRES_DSN:
        missing.append("PAYMENT_FIREWALL_POSTGRES_DSN")
    if RECEIPT_ADMIN_SECRET == "change-me":
        missing.append("PAYMENT_FIREWALL_ADMIN_SECRET")
    if RECEIPT_SECRET == "dev-insecure-receipt-secret":
        missing.append("PAYMENT_FIREWALL_RECEIPT_SECRET")
    if not PAY_TO_ADDRESS or PAY_TO_ADDRESS == "wallet_address":
        missing.append("PAYMENT_FIREWALL_PAY_TO")

    if missing:
        raise RuntimeError(
            "Production startup validation failed. Configure the following env vars: "
            + ", ".join(missing)
        )


class ScopeOfAutonomy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    max_cost: Decimal | None = Field(default=None, ge=0)
    allowed_tools: list[str] | None = Field(default=None)

    @field_validator("max_cost", mode="before")
    @classmethod
    def parse_max_cost(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return parse_decimal_input(value, "max_cost")

    @field_validator("max_cost")
    @classmethod
    def normalize_max_cost(cls, value: Decimal | None) -> Decimal | None:
        if value is None:
            return None
        normalized = normalize_money(value)
        if normalized > MAX_AMOUNT:
            raise ValueError("max_cost must be less than or equal to 1000000.000000")
        if value != normalized:
            raise ValueError("max_cost must have at most 6 decimal places")
        return normalized

    @field_validator("allowed_tools")
    @classmethod
    def sanitize_allowed_tools(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        sanitized_tools = []
        for item in value:
            sanitized = sanitize_text(item, max_length=255)
            if not sanitized:
                raise ValueError("allowed_tools entries cannot be empty")
            sanitized_tools.append(sanitized)
        return sanitized_tools


class PaymentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    agent_id: str = Field(..., min_length=1)
    user_id: str = Field(..., min_length=1)
    vendor: str = Field(..., min_length=1)
    amount: Decimal = Field(..., gt=0)
    currency: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    context: dict[str, Any] = Field(default_factory=dict)
    mcp_tool_id: str | None = Field(default=None)
    mcp_action: str | None = Field(default=None)
    scope_of_autonomy: ScopeOfAutonomy | None = Field(default=None)
    ap2_mandate: AP2MandateReference | None = Field(default=None)

    @field_validator("amount", mode="before")
    @classmethod
    def parse_amount(cls, value: Any) -> Decimal:
        return parse_decimal_input(value, "amount")

    @field_validator("amount")
    @classmethod
    def normalize_amount(cls, value: Decimal) -> Decimal:
        normalized = normalize_money(value)
        if normalized > MAX_AMOUNT:
            raise ValueError("amount must be less than or equal to 1000000.000000")
        if value != normalized:
            raise ValueError("amount must have at most 6 decimal places")
        return normalized

    @field_validator("currency")
    @classmethod
    def normalize_currency(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in ALLOWED_CURRENCIES:
            raise ValueError("currency must be one of USD, EUR, GBP, USDC")
        return normalized

    @field_validator("agent_id", "user_id", "vendor", "mcp_tool_id")
    @classmethod
    def sanitize_identifier(cls, value: str) -> str:
        if value is None:
            return None
        sanitized = sanitize_text(value, max_length=255)
        if not sanitized:
            raise ValueError("value cannot be empty")
        return sanitized

    @field_validator("description")
    @classmethod
    def sanitize_description(cls, value: str) -> str:
        sanitized = sanitize_text(value, max_length=1000)
        if not sanitized:
            raise ValueError("description cannot be empty after sanitization")
        return sanitized

    @field_validator("mcp_action")
    @classmethod
    def validate_mcp_action(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = sanitize_text(value, max_length=50).lower()
        if normalized not in ALLOWED_MCP_TOOL_ACTIONS:
            raise ValueError("mcp_action must be one of purchase, subscribe, tip")
        return normalized


class ErrorResponse(BaseModel):
    code: str
    message: str
    request_id: str
    details: dict[str, Any] = Field(default_factory=dict)


def sanitize_text(value: str, max_length: int) -> str:
    cleaned = value.replace("\x00", " ")
    cleaned = SCRIPT_PATTERN.sub(" ", cleaned)
    cleaned = TAG_PATTERN.sub(" ", cleaned)
    cleaned = html.unescape(cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if len(cleaned) > max_length:
        raise ValueError(f"value exceeds maximum length of {max_length}")
    return cleaned


def build_approval_payload(payment: PaymentRequest) -> dict[str, Any]:
    return {
        "agent_id": payment.agent_id,
        "user_id": payment.user_id,
        "vendor": payment.vendor,
        "amount": decimal_to_text(payment.amount),
        "currency": payment.currency,
        "description": payment.description,
        "context": payment.context,
        "mcp_tool_id": payment.mcp_tool_id,
        "mcp_action": payment.mcp_action,
        "ap2_mandate": payment.ap2_mandate.model_dump(mode="json") if payment.ap2_mandate is not None else None,
    }


class MetricsCollector:
    """Simple in-process metrics accumulator."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = defaultdict(int)

    def increment(self, name: str) -> None:
        with self._lock:
            self._counters[name] += 1

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counters)

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()


class RateLimiter:
    """Sliding-window rate limiter keyed by client identity."""

    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> tuple[bool, int]:
        now = time.time()
        with self._lock:
            window = self._events[key]
            while window and now - window[0] > self.window_seconds:
                window.popleft()
            if len(window) >= self.limit:
                retry_after = max(1, int(self.window_seconds - (now - window[0])))
                return False, retry_after
            window.append(now)
            return True, 0

    def reset(self) -> None:
        with self._lock:
            self._events.clear()


DEFAULT_BUDGETS: dict[str, dict[str, Decimal]] = {
    "user_123": {
        "daily_cap": Decimal("100.00"),
        "transaction_cap": Decimal("10.00"),
        "spent_today": Decimal("0.00"),
    }
}
DEFAULT_VALID_RECEIPTS: dict[str, dict[str, Any]] = {}
store = FirewallStore(
    DB_URL,
    DEFAULT_BUDGETS,
    DEFAULT_VALID_RECEIPTS,
    default_policy_version=POLICY_VERSION,
    default_policy_document=DEFAULT_POLICY_DOCUMENT,
)
setup_auth(
    store=store,
    allowed_scopes=ALLOWED_SCOPES,
    get_runtime_phase3_features=get_runtime_phase3_features,
    get_runtime_infrastructure_identity_policy=get_runtime_infrastructure_identity_policy,
    infra_identity_shared_secret=INFRA_IDENTITY_SHARED_SECRET,
    infra_identity_kubernetes_issuer=INFRA_K8S_JWT_ISSUER,
    infra_identity_kubernetes_environment=INFRA_K8S_JWT_ENVIRONMENT,
    infra_identity_kubernetes_signing_keys=INFRA_K8S_JWT_KEYS,
    infra_identity_oidc_issuer=INFRA_OIDC_JWT_ISSUER,
    infra_identity_oidc_signing_keys=INFRA_OIDC_JWKS,
    infra_identity_oidc_allowed_subject_prefixes=INFRA_OIDC_ALLOWED_SUBJECT_PREFIXES,
)
metrics = MetricsCollector()
rate_limiter = RateLimiter(RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SECONDS)


def verify_intent(description: str, context: dict[str, Any] | None = None) -> bool:
    """Compatibility wrapper around the explainable task-bound evaluator."""
    return evaluate_payment_intent(
        description=description,
        context=context,
        legacy_minimum_words=get_runtime_min_description_words(),
    ).allowed


def evaluate_intent(payment: PaymentRequest) -> IntentDecision:
    return evaluate_payment_intent(
        description=payment.description,
        context=payment.context,
        legacy_minimum_words=get_runtime_min_description_words(),
    )


def compute_firewall_fee(amount: Decimal) -> Decimal:
    fee = normalize_money(amount * FEE_RATE)
    return max(fee, MONEY_SCALE)


def reset_runtime_state() -> None:
    store.reset_for_tests()
    metrics.reset()
    rate_limiter.reset()
    AP2_FEDERATION_DISCOVERY_CACHE.reset()
    setup_ap2_api(
        store=store,
        append_audit_entry=append_audit_entry,
        error_payload=error_payload,
        hash_token=hash_token,
        sanitize_text=sanitize_text,
        get_current_identity=get_current_identity,
        ensure_scope=ensure_scope,
        get_runtime_phase3_features=get_runtime_phase3_features,
        get_runtime_ap2_lifecycle_policy=get_runtime_ap2_lifecycle_policy,
        deny_payment=deny_payment,
        shared_secret=AP2_SHARED_SECRET,
        signer_keys=AP2_SIGNER_KEYS,
        signer_jwks=AP2_SIGNER_JWKS,
        trust_anchors=AP2_TRUST_ANCHORS,
        get_federation_discovery=AP2_FEDERATION_DISCOVERY_CACHE.current_documents,
    )
    setup_x402_api(
        store=store,
        append_audit_entry=append_audit_entry,
        get_current_identity=get_current_identity,
        ensure_scope=ensure_scope,
        get_runtime_phase3_features=get_runtime_phase3_features,
        parse_and_validate_receipt_token=parse_and_validate_receipt_token,
        normalize_money=normalize_money,
        pay_to_address=PAY_TO_ADDRESS,
        challenge_ttl_seconds=X402_CHALLENGE_TTL_SECONDS,
        supported_networks=X402_SUPPORTED_NETWORKS,
        network_recipient_addresses=X402_NETWORK_RECIPIENT_ADDRESSES,
        provider_shared_secret=X402_PROVIDER_SHARED_SECRET,
        provider_keys=X402_PROVIDER_KEYS,
        provider_jwks=X402_PROVIDER_JWKS,
        provider_trust_anchors=X402_PROVIDER_TRUST_ANCHORS,
        provider_discovery=X402_PROVIDER_DISCOVERY,
        provider_discovery_max_age_seconds=X402_PROVIDER_DISCOVERY_MAX_AGE_SECONDS,
    )
    setup_integrations_api(
        get_current_identity=get_current_identity,
        ensure_scope=ensure_scope,
        registry=INTEGRATION_ADAPTER_REGISTRY,
        range_provider_config=RANGE_PROVIDER_CONFIG,
        get_range_api_key=get_range_api_key,
    )


def build_request_hash(payment: PaymentRequest) -> str:
    canonical = json.dumps(jsonable_encoder(payment.model_dump()), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def sign_receipt_components(
    receipt_id: str, pay_to: str, amount_due: Decimal, currency: str, expires_at: str
) -> str:
    canonical = f"{receipt_id}|{pay_to}|{decimal_to_text(amount_due)}|{currency}|{expires_at}"
    return hmac.new(RECEIPT_SECRET.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def build_receipt_token(
    receipt_id: str, pay_to: str, amount_due: Decimal, currency: str, expires_at: str
) -> str:
    return f"{receipt_id}.{sign_receipt_components(receipt_id, pay_to, amount_due, currency, expires_at)}"


def issue_receipt(amount_due: Decimal, currency: str, expires_in_seconds: int, pay_to: str) -> dict[str, Any]:
    receipt_id = uuid4().hex
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds)).isoformat()
    receipt = store.upsert_receipt(
        receipt=receipt_id,
        status="paid",
        pay_to=pay_to,
        metadata={
            "amount_due": decimal_to_text(amount_due),
            "currency": currency,
            "expires_at": expires_at,
        },
    )
    receipt["token"] = build_receipt_token(
        receipt_id,
        pay_to,
        normalize_money(Decimal(str(receipt["amount_due"]))),
        receipt["currency"],
        receipt["expires_at"],
    )
    return receipt


def parse_and_validate_receipt_token(receipt_token: str | None) -> tuple[str | None, dict[str, Any] | None]:
    if not receipt_token or "." not in receipt_token:
        return None, None
    receipt_id, provided_signature = receipt_token.split(".", 1)
    receipt = store.get_receipt(receipt_id)
    if receipt is None:
        return receipt_id, None
    expected_signature = sign_receipt_components(
        receipt_id,
        receipt["pay_to"],
        normalize_money(Decimal(str(receipt["amount_due"]))),
        receipt["currency"],
        receipt["expires_at"],
    )
    if not secrets.compare_digest(provided_signature, expected_signature):
        return receipt_id, None
    return receipt_id, receipt


def error_payload(
    request: Request, code: str, message: str, details: dict[str, Any] | None = None
) -> dict[str, Any]:
    request_id = getattr(request.state, "request_id", "unknown")
    payload = ErrorResponse(
        code=code,
        message=message,
        request_id=request_id,
        details=details or {},
    ).model_dump()
    return jsonable_encoder(payload)


def serialize_budget(budget: dict[str, Decimal]) -> dict[str, str]:
    return {key: decimal_to_text(value) for key, value in budget.items()}


def append_log(
    request: Request,
    payment: PaymentRequest,
    firewall_fee: Decimal,
    result: str,
    reason: str | None,
    started_at: float,
    idempotency_key: str | None,
    ) -> None:
    store.append_log(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "transaction_id": getattr(request.state, "transaction_id", None),
            "request_id": request.state.request_id,
            "client_ip": request.client.host if request.client else None,
            "agent_id": payment.agent_id,
            "user_id": payment.user_id,
            "vendor": payment.vendor,
            "amount": payment.amount,
            "currency": payment.currency,
            "firewall_fee": firewall_fee,
            "justification": payment.description,
            "context": payment.context,
            "result": result,
            "reason": reason,
            "decision_latency_ms": int((time.perf_counter() - started_at) * 1000),
            "idempotency_key": idempotency_key,
        }
    )


def append_audit_entry(
    *,
    actor_type: str,
    actor_id: str,
    action: str,
    request_path: str,
    request_payload_hash: str,
    request_payload_summary: dict[str, Any],
    decision: str,
    decision_reason: str | None,
    decision_details: dict[str, Any],
    transaction_id: str | None = None,
    transaction_amount: Decimal | None = None,
    transaction_currency: str | None = None,
    mcp_server_id: str | None = None,
    mcp_tool_id: str | None = None,
    mcp_tool_name: str | None = None,
    infrastructure_provider_name: str | None = None,
    infrastructure_subject: str | None = None,
    infrastructure_trust_tier: str | None = None,
) -> None:
    store.append_audit_entry(
        {
            "actor_type": actor_type,
            "actor_id": actor_id,
            "action": action,
            "request_path": request_path,
            "request_payload_hash": request_payload_hash,
            "request_payload_summary": request_payload_summary,
            "policy_version": store.get_current_policy_version(),
            "decision": decision,
            "decision_reason": decision_reason,
            "decision_details": decision_details,
            "transaction_id": transaction_id,
            "transaction_amount": transaction_amount,
            "transaction_currency": transaction_currency,
            "mcp_server_id": mcp_server_id,
            "mcp_tool_id": mcp_tool_id,
            "mcp_tool_name": mcp_tool_name,
            "infrastructure_provider_name": infrastructure_provider_name,
            "infrastructure_subject": infrastructure_subject,
            "infrastructure_trust_tier": infrastructure_trust_tier,
        }
    )


setup_payment_flow(
    store=store,
    metrics=metrics,
    append_audit_entry=append_audit_entry,
    append_log=append_log,
    error_payload=error_payload,
    decimal_to_text=decimal_to_text,
    pay_to_address=PAY_TO_ADDRESS,
    fee_rate=FEE_RATE,
    build_x402_challenge=build_x402_challenge,
)
setup_mcp_payment_policy(
    store=store,
    metrics=metrics,
    append_audit_entry=append_audit_entry,
    error_payload=error_payload,
    hash_token=hash_token,
    normalize_money=normalize_money,
    decimal_to_text=decimal_to_text,
    build_approval_payload=build_approval_payload,
    payment_request_summary=payment_request_summary,
    deny_payment=deny_payment,
    hitl_approval_ttl_seconds=HITL_APPROVAL_TTL_SECONDS,
    get_unknown_server_hitl_threshold=get_runtime_unknown_server_hitl_threshold,
)
setup_payment_entry_checks(
    store=store,
    metrics=metrics,
    append_audit_entry=append_audit_entry,
    error_payload=error_payload,
    decimal_to_text=decimal_to_text,
    payment_required_response=payment_required_response,
    deny_payment=deny_payment,
    verify_x402_receipt=verify_x402_receipt,
)
setup_payment_finalize(
    store=store,
    metrics=metrics,
    append_log=append_log,
    append_audit_entry=append_audit_entry,
    serialize_budget=serialize_budget,
    get_budget_alert_thresholds=get_runtime_budget_alert_thresholds,
    get_infrastructure_identity_anomaly_alert_min_severity=get_runtime_infrastructure_identity_anomaly_alert_min_severity,
)
setup_ops_api(
    store=store,
    metrics=metrics,
    get_current_identity=get_current_identity,
    ensure_scope=ensure_scope,
    database_backend="postgresql" if POSTGRES_DSN else "sqlite",
    rate_limit_requests=RATE_LIMIT_REQUESTS,
    rate_limit_window_seconds=RATE_LIMIT_WINDOW_SECONDS,
    payment_velocity_limit=PAYMENT_VELOCITY_LIMIT,
    payment_velocity_window_seconds=PAYMENT_VELOCITY_WINDOW_SECONDS,
)
setup_policy_api(
    store=store,
    append_audit_entry=append_audit_entry,
    hash_token=hash_token,
    sanitize_text=sanitize_text,
    get_current_identity=get_current_identity,
    ensure_scope=ensure_scope,
)
setup_ap2_api(
    store=store,
    append_audit_entry=append_audit_entry,
    error_payload=error_payload,
    hash_token=hash_token,
    sanitize_text=sanitize_text,
    get_current_identity=get_current_identity,
    ensure_scope=ensure_scope,
    get_runtime_phase3_features=get_runtime_phase3_features,
    get_runtime_ap2_lifecycle_policy=get_runtime_ap2_lifecycle_policy,
    deny_payment=deny_payment,
    shared_secret=AP2_SHARED_SECRET,
    signer_keys=AP2_SIGNER_KEYS,
    signer_jwks=AP2_SIGNER_JWKS,
    trust_anchors=AP2_TRUST_ANCHORS,
    get_federation_discovery=AP2_FEDERATION_DISCOVERY_CACHE.current_documents,
)
setup_phase3_api(
    store=store,
    get_current_identity=get_current_identity,
    ensure_scope=ensure_scope,
    list_infrastructure_identity_verifiers=list_infrastructure_identity_verifiers,
    append_audit_entry=append_audit_entry,
)
setup_x402_api(
    store=store,
    append_audit_entry=append_audit_entry,
    get_current_identity=get_current_identity,
    ensure_scope=ensure_scope,
    get_runtime_phase3_features=get_runtime_phase3_features,
    parse_and_validate_receipt_token=parse_and_validate_receipt_token,
    normalize_money=normalize_money,
    pay_to_address=PAY_TO_ADDRESS,
    challenge_ttl_seconds=X402_CHALLENGE_TTL_SECONDS,
    supported_networks=X402_SUPPORTED_NETWORKS,
    network_recipient_addresses=X402_NETWORK_RECIPIENT_ADDRESSES,
    provider_shared_secret=X402_PROVIDER_SHARED_SECRET,
    provider_keys=X402_PROVIDER_KEYS,
    provider_jwks=X402_PROVIDER_JWKS,
    provider_trust_anchors=X402_PROVIDER_TRUST_ANCHORS,
    provider_discovery=X402_PROVIDER_DISCOVERY,
    provider_discovery_max_age_seconds=X402_PROVIDER_DISCOVERY_MAX_AGE_SECONDS,
)

setup_mcp_api(
    store=store,
    append_audit_entry=append_audit_entry,
    hash_token=hash_token,
    get_current_identity=get_current_identity,
    ensure_scope=ensure_scope,
)
setup_audit_api(
    store=store,
    compute_audit_entry_hash=compute_audit_entry_hash,
    get_current_identity=get_current_identity,
    ensure_scope=ensure_scope,
)
setup_oauth_api(
    store=store,
    append_audit_entry=append_audit_entry,
    hash_token=hash_token,
    issue_secret_token=issue_secret_token,
    normalize_scope_string=normalize_scope_string,
    verify_pkce=verify_pkce,
    error_payload=error_payload,
    sanitize_text=sanitize_text,
    allowed_scopes=ALLOWED_SCOPES,
    oauth_issuer=OAUTH_ISSUER,
    access_token_ttl_seconds=ACCESS_TOKEN_TTL_SECONDS,
    refresh_token_ttl_seconds=REFRESH_TOKEN_TTL_SECONDS,
    auth_code_ttl_seconds=AUTH_CODE_TTL_SECONDS,
)
setup_hitl_api(
    store=store,
    append_audit_entry=append_audit_entry,
    hash_token=hash_token,
    issue_secret_token=issue_secret_token,
    normalize_money=normalize_money,
    decimal_to_text=decimal_to_text,
    sanitize_text=sanitize_text,
    parse_decimal_input=parse_decimal_input,
    get_current_identity=get_current_identity,
    ensure_scope=ensure_scope,
    get_spend_token_ttl_seconds=get_runtime_spend_token_ttl_seconds,
    max_amount=MAX_AMOUNT,
)
setup_hitl_policy(
    store=store,
    metrics=metrics,
    append_audit_entry=append_audit_entry,
    error_payload=error_payload,
    deny_payment=deny_payment,
    hash_token=hash_token,
    build_approval_payload=build_approval_payload,
    payment_request_summary=payment_request_summary,
    get_hitl_approval_ttl_seconds=get_runtime_hitl_approval_ttl_seconds,
    get_runtime_infrastructure_identity_policy=get_runtime_infrastructure_identity_policy,
    get_runtime_infrastructure_identity_anomaly_hitl_min_severity=get_runtime_infrastructure_identity_anomaly_hitl_min_severity,
    get_runtime_infrastructure_identity_anomaly_deny_min_severity=get_runtime_infrastructure_identity_anomaly_deny_min_severity,
)
setup_budgets_api(
    store=store,
    append_audit_entry=append_audit_entry,
    decimal_to_text=decimal_to_text,
    serialize_budget=serialize_budget,
    sanitize_text=sanitize_text,
    parse_decimal_input=parse_decimal_input,
    normalize_money=normalize_money,
    get_current_identity=get_current_identity,
    ensure_scope=ensure_scope,
    max_amount=MAX_AMOUNT,
    get_budget_alert_thresholds=get_runtime_budget_alert_thresholds,
)
setup_webhooks_api(
    store=store,
    append_audit_entry=append_audit_entry,
    hash_token=hash_token,
    sanitize_text=sanitize_text,
    get_current_identity=get_current_identity,
    ensure_scope=ensure_scope,
    get_webhook_timeout_seconds=get_runtime_webhook_timeout_seconds,
    webhook_dispatch_enabled=WEBHOOK_DISPATCH_ENABLED,
    webhook_dispatch_interval_seconds=WEBHOOK_DISPATCH_INTERVAL_SECONDS,
    get_webhook_max_attempts=get_runtime_webhook_max_attempts,
)
setup_receipts_api(
    store=store,
    append_audit_entry=append_audit_entry,
    issue_receipt=issue_receipt,
    decimal_to_text=decimal_to_text,
    sanitize_text=sanitize_text,
    parse_decimal_input=parse_decimal_input,
    normalize_money=normalize_money,
    error_payload=error_payload,
    get_current_identity=get_current_identity,
    ensure_scope=ensure_scope,
    metrics=metrics,
    max_amount=MAX_AMOUNT,
    default_receipt_ttl_seconds=DEFAULT_RECEIPT_TTL_SECONDS,
    pay_to_address=PAY_TO_ADDRESS,
    receipt_admin_secret=RECEIPT_ADMIN_SECRET,
    allowed_currencies=ALLOWED_CURRENCIES,
)
setup_integrations_api(
    get_current_identity=get_current_identity,
    ensure_scope=ensure_scope,
    registry=INTEGRATION_ADAPTER_REGISTRY,
    range_provider_config=RANGE_PROVIDER_CONFIG,
    get_range_api_key=get_range_api_key,
)
setup_demo_api(
    demo_access_token=os.getenv("PAYMENT_FIREWALL_DEMO_ACCESS_TOKEN"),
)
app.include_router(audit_router)
app.include_router(ap2_router)
app.include_router(budgets_router)
app.include_router(demo_router)
app.include_router(hitl_router)
app.include_router(integrations_router)
app.include_router(mcp_router)
app.include_router(ops_router)
app.include_router(oauth_router)
app.include_router(phase3_router)
app.include_router(policy_router)
app.include_router(receipts_router)
app.include_router(webhooks_router)
app.include_router(x402_router)


@app.on_event("startup")
async def start_background_webhook_dispatcher() -> None:
    if WEBHOOK_DISPATCH_ENABLED:
        webhook_dispatcher.start()


@app.on_event("shutdown")
async def stop_background_webhook_dispatcher() -> None:
    webhook_dispatcher.stop()


@app.middleware("http")
async def add_request_context(request: Request, call_next):
    request.state.request_id = request.headers.get("X-Request-Id", str(uuid4()))
    request.state.started_at = time.perf_counter()
    metrics.increment("http_requests_total")

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_BODY_BYTES:
                metrics.increment("http_request_too_large_total")
                body = error_payload(
                    request,
                    "REQUEST_TOO_LARGE",
                    "Request body exceeds the maximum allowed size.",
                    {"max_body_bytes": MAX_BODY_BYTES},
                )
                response = JSONResponse(status_code=status.HTTP_413_CONTENT_TOO_LARGE, content=body)
                response.headers["X-Request-Id"] = request.state.request_id
                return response
        except ValueError:
            pass

    raw_body = await request.body()
    if len(raw_body) > MAX_BODY_BYTES:
        metrics.increment("http_request_too_large_total")
        body = error_payload(
            request,
            "REQUEST_TOO_LARGE",
            "Request body exceeds the maximum allowed size.",
            {"max_body_bytes": MAX_BODY_BYTES},
        )
        response = JSONResponse(status_code=status.HTTP_413_CONTENT_TOO_LARGE, content=body)
        response.headers["X-Request-Id"] = request.state.request_id
        return response

    limited_paths = {"/pay", "/receipts/issue"}
    if request.url.path in limited_paths:
        client_key = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")
        allowed, retry_after = rate_limiter.allow(f"{request.url.path}:{client_key}")
        if not allowed:
            metrics.increment("http_rate_limited_total")
            body = error_payload(
                request,
                "RATE_LIMITED",
                "Rate limit exceeded for this endpoint.",
                {"retry_after_seconds": retry_after},
            )
            response = JSONResponse(status_code=status.HTTP_429_TOO_MANY_REQUESTS, content=body)
            response.headers["Retry-After"] = str(retry_after)
            response.headers["X-Request-Id"] = request.state.request_id
            return response

    response = await call_next(request)
    response.headers["X-Request-Id"] = request.state.request_id
    return response


@app.on_event("startup")
def startup_validation() -> None:
    """Validate runtime configuration before serving requests."""

    validate_startup_configuration()


@app.post("/pay")
def authorize_payment(
    request: Request,
    payment: PaymentRequest,
    x_payment_receipt: str | None = Header(default=None, alias="X-Payment-Receipt"),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    x_spend_token: str | None = Header(default=None, alias="X-Spend-Token"),
    identity: AgentIdentity = Depends(require_scopes("payment:authorize")),
) -> JSONResponse:
    started_at = request.state.started_at
    request.state.current_identity = identity
    request_hash: str | None = None
    if identity.agent_id and identity.agent_id != payment.agent_id:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=error_payload(
                request,
                "AGENT_ID_MISMATCH",
                "Token agent_id does not match the payment request agent_id.",
                {"token_agent_id": identity.agent_id, "request_agent_id": payment.agent_id},
            ),
        )
    if (payment.mcp_tool_id and not payment.mcp_action) or (payment.mcp_action and not payment.mcp_tool_id):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content=error_payload(
                request,
                "INVALID_MCP_CONTEXT",
                "mcp_tool_id and mcp_action must be provided together.",
            ),
        )
    if idempotency_key and not UUID4_PATTERN.fullmatch(idempotency_key):
        metrics.increment("payment_invalid_idempotency_key_total")
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content=error_payload(
                request,
                "INVALID_IDEMPOTENCY_KEY",
                "Idempotency-Key must be a UUIDv4 string.",
                {"idempotency_key": idempotency_key},
            ),
        )
    request_hash = build_request_hash(payment)
    mcp_server_id: str | None = None
    mcp_tool_name: str | None = None
    idempotent_response = check_payment_idempotency(
        request=request,
        idempotency_key=idempotency_key,
        request_hash=request_hash,
    )
    if idempotent_response is not None:
        return idempotent_response

    amount_due = compute_firewall_fee(payment.amount)
    receipt_response, receipt_id, receipt, receipt_source = validate_payment_receipt(
        request=request,
        payment=payment,
        request_hash=request_hash,
        amount_due=amount_due,
        started_at=started_at,
        idempotency_key=idempotency_key,
        x_payment_receipt=x_payment_receipt,
    )
    if receipt_response is not None:
        return receipt_response

    ap2_response = enforce_ap2_policy(
        request=request,
        payment=payment,
        request_hash=request_hash,
        amount_due=amount_due,
        started_at=started_at,
        idempotency_key=idempotency_key,
        mcp_server_id=mcp_server_id,
        mcp_tool_id=payment.mcp_tool_id,
        mcp_tool_name=mcp_tool_name,
    )
    if ap2_response is not None:
        return ap2_response

    if payment.scope_of_autonomy and payment.scope_of_autonomy.allowed_tools is not None:
        if not payment.mcp_tool_id or payment.mcp_tool_id not in payment.scope_of_autonomy.allowed_tools:
            return deny_payment(
                request=request,
                payment=payment,
                request_hash=request_hash,
                amount_due=amount_due,
                started_at=started_at,
                idempotency_key=idempotency_key,
                status_code=status.HTTP_403_FORBIDDEN,
                error_code="SCOPE_OF_AUTONOMY_TOOL_NOT_ALLOWED",
                message="The requested tool is not allowed by the presented ScopeOfAutonomy.",
                details={
                    "requested_tool": payment.mcp_tool_id,
                    "allowed_tools": payment.scope_of_autonomy.allowed_tools,
                },
                audit_reason="The requested tool is not allowed by the presented ScopeOfAutonomy.",
                audit_reason_code="SCOPE_OF_AUTONOMY_TOOL_NOT_ALLOWED",
                mcp_tool_id=payment.mcp_tool_id,
            )

    mcp_response, mcp_server_id, mcp_tool_name = enforce_mcp_payment_policy(
        request=request,
        payment=payment,
        request_hash=request_hash,
        amount_due=amount_due,
        started_at=started_at,
        idempotency_key=idempotency_key,
        x_spend_token=x_spend_token,
        receipt_id=receipt_id,
        receipt_source=receipt_source,
    )
    if mcp_response is not None:
        return mcp_response

    agent_budget = store.get_agent_budget(payment.agent_id)
    if agent_budget is None:
        return deny_payment(
            request=request,
            payment=payment,
            request_hash=request_hash,
            amount_due=amount_due,
            started_at=started_at,
            idempotency_key=idempotency_key,
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="AGENT_BUDGET_NOT_FOUND",
            message="No budget configured for agent.",
            details={"agent_id": payment.agent_id},
            metric_name="payment_denied_agent_budget_missing_total",
            audit_reason="No budget configured for agent.",
            audit_reason_code="AGENT_BUDGET_NOT_FOUND",
        )

    if payment.amount > agent_budget["transaction_cap"]:
        reason = "Transaction exceeds agent per-transaction cap."
        return deny_payment(
            request=request,
            payment=payment,
            request_hash=request_hash,
            amount_due=amount_due,
            started_at=started_at,
            idempotency_key=idempotency_key,
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="AGENT_TRANSACTION_CAP_EXCEEDED",
            message=reason,
            details={
                "agent_transaction_cap": decimal_to_text(agent_budget["transaction_cap"]),
                "requested_amount": decimal_to_text(payment.amount),
            },
            metric_name="payment_denied_agent_transaction_cap_total",
            append_log_reason=reason,
            mark_receipt_id=receipt_id or "",
            mark_receipt_source=receipt_source,
            audit_reason=reason,
            audit_reason_code="AGENT_TRANSACTION_CAP_EXCEEDED",
        )

    projected_agent_total = normalize_money(agent_budget["spent_today"] + payment.amount)
    if projected_agent_total > agent_budget["daily_cap"]:
        reason = "Transaction exceeds agent daily budget."
        return deny_payment(
            request=request,
            payment=payment,
            request_hash=request_hash,
            amount_due=amount_due,
            started_at=started_at,
            idempotency_key=idempotency_key,
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="AGENT_DAILY_CAP_EXCEEDED",
            message=reason,
            details={
                "agent_daily_cap": decimal_to_text(agent_budget["daily_cap"]),
                "agent_spent_today": decimal_to_text(agent_budget["spent_today"]),
                "requested_amount": decimal_to_text(payment.amount),
            },
            metric_name="payment_denied_agent_daily_cap_total",
            append_log_reason=reason,
            mark_receipt_id=receipt_id or "",
            mark_receipt_source=receipt_source,
            audit_reason=reason,
            audit_reason_code="AGENT_DAILY_CAP_EXCEEDED",
        )

    velocity_window_start = (datetime.now(timezone.utc) - timedelta(seconds=PAYMENT_VELOCITY_WINDOW_SECONDS)).isoformat()
    recent_event_count = store.count_recent_transaction_events(payment.agent_id, payment.user_id, velocity_window_start)
    current_velocity_limit = get_runtime_payment_velocity_limit()
    if recent_event_count >= current_velocity_limit:
        reason = "Transaction exceeds velocity policy for this agent and user."
        return deny_payment(
            request=request,
            payment=payment,
            request_hash=request_hash,
            amount_due=amount_due,
            started_at=started_at,
            idempotency_key=idempotency_key,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            error_code="VELOCITY_LIMIT_EXCEEDED",
            message=reason,
            details={
                "velocity_limit": current_velocity_limit,
                "window_seconds": PAYMENT_VELOCITY_WINDOW_SECONDS,
                "recent_event_count": recent_event_count,
            },
            metric_name="payment_denied_velocity_total",
            append_log_reason=reason,
            mark_receipt_id=receipt_id or "",
            mark_receipt_source=receipt_source,
            audit_reason=reason,
            audit_reason_code="VELOCITY_LIMIT_EXCEEDED",
            extra_audit_details={"recent_event_count": recent_event_count},
        )

    budget = store.get_budget(payment.user_id)
    if budget is None:
        return deny_payment(
            request=request,
            payment=payment,
            request_hash=request_hash,
            amount_due=amount_due,
            started_at=started_at,
            idempotency_key=idempotency_key,
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="BUDGET_NOT_FOUND",
            message="No budget configured for user.",
            details={"user_id": payment.user_id},
            metric_name="payment_denied_budget_missing_total",
            append_log_reason="No budget configured for user.",
            mark_receipt_id=receipt_id or "",
            mark_receipt_source=receipt_source,
            audit_reason="No budget configured for user.",
            audit_reason_code="BUDGET_NOT_FOUND",
            mcp_server_id=mcp_server_id,
            mcp_tool_id=payment.mcp_tool_id,
            mcp_tool_name=mcp_tool_name,
        )

    if payment.scope_of_autonomy and payment.scope_of_autonomy.max_cost is not None:
        projected_scope_total = normalize_money(budget["spent_today"] + payment.amount)
        if projected_scope_total > payment.scope_of_autonomy.max_cost:
            return deny_payment(
                request=request,
                payment=payment,
                request_hash=request_hash,
                amount_due=amount_due,
                started_at=started_at,
                idempotency_key=idempotency_key,
                status_code=status.HTTP_403_FORBIDDEN,
                error_code="SCOPE_OF_AUTONOMY_MAX_COST_EXCEEDED",
                message="The requested amount exceeds the presented ScopeOfAutonomy max_cost.",
                details={
                    "max_cost": decimal_to_text(payment.scope_of_autonomy.max_cost),
                    "spent_today": decimal_to_text(budget["spent_today"]),
                    "requested_amount": decimal_to_text(payment.amount),
                },
                audit_reason="The requested amount exceeds the presented ScopeOfAutonomy max_cost.",
                audit_reason_code="SCOPE_OF_AUTONOMY_MAX_COST_EXCEEDED",
                mcp_server_id=mcp_server_id,
                mcp_tool_id=payment.mcp_tool_id,
                mcp_tool_name=mcp_tool_name,
            )

    if payment.amount > budget["transaction_cap"]:
        reason = "Transaction exceeds per-transaction cap."
        return deny_payment(
            request=request,
            payment=payment,
            request_hash=request_hash,
            amount_due=amount_due,
            started_at=started_at,
            idempotency_key=idempotency_key,
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="TRANSACTION_CAP_EXCEEDED",
            message=reason,
            details={
                "transaction_cap": decimal_to_text(budget["transaction_cap"]),
                "requested_amount": decimal_to_text(payment.amount),
            },
            metric_name="payment_denied_transaction_cap_total",
            append_log_reason=reason,
            mark_receipt_id=receipt_id or "",
            mark_receipt_source=receipt_source,
            audit_reason=reason,
            audit_reason_code="TRANSACTION_CAP_EXCEEDED",
            mcp_server_id=mcp_server_id,
            mcp_tool_id=payment.mcp_tool_id,
            mcp_tool_name=mcp_tool_name,
        )

    projected_total = normalize_money(budget["spent_today"] + payment.amount)
    if projected_total > budget["daily_cap"]:
        reason = "Transaction exceeds daily budget."
        return deny_payment(
            request=request,
            payment=payment,
            request_hash=request_hash,
            amount_due=amount_due,
            started_at=started_at,
            idempotency_key=idempotency_key,
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="DAILY_CAP_EXCEEDED",
            message=reason,
            details={
                "daily_cap": decimal_to_text(budget["daily_cap"]),
                "spent_today": decimal_to_text(budget["spent_today"]),
                "requested_amount": decimal_to_text(payment.amount),
            },
            metric_name="payment_denied_daily_cap_total",
            append_log_reason=reason,
            mark_receipt_id=receipt_id or "",
            mark_receipt_source=receipt_source,
            audit_reason=reason,
            audit_reason_code="DAILY_CAP_EXCEEDED",
            mcp_server_id=mcp_server_id,
            mcp_tool_id=payment.mcp_tool_id,
            mcp_tool_name=mcp_tool_name,
        )

    intent_decision = evaluate_intent(payment)
    request.state.intent_decision = intent_decision.public_details()
    if not intent_decision.allowed:
        reason = intent_decision.reason
        return deny_payment(
            request=request,
            payment=payment,
            request_hash=request_hash,
            amount_due=amount_due,
            started_at=started_at,
            idempotency_key=idempotency_key,
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="INTENT_VERIFICATION_FAILED",
            message=reason,
            details={"intent_decision": intent_decision.public_details()},
            metric_name="payment_denied_intent_total",
            append_log_reason=reason,
            mark_receipt_id=receipt_id or "",
            mark_receipt_source=receipt_source,
            audit_reason=reason,
            audit_reason_code="INTENT_VERIFICATION_FAILED",
            mcp_server_id=mcp_server_id,
            mcp_tool_id=payment.mcp_tool_id,
            mcp_tool_name=mcp_tool_name,
        )

    hitl_response = enforce_direct_hitl_policy(
        request=request,
        payment=payment,
        request_hash=request_hash,
        amount_due=amount_due,
        started_at=started_at,
        idempotency_key=idempotency_key,
        x_spend_token=x_spend_token,
        receipt_id=receipt_id,
        receipt_source=receipt_source,
        mcp_server_id=mcp_server_id,
        mcp_tool_name=mcp_tool_name,
    )
    if hitl_response is not None:
        return hitl_response

    return finalize_authorized_payment(
        request=request,
        payment=payment,
        request_hash=request_hash,
        amount_due=amount_due,
        started_at=started_at,
        idempotency_key=idempotency_key,
        receipt_id=receipt_id,
        receipt_source=receipt_source,
        projected_total=projected_total,
        projected_agent_total=projected_agent_total,
        mcp_server_id=mcp_server_id,
        mcp_tool_name=mcp_tool_name,
    )

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=PORT, reload=False)
