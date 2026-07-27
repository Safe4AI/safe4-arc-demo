from __future__ import annotations

import os
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any
from urllib.parse import urlsplit, urlunsplit


MONEY_SCALE = Decimal("0.000001")


def env_decimal(name: str, default: str) -> Decimal:
    raw = os.getenv(name, default)
    try:
        return Decimal(raw)
    except InvalidOperation:
        return Decimal(default)


def env_positive_int(name: str, default: str, *, minimum: int = 1) -> int:
    raw = os.getenv(name, default)
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if value < minimum:
        raise RuntimeError(f"{name} must be at least {minimum}")
    return value


def normalize_money(value: Decimal) -> Decimal:
    return value.quantize(MONEY_SCALE, rounding=ROUND_HALF_UP)


def parse_decimal_input(value: Any, field_name: str) -> Decimal:
    if isinstance(value, Decimal):
        return value
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, float):
        return Decimal(str(value))
    raise ValueError(f"{field_name} must be provided as a JSON number")


def parse_budget_alert_thresholds(raw: str) -> list[Decimal]:
    thresholds: list[Decimal] = []
    for item in raw.split(","):
        candidate = item.strip()
        if not candidate:
            continue
        try:
            threshold = normalize_money(Decimal(candidate))
        except InvalidOperation as exc:
            raise RuntimeError("PAYMENT_FIREWALL_BUDGET_ALERT_THRESHOLDS must contain decimal values") from exc
        if threshold <= Decimal("0") or threshold > Decimal("1"):
            raise RuntimeError("PAYMENT_FIREWALL_BUDGET_ALERT_THRESHOLDS values must be within (0, 1]")
        thresholds.append(threshold)
    if not thresholds:
        return [Decimal("0.500000"), Decimal("0.800000"), Decimal("1.000000")]
    return sorted(set(thresholds))


def parse_budget_alert_threshold_values(values: Any) -> list[Decimal]:
    if isinstance(values, str):
        return parse_budget_alert_thresholds(values)
    if isinstance(values, list):
        return parse_budget_alert_thresholds(",".join(str(item) for item in values))
    return [Decimal("0.500000"), Decimal("0.800000"), Decimal("1.000000")]


def parse_x402_provider_keys(raw: str) -> dict[str, str]:
    keys: dict[str, str] = {}
    for item in raw.split(","):
        candidate = item.strip()
        if not candidate:
            continue
        if ":" not in candidate:
            raise RuntimeError("PAYMENT_FIREWALL_X402_PROVIDER_KEYS entries must use key_id:secret format")
        key_id, secret = candidate.split(":", 1)
        key_id = key_id.strip()
        secret = secret.strip()
        if not key_id or not secret:
            raise RuntimeError("PAYMENT_FIREWALL_X402_PROVIDER_KEYS entries must include both key_id and secret")
        keys[key_id] = secret
    if not keys:
        return {"default": "dev-x402-provider-secret"}
    return keys


def parse_x402_network_recipient_addresses(
    raw: str | None,
    *,
    supported_networks: list[str],
    default_pay_to: str,
) -> dict[str, str]:
    recipient_addresses: dict[str, str] = {network: default_pay_to for network in supported_networks}
    if raw is None or not raw.strip():
        return recipient_addresses
    for item in raw.split(","):
        candidate = item.strip()
        if not candidate:
            continue
        if ":" not in candidate:
            raise RuntimeError("PAYMENT_FIREWALL_X402_NETWORK_RECIPIENTS entries must use network:address format")
        network, address = candidate.split(":", 1)
        network = network.strip()
        address = address.strip()
        if not network or not address:
            raise RuntimeError("PAYMENT_FIREWALL_X402_NETWORK_RECIPIENTS entries must include both network and address")
        if network not in supported_networks:
            raise RuntimeError("PAYMENT_FIREWALL_X402_NETWORK_RECIPIENTS network must be in PAYMENT_FIREWALL_X402_SUPPORTED_NETWORKS")
        recipient_addresses[network] = address
    return recipient_addresses


def parse_ap2_signer_keys(raw: str) -> dict[str, str]:
    keys: dict[str, str] = {}
    for item in raw.split(","):
        candidate = item.strip()
        if not candidate:
            continue
        if ":" not in candidate:
            raise RuntimeError("PAYMENT_FIREWALL_AP2_SIGNER_KEYS entries must use key_id:secret format")
        key_id, secret = candidate.split(":", 1)
        key_id = key_id.strip()
        secret = secret.strip()
        if not key_id or not secret:
            raise RuntimeError("PAYMENT_FIREWALL_AP2_SIGNER_KEYS entries must include both key_id and secret")
        keys[key_id] = secret
    if not keys:
        return {"default": "dev-ap2-shared-secret"}
    return keys


def parse_optional_runtime_url(raw: str | None, *, env_name: str) -> str | None:
    if raw is None:
        return None
    candidate = raw.strip()
    if not candidate:
        return None
    parts = urlsplit(candidate)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise RuntimeError(f"{env_name} must be an absolute http or https URL")
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "", parts.query or "", parts.fragment or ""))


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
        return {"default": "dev-insecure-infra-identity-secret"}
    return keys
