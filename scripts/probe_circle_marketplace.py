from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Protocol, Sequence
from urllib.parse import urlsplit


REPORT_SCHEMA = "safe4-circle-marketplace-admission-v1"
REQUIRED_NETWORK = "eip155:5042002"
REJECTED_NEAR_MATCH_NETWORK = "eip155:5042"
REQUESTED_CHAIN = "ARC-TESTNET"
ARC_TESTNET_USDC = "0x3600000000000000000000000000000000000000"
HARD_MAX_AMOUNT_USDC = Decimal("0.01")
USDC_SCALE = Decimal("1000000")
PAGE_SIZE = 50
MAX_PAGES = 20
MAX_CANDIDATES = 10
ESTIMATE_RUNS = 2
CLI_TIMEOUT_SECONDS = 45
EVM_ADDRESS_PATTERN = re.compile(r"^0x[0-9a-fA-F]{40}$")
BASE_UNITS_PATTERN = re.compile(r"^[0-9]+$")
DISPLAY_PRICE_PATTERN = re.compile(
    r"^\$?(?P<amount>(?:0|[1-9][0-9]*)(?:\.[0-9]{1,6})?)\s+USDC$",
    re.IGNORECASE,
)
GATEWAY_SCHEME = "GatewayWalletBatched"
EXPLICIT_ARC_CHAIN_LABELS = {
    REQUIRED_NETWORK.casefold(),
    REQUESTED_CHAIN.casefold(),
    "Arc Testnet".casefold(),
}


class ProbeFailure(Exception):
    """A sanitized, non-secret-bearing probe failure."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class CliResult:
    returncode: int
    stdout: str
    stderr: str = ""


class CircleCliRunner(Protocol):
    def __call__(self, args: Sequence[str], timeout_seconds: int) -> CliResult:
        ...


@dataclass(frozen=True)
class SearchTerms:
    resource: str
    recipient: str
    price_usdc: Decimal
    input_method: str


@dataclass(frozen=True)
class EstimateTerms:
    price_usdc: Decimal
    chain: str
    scheme: str
    seller: str


def _decimal_text(value: Decimal) -> str:
    return format(value.quantize(Decimal("0.000001")), "f")


def _valid_address(value: Any) -> bool:
    return isinstance(value, str) and EVM_ADDRESS_PATTERN.fullmatch(value) is not None


def _valid_https_url(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlsplit(value)
    return parsed.scheme == "https" and bool(parsed.netloc) and not parsed.username and not parsed.password


def _parse_json_document(raw: str, *, code: str) -> dict[str, Any]:
    try:
        document = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ProbeFailure(code) from exc
    if not isinstance(document, dict):
        raise ProbeFailure(code)
    return document


def _parse_display_price(value: Any, *, code: str) -> Decimal:
    if not isinstance(value, str):
        raise ProbeFailure(code)
    match = DISPLAY_PRICE_PATTERN.fullmatch(value.strip())
    if match is None:
        raise ProbeFailure(code)
    try:
        amount = Decimal(match.group("amount"))
    except InvalidOperation as exc:
        raise ProbeFailure(code) from exc
    if amount <= 0 or amount.as_tuple().exponent < -6:
        raise ProbeFailure(code)
    return amount


def _parse_inspect_price(value: Any) -> Decimal:
    if isinstance(value, str):
        return _parse_display_price(value, code="INSPECT_PRICE_MISSING")
    if not isinstance(value, dict) or set(value) != {"amount", "formatted"}:
        raise ProbeFailure("INSPECT_PRICE_MISSING")
    base_units_price = _parse_base_units(
        value.get("amount"),
        code="INSPECT_PRICE_MISSING",
    )
    formatted_price = _parse_display_price(
        value.get("formatted"),
        code="INSPECT_PRICE_MISSING",
    )
    if base_units_price != formatted_price:
        raise ProbeFailure("INSPECT_PRICE_INCONSISTENT")
    return base_units_price


def _parse_base_units(value: Any, *, code: str) -> Decimal:
    if not isinstance(value, str) or BASE_UNITS_PATTERN.fullmatch(value) is None:
        raise ProbeFailure(code)
    amount_units = int(value)
    if amount_units <= 0:
        raise ProbeFailure(code)
    return Decimal(amount_units) / USDC_SCALE


def _require_data(document: dict[str, Any], *, code: str) -> dict[str, Any]:
    data = document.get("data")
    if not isinstance(data, dict):
        raise ProbeFailure(code)
    return data


def _is_explicit_arc_chain(value: Any) -> bool:
    return isinstance(value, str) and value.strip().casefold() in EXPLICIT_ARC_CHAIN_LABELS


def _is_gateway_scheme(value: Any) -> bool:
    return isinstance(value, str) and value.strip() == GATEWAY_SCHEME


def default_circle_cli_runner(args: Sequence[str], timeout_seconds: int) -> CliResult:
    executable = shutil.which("circle.cmd") or shutil.which("circle")
    if executable is None:
        return CliResult(returncode=127, stdout="", stderr="")
    try:
        completed = subprocess.run(
            [executable, *args],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        return CliResult(returncode=124, stdout="", stderr="")
    return CliResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        # Deliberately do not propagate CLI stderr. It can contain local paths,
        # debug details, or future session metadata.
        stderr="",
    )


def _validate_read_only_command(args: Sequence[str], *, max_amount: Decimal) -> None:
    normalized = list(args)
    if normalized[:2] == ["services", "search"]:
        allowed = {"--limit", "--offset", "--output"}
    elif normalized[:2] == ["services", "inspect"]:
        allowed = {"--output"}
    elif normalized[:2] == ["services", "pay"]:
        allowed = {"--address", "--chain", "--max-amount", "--estimate", "--output"}
        required = {"--address", "--chain", "--max-amount", "--estimate", "--output"}
        if any(normalized.count(flag) != 1 for flag in required):
            raise ProbeFailure("UNSAFE_PAY_COMMAND")
        try:
            chain = normalized[normalized.index("--chain") + 1]
            cap_raw = normalized[normalized.index("--max-amount") + 1]
        except (ValueError, IndexError) as exc:
            raise ProbeFailure("UNSAFE_PAY_COMMAND") from exc
        try:
            cap = Decimal(cap_raw)
        except InvalidOperation as exc:
            raise ProbeFailure("UNSAFE_PAY_COMMAND") from exc
        if chain != REQUESTED_CHAIN or cap <= 0 or cap > HARD_MAX_AMOUNT_USDC or cap != max_amount:
            raise ProbeFailure("UNSAFE_PAY_COMMAND")
    else:
        raise ProbeFailure("UNSAFE_CLI_COMMAND")

    index = 2
    if normalized[:2] in (["services", "inspect"], ["services", "pay"]):
        if len(normalized) <= 2:
            raise ProbeFailure("UNSAFE_CLI_COMMAND")
        if normalized[2].startswith("--"):
            raise ProbeFailure("UNSAFE_CLI_COMMAND")
        index = 3
    seen: set[str] = set()
    while index < len(normalized):
        token = normalized[index]
        if not token.startswith("--"):
            raise ProbeFailure("UNSAFE_CLI_COMMAND")
        if token not in allowed:
            raise ProbeFailure("UNSAFE_CLI_COMMAND")
        if token in seen:
            raise ProbeFailure("UNSAFE_CLI_COMMAND")
        seen.add(token)
        if token in {"--estimate"}:
            index += 1
            continue
        if index + 1 >= len(normalized):
            raise ProbeFailure("UNSAFE_CLI_COMMAND")
        if normalized[index + 1].startswith("--"):
            raise ProbeFailure("UNSAFE_CLI_COMMAND")
        index += 2


def _run_json(
    runner: CircleCliRunner,
    args: Sequence[str],
    *,
    max_amount: Decimal,
    failure_code: str,
    malformed_code: str,
) -> dict[str, Any]:
    _validate_read_only_command(args, max_amount=max_amount)
    result = runner(args, CLI_TIMEOUT_SECONDS)
    if result.returncode != 0:
        raise ProbeFailure(failure_code)
    return _parse_json_document(result.stdout, code=malformed_code)


def _parse_search_page(
    document: dict[str, Any],
    *,
    expected_limit: int,
    expected_offset: int,
) -> tuple[list[dict[str, Any]], int]:
    data = _require_data(document, code="SEARCH_OUTPUT_MALFORMED")
    items = data.get("items")
    pagination = data.get("pagination")
    if not isinstance(items, list) or not isinstance(pagination, dict):
        raise ProbeFailure("SEARCH_OUTPUT_MALFORMED")
    limit = pagination.get("limit")
    offset = pagination.get("offset")
    total = pagination.get("total")
    if (
        isinstance(limit, bool)
        or isinstance(offset, bool)
        or isinstance(total, bool)
        or not isinstance(limit, int)
        or not isinstance(offset, int)
        or not isinstance(total, int)
        or limit != expected_limit
        or offset != expected_offset
        or total < 0
        or len(items) > expected_limit
    ):
        raise ProbeFailure("SEARCH_PAGINATION_MALFORMED")
    if any(not isinstance(item, dict) for item in items):
        raise ProbeFailure("SEARCH_OUTPUT_MALFORMED")
    return items, total


def _search_all(
    runner: CircleCliRunner,
    *,
    max_amount: Decimal,
) -> list[dict[str, Any]]:
    all_items: list[dict[str, Any]] = []
    expected_total: int | None = None

    for page_index in range(MAX_PAGES):
        offset = page_index * PAGE_SIZE
        document = _run_json(
            runner,
            [
                "services",
                "search",
                "--limit",
                str(PAGE_SIZE),
                "--offset",
                str(offset),
                "--output",
                "json",
            ],
            max_amount=max_amount,
            failure_code="SEARCH_CLI_FAILED",
            malformed_code="SEARCH_OUTPUT_MALFORMED",
        )
        items, total = _parse_search_page(
            document,
            expected_limit=PAGE_SIZE,
            expected_offset=offset,
        )
        if expected_total is None:
            expected_total = total
            if expected_total > PAGE_SIZE * MAX_PAGES:
                raise ProbeFailure("SEARCH_RESULT_LIMIT_EXCEEDED")
        elif total != expected_total:
            raise ProbeFailure("SEARCH_PAGINATION_CHANGED")

        all_items.extend(items)

        if len(all_items) >= total:
            if len(all_items) != total:
                raise ProbeFailure("SEARCH_PAGINATION_MALFORMED")
            return all_items
        if not items:
            raise ProbeFailure("SEARCH_PAGINATION_TRUNCATED")

    raise ProbeFailure("SEARCH_RESULT_LIMIT_EXCEEDED")


def _candidate_search_terms(item: dict[str, Any], *, max_amount: Decimal) -> SearchTerms:
    resource = item.get("resource")
    if not _valid_https_url(resource):
        raise ProbeFailure("CANDIDATE_RESOURCE_INVALID")

    metadata = item.get("metadata")
    accepts = item.get("accepts")
    if not isinstance(metadata, dict) or not isinstance(accepts, list):
        raise ProbeFailure("CANDIDATE_OUTPUT_MALFORMED")
    if metadata.get("supportsCircleGateway") is not True:
        raise ProbeFailure("GATEWAY_NOT_SUPPORTED")

    input_schema = metadata.get("input")
    if not isinstance(input_schema, dict) or not input_schema:
        raise ProbeFailure("INPUT_SCHEMA_MISSING")
    input_method = input_schema.get("method")
    if not isinstance(input_method, str) or input_method.strip().upper() not in {
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
    }:
        raise ProbeFailure("INPUT_SCHEMA_MISSING")
    description = metadata.get("description")
    if not isinstance(description, str) or not description.strip():
        raise ProbeFailure("SERVICE_DESCRIPTION_MISSING")
    output_schema = metadata.get("output")
    if not isinstance(output_schema, dict) or not output_schema:
        raise ProbeFailure("OUTPUT_SCHEMA_MISSING")
    output_type = output_schema.get("type")
    if output_type not in {
        "object",
        "array",
        "string",
        "number",
        "integer",
        "boolean",
    }:
        raise ProbeFailure("OUTPUT_SCHEMA_MISSING")
    if output_type == "object":
        properties = output_schema.get("properties")
        if not isinstance(properties, dict) or not properties:
            raise ProbeFailure("OUTPUT_SCHEMA_MISSING")
    if output_type == "array":
        items_schema = output_schema.get("items")
        if not isinstance(items_schema, dict) or not items_schema:
            raise ProbeFailure("OUTPUT_SCHEMA_MISSING")

    exact_accepts = [
        accept
        for accept in accepts
        if isinstance(accept, dict) and accept.get("network") == REQUIRED_NETWORK
    ]
    if len(exact_accepts) != 1:
        raise ProbeFailure(
            "EXACT_ARC_TERMS_MISSING" if not exact_accepts else "AMBIGUOUS_ARC_TERMS"
        )
    accept = exact_accepts[0]
    recipient = accept.get("payTo")
    if not _valid_address(recipient):
        raise ProbeFailure("RECIPIENT_MISSING")
    asset = accept.get("asset")
    if not isinstance(asset, str) or asset.casefold() != ARC_TESTNET_USDC.casefold():
        raise ProbeFailure("ARC_USDC_ASSET_MISMATCH")
    price = _parse_base_units(accept.get("amount"), code="PRICE_MISSING")
    if price > max_amount:
        raise ProbeFailure("PRICE_OVER_CAP")

    return SearchTerms(
        resource=resource,
        recipient=recipient,
        price_usdc=price,
        input_method=input_method.strip().upper(),
    )


def _parse_inspect(
    document: dict[str, Any],
    *,
    expected: SearchTerms,
    max_amount: Decimal,
) -> dict[str, str]:
    data = _require_data(document, code="INSPECT_OUTPUT_MALFORMED")
    status_value = data.get("status")
    http_status = data.get("httpStatus")
    scheme = data.get("scheme")
    chains = data.get("chains")
    if not isinstance(status_value, str) or not status_value.strip():
        raise ProbeFailure("INSPECT_STATUS_MISSING")
    if isinstance(http_status, bool) or http_status != 402:
        raise ProbeFailure("INSPECT_NOT_PAYMENT_REQUIRED")
    if not _is_gateway_scheme(scheme):
        raise ProbeFailure("INSPECT_GATEWAY_SCHEME_MISMATCH")
    if not isinstance(chains, list) or not any(_is_explicit_arc_chain(chain) for chain in chains):
        raise ProbeFailure("INSPECT_ARC_CHAIN_MISSING")
    price = _parse_inspect_price(data.get("price"))
    if price > max_amount:
        raise ProbeFailure("INSPECT_PRICE_OVER_CAP")
    if price != expected.price_usdc:
        raise ProbeFailure("INSPECT_PRICE_CHANGED")
    return {
        "status": status_value.strip(),
        "http_status": "402",
        "price_usdc": _decimal_text(price),
        "scheme": scheme,
        "chain": REQUESTED_CHAIN,
    }


def _parse_estimate(
    document: dict[str, Any],
    *,
    expected: SearchTerms,
    max_amount: Decimal,
) -> EstimateTerms:
    data = _require_data(document, code="ESTIMATE_OUTPUT_MALFORMED")
    chain = data.get("chain")
    scheme = data.get("scheme")
    seller = data.get("seller")
    if not _is_explicit_arc_chain(chain):
        raise ProbeFailure("ESTIMATE_CHAIN_FALLBACK")
    if not _is_gateway_scheme(scheme):
        raise ProbeFailure("ESTIMATE_GATEWAY_SCHEME_MISMATCH")
    if not _valid_address(seller):
        raise ProbeFailure("ESTIMATE_SELLER_MISSING")
    if seller.casefold() != expected.recipient.casefold():
        raise ProbeFailure("ESTIMATE_SELLER_CHANGED")
    price = _parse_display_price(data.get("price"), code="ESTIMATE_PRICE_MISSING")
    if price > max_amount:
        raise ProbeFailure("ESTIMATE_PRICE_OVER_CAP")
    if price != expected.price_usdc:
        raise ProbeFailure("ESTIMATE_PRICE_CHANGED")
    return EstimateTerms(
        price_usdc=price,
        chain=chain.strip(),
        scheme=scheme.strip(),
        seller=seller,
    )


def _candidate_report(
    runner: CircleCliRunner,
    item: dict[str, Any],
    *,
    wallet_address: str,
    max_amount: Decimal,
) -> dict[str, Any]:
    resource = item.get("resource")
    safe_resource = resource if _valid_https_url(resource) else None
    report: dict[str, Any] = {
        "resource": safe_resource,
        "decision": "NO_GO",
        "reason_codes": [],
    }
    try:
        expected = _candidate_search_terms(item, max_amount=max_amount)
        inspect_document = _run_json(
            runner,
            ["services", "inspect", expected.resource, "--output", "json"],
            max_amount=max_amount,
            failure_code="INSPECT_CLI_FAILED",
            malformed_code="INSPECT_OUTPUT_MALFORMED",
        )
        inspect = _parse_inspect(
            inspect_document,
            expected=expected,
            max_amount=max_amount,
        )

        estimates: list[EstimateTerms] = []
        for _ in range(ESTIMATE_RUNS):
            estimate_document = _run_json(
                runner,
                [
                    "services",
                    "pay",
                    expected.resource,
                    "--address",
                    wallet_address,
                    "--chain",
                    REQUESTED_CHAIN,
                    "--max-amount",
                    str(max_amount),
                    "--estimate",
                    "--output",
                    "json",
                ],
                max_amount=max_amount,
                failure_code="ESTIMATE_CLI_FAILED",
                malformed_code="ESTIMATE_OUTPUT_MALFORMED",
            )
            estimates.append(
                _parse_estimate(
                    estimate_document,
                    expected=expected,
                    max_amount=max_amount,
                )
            )
        if len(set(estimates)) != 1:
            raise ProbeFailure("ESTIMATE_NOT_REPEATABLE")
        estimate = estimates[0]
        report.update(
            {
                "decision": "GO",
                "network": REQUIRED_NETWORK,
                "gateway": True,
                "recipient": expected.recipient,
                "price_usdc": _decimal_text(expected.price_usdc),
                "input_method": expected.input_method,
                "inspect": inspect,
                "estimate": {
                    "chain": estimate.chain,
                    "scheme": estimate.scheme,
                    "seller": estimate.seller,
                    "price_usdc": _decimal_text(estimate.price_usdc),
                    "runs": ESTIMATE_RUNS,
                },
            }
        )
    except ProbeFailure as exc:
        report["reason_codes"] = [exc.code]
    return report


def _empty_report(*, max_amount: Decimal) -> dict[str, Any]:
    return {
        "schema_version": REPORT_SCHEMA,
        "mode": "READ_ONLY_ESTIMATE",
        "decision": "NO_GO",
        "required_network": REQUIRED_NETWORK,
        "requested_chain": REQUESTED_CHAIN,
        "max_amount_usdc": _decimal_text(max_amount),
        "summary": {
            "services_scanned": 0,
            "gateway_services": 0,
            "near_match_wrong_arc_network": 0,
            "exact_arc_services": 0,
            "exact_arc_gateway_services": 0,
            "inspected_candidates": 0,
            "admitted_candidates": 0,
            "duplicate_resources": 0,
        },
        "reason_codes": [],
        "candidates": [],
        "safety": {
            "deposit_executed": False,
            "payment_executed": False,
            "payment_mode": "estimate_only",
            "allowed_cli_operations": [
                "services search",
                "services inspect",
                "services pay --estimate",
            ],
        },
    }


def run_marketplace_probe(
    *,
    wallet_address: str,
    runner: CircleCliRunner = default_circle_cli_runner,
    max_amount: Decimal = HARD_MAX_AMOUNT_USDC,
) -> dict[str, Any]:
    report = _empty_report(max_amount=max_amount)
    if not _valid_address(wallet_address):
        report["reason_codes"] = ["WALLET_ADDRESS_INVALID"]
        return report
    if max_amount <= 0 or max_amount > HARD_MAX_AMOUNT_USDC:
        report["reason_codes"] = ["MAX_AMOUNT_UNSAFE"]
        return report

    try:
        items = _search_all(runner, max_amount=max_amount)
    except ProbeFailure as exc:
        report["reason_codes"] = [exc.code]
        return report
    except Exception:
        report["reason_codes"] = ["PROBE_INTERNAL_ERROR"]
        return report

    gateway_services = 0
    near_match = 0
    exact_arc_services = 0
    candidates: list[dict[str, Any]] = []
    candidate_items: dict[str, dict[str, Any]] = {}
    candidate_fingerprints: dict[str, str] = {}
    ambiguous_candidate_resources: set[str] = set()
    malformed_candidate_count = 0
    resource_counts: dict[str, int] = {}

    for item in items:
        resource = item.get("resource")
        if isinstance(resource, str):
            resource_counts[resource] = resource_counts.get(resource, 0) + 1
        metadata = item.get("metadata")
        accepts = item.get("accepts")
        supports_gateway = (
            isinstance(metadata, dict)
            and metadata.get("supportsCircleGateway") is True
        )
        if supports_gateway:
            gateway_services += 1
        if not isinstance(accepts, list):
            continue
        networks = {
            accept.get("network")
            for accept in accepts
            if isinstance(accept, dict) and isinstance(accept.get("network"), str)
        }
        if REJECTED_NEAR_MATCH_NETWORK in networks:
            near_match += 1
        if REQUIRED_NETWORK in networks:
            exact_arc_services += 1
        if supports_gateway and REQUIRED_NETWORK in networks:
            if not isinstance(resource, str):
                candidates.append(
                    {
                        "resource": None,
                        "decision": "NO_GO",
                        "reason_codes": ["CANDIDATE_RESOURCE_INVALID"],
                    }
                )
                malformed_candidate_count += 1
                continue
            fingerprint = json.dumps(
                item,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            if resource in candidate_items:
                if candidate_fingerprints[resource] != fingerprint:
                    ambiguous_candidate_resources.add(resource)
                continue
            if len(candidate_items) >= MAX_CANDIDATES:
                report["reason_codes"] = ["CANDIDATE_LIMIT_EXCEEDED"]
                report["summary"].update(
                    {
                        "services_scanned": len(items),
                        "gateway_services": gateway_services,
                        "near_match_wrong_arc_network": near_match,
                        "exact_arc_services": exact_arc_services,
                        "exact_arc_gateway_services": len(candidate_items) + 1,
                        "duplicate_resources": sum(
                            count - 1
                            for count in resource_counts.values()
                            if count > 1
                        ),
                    }
                )
                return report
            candidate_items[resource] = item
            candidate_fingerprints[resource] = fingerprint

    for resource, item in candidate_items.items():
        if resource in ambiguous_candidate_resources:
            candidate = {
                "resource": resource,
                "decision": "NO_GO",
                "reason_codes": ["AMBIGUOUS_DUPLICATE_RESOURCE"],
            }
        else:
            candidate = _candidate_report(
                runner,
                item,
                wallet_address=wallet_address,
                max_amount=max_amount,
            )
        if candidate["reason_codes"] and candidate["reason_codes"][0] in {
            "CANDIDATE_RESOURCE_INVALID",
            "CANDIDATE_OUTPUT_MALFORMED",
            "INPUT_SCHEMA_MISSING",
            "SERVICE_DESCRIPTION_MISSING",
            "OUTPUT_SCHEMA_MISSING",
            "RECIPIENT_MISSING",
            "PRICE_MISSING",
            "AMBIGUOUS_DUPLICATE_RESOURCE",
        }:
            malformed_candidate_count += 1
        candidates.append(candidate)

    candidates.sort(key=lambda item: item.get("resource") or "")
    admitted = [candidate for candidate in candidates if candidate["decision"] == "GO"]
    report["candidates"] = candidates
    report["summary"] = {
        "services_scanned": len(items),
        "gateway_services": gateway_services,
        "near_match_wrong_arc_network": near_match,
        "exact_arc_services": exact_arc_services,
        "exact_arc_gateway_services": len(candidates),
        "inspected_candidates": len(candidates),
        "admitted_candidates": len(admitted),
        "duplicate_resources": sum(
            count - 1 for count in resource_counts.values() if count > 1
        ),
    }

    if admitted:
        report["decision"] = "GO"
        report["reason_codes"] = ["EXACT_ARC_GATEWAY_SERVICE_ADMITTED"]
    elif malformed_candidate_count:
        report["reason_codes"] = ["EXACT_ARC_CANDIDATE_MALFORMED"]
    else:
        report["reason_codes"] = ["NO_EXACT_ARC_GATEWAY_SERVICE"]
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only Circle Marketplace admission probe. It searches, inspects, "
            "and estimates; it never deposits or executes payment."
        )
    )
    parser.add_argument(
        "--wallet-address",
        required=True,
        help="Public Arc Testnet Agent Wallet address used only for payment estimation.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = run_marketplace_probe(wallet_address=args.wallet_address)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["decision"] == "GO" else 2


if __name__ == "__main__":
    raise SystemExit(main())
