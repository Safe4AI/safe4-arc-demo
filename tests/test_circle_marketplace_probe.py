from __future__ import annotations

import json
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Sequence

import pytest

from scripts.probe_circle_marketplace import (
    ARC_TESTNET_USDC,
    CliResult,
    HARD_MAX_AMOUNT_USDC,
    ProbeFailure,
    REQUIRED_NETWORK,
    _validate_read_only_command,
    run_marketplace_probe,
)


WALLET = "0x1111111111111111111111111111111111111111"
SELLER = "0x2222222222222222222222222222222222222222"
RESOURCE = "https://service.example/research"


def search_item(
    *,
    network: str = REQUIRED_NETWORK,
    gateway: bool = True,
    amount: str = "2400",
    pay_to: str = SELLER,
    asset: str = ARC_TESTNET_USDC,
    include_schema: bool = True,
) -> dict[str, object]:
    metadata: dict[str, object] = {
        "supportsCircleGateway": gateway,
        "description": "Generate a structured company research result.",
        "output": {
            "type": "object",
            "properties": {
                "result": {"type": "string"},
            },
        },
    }
    if include_schema:
        metadata["input"] = {
            "type": "http",
            "method": "POST",
            "body": {
                "type": "object",
                "required": ["company"],
                "properties": {"company": {"type": "string"}},
            },
        }
    return {
        "resource": RESOURCE,
        "accepts": [
            {
                "scheme": "exact",
                "network": network,
                "asset": asset,
                "payTo": pay_to,
                "amount": amount,
            }
        ],
        "metadata": metadata,
    }


def search_page(
    items: list[dict[str, object]],
    *,
    limit: int = 50,
    offset: int = 0,
    total: int | None = None,
) -> str:
    return json.dumps(
        {
            "data": {
                "items": items,
                "pagination": {
                    "limit": limit,
                    "offset": offset,
                    "total": len(items) if total is None else total,
                },
            }
        }
    )


def inspect_output(
    *,
    chain: str = "Arc Testnet",
    price: object = "$0.0024 USDC",
    scheme: str = "GatewayWalletBatched",
    http_status: int = 402,
) -> str:
    return json.dumps(
        {
            "data": {
                "status": "payment_required",
                "httpStatus": http_status,
                "price": price,
                "scheme": scheme,
                "chains": [chain],
            }
        }
    )


def estimate_output(
    *,
    chain: str = "Arc Testnet",
    price: str = "$0.0024 USDC",
    scheme: str = "GatewayWalletBatched",
    seller: str = SELLER,
) -> str:
    return json.dumps(
        {
            "data": {
                "price": price,
                "chain": chain,
                "scheme": scheme,
                "seller": seller,
            }
        }
    )


@dataclass
class FakeRunner:
    results: list[CliResult]
    calls: list[list[str]] = field(default_factory=list)

    def __call__(self, args: Sequence[str], timeout_seconds: int) -> CliResult:
        self.calls.append(list(args))
        assert timeout_seconds > 0
        if not self.results:
            raise AssertionError(f"unexpected CLI call: {args}")
        return self.results.pop(0)


def result(stdout: str, *, returncode: int = 0, stderr: str = "") -> CliResult:
    return CliResult(returncode=returncode, stdout=stdout, stderr=stderr)


def admitted_runner() -> FakeRunner:
    return FakeRunner(
        [
            result(search_page([search_item()])),
            result(inspect_output()),
            result(estimate_output()),
            result(estimate_output()),
        ]
    )


def test_exact_arc_gateway_candidate_is_admitted_after_two_estimates() -> None:
    runner = admitted_runner()

    report = run_marketplace_probe(wallet_address=WALLET, runner=runner)

    assert report["decision"] == "GO"
    assert report["summary"]["services_scanned"] == 1
    assert report["summary"]["admitted_candidates"] == 1
    candidate = report["candidates"][0]
    assert candidate["network"] == REQUIRED_NETWORK
    assert candidate["price_usdc"] == "0.002400"
    assert candidate["recipient"] == SELLER
    assert candidate["estimate"]["runs"] == 2
    pay_calls = [call for call in runner.calls if call[:2] == ["services", "pay"]]
    assert len(pay_calls) == 2
    for call in pay_calls:
        assert "--estimate" in call
        assert call[call.index("--chain") + 1] == "ARC-TESTNET"
        assert Decimal(call[call.index("--max-amount") + 1]) <= Decimal("0.01")
    assert all(call[:2] != ["gateway", "deposit"] for call in runner.calls)


@pytest.mark.parametrize(
    "args",
    [
        [
            "services",
            "pay",
            RESOURCE,
            "--address",
            WALLET,
            "--chain",
            "ARC-TESTNET",
            "--max-amount",
            "0.01",
            "--output",
            "json",
        ],
        [
            "services",
            "pay",
            RESOURCE,
            "--address",
            WALLET,
            "--chain",
            "ETH",
            "--max-amount",
            "0.01",
            "--estimate",
            "--output",
            "json",
        ],
        [
            "services",
            "pay",
            RESOURCE,
            "--address",
            WALLET,
            "--chain",
            "ARC-TESTNET",
            "--max-amount",
            "0.010001",
            "--estimate",
            "--output",
            "json",
        ],
        [
            "gateway",
            "deposit",
            "--address",
            WALLET,
            "--chain",
            "ARC-TESTNET",
        ],
        [
            "services",
            "pay",
            RESOURCE,
            "--address",
            WALLET,
            "--chain",
            "ARC-TESTNET",
            "--chain",
            "ETH",
            "--max-amount",
            "0.01",
            "--estimate",
            "--output",
            "json",
        ],
        [
            "services",
            "pay",
            RESOURCE,
            "--address",
            WALLET,
            "--chain",
            "ARC-TESTNET",
            "--max-amount",
            "0.01",
            "--max-amount",
            "1",
            "--estimate",
            "--output",
            "json",
        ],
        [
            "services",
            "pay",
            RESOURCE,
            "--address",
            "--estimate",
            "--chain",
            "ARC-TESTNET",
            "--max-amount",
            "0.01",
            "--output",
            "json",
        ],
        [
            "services",
            "pay",
            RESOURCE,
            "--address",
            WALLET,
            "--chain",
            "ARC-TESTNET",
            "--max-amount",
            "0.01",
            "--estimate",
            "--estimate",
            "--output",
            "json",
        ],
    ],
)
def test_command_guard_rejects_mutation_wrong_chain_and_over_cap(
    args: list[str],
) -> None:
    with pytest.raises(ProbeFailure):
        _validate_read_only_command(args, max_amount=HARD_MAX_AMOUNT_USDC)


def test_structured_inspect_price_is_admitted_when_amount_and_display_agree() -> None:
    runner = FakeRunner(
        [
            result(search_page([search_item()])),
            result(
                inspect_output(
                    price={
                        "amount": "2400",
                        "formatted": "$0.0024 USDC",
                    }
                )
            ),
            result(estimate_output()),
            result(estimate_output()),
        ]
    )

    report = run_marketplace_probe(wallet_address=WALLET, runner=runner)

    assert report["decision"] == "GO"
    assert report["candidates"][0]["inspect"]["price_usdc"] == "0.002400"


def test_structured_inspect_price_fails_when_amount_and_display_disagree() -> None:
    runner = FakeRunner(
        [
            result(search_page([search_item()])),
            result(
                inspect_output(
                    price={
                        "amount": "2400",
                        "formatted": "$0.0025 USDC",
                    }
                )
            ),
        ]
    )

    report = run_marketplace_probe(wallet_address=WALLET, runner=runner)

    assert report["decision"] == "NO_GO"
    assert report["candidates"][0]["reason_codes"] == [
        "INSPECT_PRICE_INCONSISTENT"
    ]


def test_search_paginates_using_structured_limit_offset_and_total() -> None:
    first_page = [search_item(network="eip155:8453") for _ in range(50)]
    for index, item in enumerate(first_page):
        item["resource"] = f"https://service.example/base/{index}"
    final_item = search_item(network="eip155:5042")
    final_item["resource"] = "https://service.example/wrong-arc"
    runner = FakeRunner(
        [
            result(search_page(first_page, limit=50, offset=0, total=51)),
            result(search_page([final_item], limit=50, offset=50, total=51)),
        ]
    )

    report = run_marketplace_probe(wallet_address=WALLET, runner=runner)

    assert report["decision"] == "NO_GO"
    assert report["summary"]["services_scanned"] == 51
    assert report["summary"]["near_match_wrong_arc_network"] == 1
    assert report["summary"]["exact_arc_gateway_services"] == 0
    assert runner.calls[1][runner.calls[1].index("--offset") + 1] == "50"


def test_near_match_chain_5042_is_rejected_without_inspect_or_estimate() -> None:
    runner = FakeRunner(
        [result(search_page([search_item(network="eip155:5042")]))]
    )

    report = run_marketplace_probe(wallet_address=WALLET, runner=runner)

    assert report["decision"] == "NO_GO"
    assert report["summary"]["near_match_wrong_arc_network"] == 1
    assert len(runner.calls) == 1


def test_identical_duplicate_resource_is_counted_and_inspected_once() -> None:
    item = search_item()
    runner = FakeRunner(
        [
            result(search_page([item, item])),
            result(inspect_output()),
            result(estimate_output()),
            result(estimate_output()),
        ]
    )

    report = run_marketplace_probe(wallet_address=WALLET, runner=runner)

    assert report["decision"] == "GO"
    assert report["summary"]["duplicate_resources"] == 1
    assert report["summary"]["exact_arc_gateway_services"] == 1
    assert len([call for call in runner.calls if call[:2] == ["services", "inspect"]]) == 1


def test_conflicting_duplicate_resource_is_rejected_without_inspection() -> None:
    first = search_item()
    second = search_item(amount="2500")
    runner = FakeRunner([result(search_page([first, second]))])

    report = run_marketplace_probe(wallet_address=WALLET, runner=runner)

    assert report["decision"] == "NO_GO"
    assert report["candidates"][0]["reason_codes"] == [
        "AMBIGUOUS_DUPLICATE_RESOURCE"
    ]
    assert len(runner.calls) == 1


@pytest.mark.parametrize("fallback_chain", ["Ethereum", "eip155:1", "Arc"])
def test_estimate_chain_fallback_is_rejected(fallback_chain: str) -> None:
    runner = FakeRunner(
        [
            result(search_page([search_item()])),
            result(inspect_output()),
            result(estimate_output(chain=fallback_chain)),
        ]
    )

    report = run_marketplace_probe(wallet_address=WALLET, runner=runner)

    assert report["decision"] == "NO_GO"
    assert report["candidates"][0]["reason_codes"] == ["ESTIMATE_CHAIN_FALLBACK"]


@pytest.mark.parametrize(
    ("mutator", "expected_code"),
    [
        (lambda item: item.pop("resource"), "CANDIDATE_RESOURCE_INVALID"),
        (
            lambda item: item["metadata"].pop("input"),
            "INPUT_SCHEMA_MISSING",
        ),
        (
            lambda item: item["metadata"].pop("description"),
            "SERVICE_DESCRIPTION_MISSING",
        ),
        (
            lambda item: item["metadata"].pop("output"),
            "OUTPUT_SCHEMA_MISSING",
        ),
        (
            lambda item: item["accepts"][0].pop("payTo"),
            "RECIPIENT_MISSING",
        ),
        (
            lambda item: item["accepts"][0].pop("amount"),
            "PRICE_MISSING",
        ),
    ],
)
def test_missing_candidate_fields_fail_closed(mutator, expected_code: str) -> None:
    item = search_item()
    mutator(item)
    runner = FakeRunner([result(search_page([item]))])

    report = run_marketplace_probe(wallet_address=WALLET, runner=runner)

    assert report["decision"] == "NO_GO"
    assert report["candidates"][0]["reason_codes"] == [expected_code]
    assert len(runner.calls) == 1


def test_search_malformed_json_returns_sanitized_no_go() -> None:
    runner = FakeRunner(
        [result("not-json", stderr="session=/secret/path auth=bearer-token")]
    )

    report = run_marketplace_probe(wallet_address=WALLET, runner=runner)

    encoded = json.dumps(report)
    assert report["decision"] == "NO_GO"
    assert report["reason_codes"] == ["SEARCH_OUTPUT_MALFORMED"]
    assert "bearer-token" not in encoded
    assert "/secret/path" not in encoded


def test_cli_error_never_copies_stderr_into_report() -> None:
    runner = FakeRunner(
        [
            result(
                "",
                returncode=1,
                stderr="email=owner@example.com session=top-secret",
            )
        ]
    )

    report = run_marketplace_probe(wallet_address=WALLET, runner=runner)

    encoded = json.dumps(report)
    assert report["reason_codes"] == ["SEARCH_CLI_FAILED"]
    assert "owner@example.com" not in encoded
    assert "top-secret" not in encoded


@pytest.mark.parametrize(
    ("outputs", "expected_code"),
    [
        (
            [
                result(search_page([search_item()])),
                result("{not-json"),
            ],
            "INSPECT_OUTPUT_MALFORMED",
        ),
        (
            [
                result(search_page([search_item()])),
                result(inspect_output()),
                result("[]"),
            ],
            "ESTIMATE_OUTPUT_MALFORMED",
        ),
        (
            [
                result(search_page([search_item()])),
                result("", returncode=1, stderr="session=inspect-secret"),
            ],
            "INSPECT_CLI_FAILED",
        ),
        (
            [
                result(search_page([search_item()])),
                result(inspect_output()),
                result("", returncode=1, stderr="session=estimate-secret"),
            ],
            "ESTIMATE_CLI_FAILED",
        ),
    ],
)
def test_inspect_and_estimate_failures_are_sanitized(
    outputs: list[CliResult],
    expected_code: str,
) -> None:
    runner = FakeRunner(outputs)

    report = run_marketplace_probe(wallet_address=WALLET, runner=runner)

    encoded = json.dumps(report)
    assert report["decision"] == "NO_GO"
    assert report["candidates"][0]["reason_codes"] == [expected_code]
    assert "inspect-secret" not in encoded
    assert "estimate-secret" not in encoded


def test_pagination_total_change_fails_closed() -> None:
    first_page = [search_item(network="eip155:8453") for _ in range(50)]
    for index, item in enumerate(first_page):
        item["resource"] = f"https://service.example/base/{index}"
    runner = FakeRunner(
        [
            result(search_page(first_page, offset=0, total=51)),
            result(search_page([], offset=50, total=52)),
        ]
    )

    report = run_marketplace_probe(wallet_address=WALLET, runner=runner)

    assert report["decision"] == "NO_GO"
    assert report["reason_codes"] == ["SEARCH_PAGINATION_CHANGED"]


@pytest.mark.parametrize(
    ("stage", "outputs", "expected_code"),
    [
        (
            "inspect",
            [
                result(search_page([search_item()])),
                result(inspect_output(price="$0.010001 USDC")),
            ],
            "INSPECT_PRICE_OVER_CAP",
        ),
        (
            "estimate",
            [
                result(search_page([search_item(amount="10000")])),
                result(inspect_output(price="$0.01 USDC")),
                result(estimate_output(price="$0.010001 USDC")),
            ],
            "ESTIMATE_PRICE_OVER_CAP",
        ),
    ],
)
def test_over_cap_price_is_rejected(
    stage: str,
    outputs: list[CliResult],
    expected_code: str,
) -> None:
    runner = FakeRunner(outputs)

    report = run_marketplace_probe(wallet_address=WALLET, runner=runner)

    assert stage
    assert report["decision"] == "NO_GO"
    assert report["candidates"][0]["reason_codes"] == [expected_code]


def test_search_price_over_cap_is_rejected_before_network_calls() -> None:
    runner = FakeRunner(
        [result(search_page([search_item(amount="10001")]))]
    )

    report = run_marketplace_probe(wallet_address=WALLET, runner=runner)

    assert report["candidates"][0]["reason_codes"] == ["PRICE_OVER_CAP"]
    assert len(runner.calls) == 1


def test_estimate_seller_change_is_rejected() -> None:
    runner = FakeRunner(
        [
            result(search_page([search_item()])),
            result(inspect_output()),
            result(
                estimate_output(
                    seller="0x3333333333333333333333333333333333333333"
                )
            ),
        ]
    )

    report = run_marketplace_probe(wallet_address=WALLET, runner=runner)

    assert report["candidates"][0]["reason_codes"] == ["ESTIMATE_SELLER_CHANGED"]


def test_estimate_must_be_repeatable() -> None:
    runner = FakeRunner(
        [
            result(search_page([search_item()])),
            result(inspect_output()),
            result(estimate_output()),
            result(estimate_output(chain="ARC-TESTNET", price="$0.0024 USDC")),
        ]
    )
    # Make the second otherwise-valid estimate observably different without
    # changing the bound price or recipient.
    second = json.loads(runner.results[-1].stdout)
    second["data"]["chain"] = "eip155:5042002"
    runner.results[-1] = result(json.dumps(second))

    report = run_marketplace_probe(wallet_address=WALLET, runner=runner)

    assert report["candidates"][0]["reason_codes"] == ["ESTIMATE_NOT_REPEATABLE"]


def test_non_gateway_candidate_is_never_inspected() -> None:
    runner = FakeRunner(
        [result(search_page([search_item(gateway=False)]))]
    )

    report = run_marketplace_probe(wallet_address=WALLET, runner=runner)

    assert report["summary"]["exact_arc_services"] == 1
    assert report["summary"]["exact_arc_gateway_services"] == 0
    assert len(runner.calls) == 1


def test_wrong_arc_usdc_asset_is_rejected() -> None:
    runner = FakeRunner(
        [
            result(
                search_page(
                    [
                        search_item(
                            asset="0x3333333333333333333333333333333333333333"
                        )
                    ]
                )
            )
        ]
    )

    report = run_marketplace_probe(wallet_address=WALLET, runner=runner)

    assert report["candidates"][0]["reason_codes"] == [
        "ARC_USDC_ASSET_MISMATCH"
    ]


def test_max_amount_above_hard_cap_never_invokes_cli() -> None:
    runner = FakeRunner([])

    report = run_marketplace_probe(
        wallet_address=WALLET,
        runner=runner,
        max_amount=Decimal("0.010001"),
    )

    assert report["reason_codes"] == ["MAX_AMOUNT_UNSAFE"]
    assert runner.calls == []
