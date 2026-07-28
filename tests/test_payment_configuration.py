from __future__ import annotations

import base64
from datetime import datetime, timezone
from decimal import Decimal
import json

import pytest

from app import main
from app.api.policy import PolicyDocumentModel


def _decode_provider_payload(token: str) -> dict[str, object]:
    _, payload_segment, _ = token.split(".", 2)
    padding = "=" * (-len(payload_segment) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_segment + padding))


def test_arc_testnet_is_the_default_x402_network() -> None:
    assert main.X402_SUPPORTED_NETWORKS[0] == "arc-testnet"
    assert (
        main.X402_NETWORK_RECIPIENT_ADDRESSES["arc-testnet"]
        == main.PAY_TO_ADDRESS
    )


def test_embedded_default_policy_validates_for_future_activation() -> None:
    policy = PolicyDocumentModel.model_validate(main.DEFAULT_POLICY_DOCUMENT)
    assert policy.version == main.POLICY_VERSION
    assert policy.controls.infrastructure_identity_policy is not None
    assert policy.controls.infrastructure_identity_policy.trusted_provider_names == []


def test_provider_receipt_builder_never_invents_settlement_proof() -> None:
    token = main.build_provider_receipt_token(
        receipt_id="receipt_without_observed_proof",
        pay_to="0x530271DA8CC4e44375f22ad9632bC61A55382f88",
        amount_paid=Decimal("0.010000"),
        currency="USDC",
        network="arc-testnet",
        shared_secret="test-only-secret",
        settled_at=datetime.now(timezone.utc).isoformat(),
    )

    payload = _decode_provider_payload(token)
    assert payload["settlement_proof_type"] == "transaction_hash"
    assert payload["settlement_proof_value"] is None
    assert "proof_receipt_without_observed_proof" not in token


@pytest.mark.parametrize("pay_to", ["", "wallet_address"])
def test_production_rejects_missing_or_placeholder_pay_to(
    monkeypatch: pytest.MonkeyPatch,
    pay_to: str,
) -> None:
    monkeypatch.setattr(main, "APP_ENV", "production")
    monkeypatch.setattr(main, "POSTGRES_DSN", "postgresql://configured")
    monkeypatch.setattr(main, "RECEIPT_ADMIN_SECRET", "configured-admin-secret")
    monkeypatch.setattr(main, "RECEIPT_SECRET", "configured-receipt-secret")
    monkeypatch.setattr(main, "PAY_TO_ADDRESS", pay_to)

    with pytest.raises(RuntimeError, match="PAYMENT_FIREWALL_PAY_TO"):
        main.validate_startup_configuration()


def test_production_accepts_explicit_pay_to(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "APP_ENV", "production")
    monkeypatch.setattr(main, "POSTGRES_DSN", "postgresql://configured")
    monkeypatch.setattr(main, "RECEIPT_ADMIN_SECRET", "configured-admin-secret")
    monkeypatch.setattr(main, "RECEIPT_SECRET", "configured-receipt-secret")
    monkeypatch.setattr(
        main,
        "PAY_TO_ADDRESS",
        "0x530271DA8CC4e44375f22ad9632bC61A55382f88",
    )

    main.validate_startup_configuration()
