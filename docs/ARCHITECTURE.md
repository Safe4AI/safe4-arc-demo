# Safe4 Arc demo architecture

## Position in the payment path

Safe4 is called after an agent decides it wants to pay but before the wallet
signs or broadcasts settlement.

```text
task
  → agent proposes payment
    → Safe4 evaluates payment context and policy
      → DENIED: reason + audit evidence, no settlement
      → ALLOWED: Arc USDC settlement
        → RPC verification
          → receipt finalized with transaction hash
```

The wallet remains responsible for custody and signing. Safe4 is responsible
for deciding whether the proposed payment is permitted and for verifying the
settlement evidence before finalization.

## Existing service

- `app/main.py` composes the FastAPI service and payment flow.
- `app/payment_entry_checks.py`, `app/payment_flow.py`, and
  `app/payment_finalize.py` separate payment checks from finalization.
- `app/protocols/x402.py` implements x402 challenge and receipt machinery.
- `app/protocols/ap2.py` implements AP2 mandate evidence.
- `app/integrations/` supplies external risk-provider seams.
- `app/storage.py` persists payment, approval, receipt, and audit state.

## Arc settlement seam

The x402 module already carries:

- `settlement_proof_type`
- `settlement_reference`
- `settlement_proof_value`
- `settlement_method`

The current service fallback can synthesize a proof value. The hackathon
connection replaces that fallback with a real Arc transaction and requires RPC
verification of:

1. Arc Testnet chain ID
2. USDC contract target
3. expected sender and recipient
4. exact six-decimal USDC amount and ERC-20 calldata
5. successful receipt
6. matching `Transfer` event

Only after those checks pass should Safe4 finalize the payment receipt.

## Differentiation

Wallet products already provide spending limits, allowlists, blocklists, and
sanctions screening. Safe4's differentiating layer combines those controls with
context the wallet does not inherently know:

- the task the agent was given
- whether the proposed payment matches that task
- autonomy and approval scope
- cross-payment velocity and budget state
- recipient and operational risk signals
- a tamper-evident explanation of the decision

The final golden path must demonstrate a payment denied for contextual intent,
not merely for exceeding a limit.

## Trust boundaries

- Private keys remain outside Safe4 source and logs.
- Arc RPC data is untrusted until checked against the expected transaction.
- Testnet configuration is not production configuration.
- Development defaults are deliberately labeled and must not be used as
  production secrets.
- This project makes no certification or regulatory-compliance claims.
