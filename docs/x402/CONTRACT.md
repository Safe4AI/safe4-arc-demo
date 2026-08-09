# Safe4 x402 contract

This is the one page an agent developer needs to point an x402-shaped client
at Safe4 and get a real challenge → proof → decision loop, without reading
the application source.

**What this is not.** Safe4 acting as an x402 resource server that issues
challenges and verifies proof is not the same claim as x402 on-chain
settlement. Nothing described on this page broadcasts a blockchain
transaction. Safe4 returns an authorization decision; a caller's own
settlement (or Safe4's separate, presenter-only live settlement lane — see
`docs/hackathon/CLAIM_LEDGER.md`) is what actually moves funds, and only
after Safe4 returns ALLOW.

**Spec conformance.** This is "x402-shaped," not a certified implementation
of the published x402 specification. It follows the same `402 → challenge →
retry-with-proof` shape and reuses x402's `X-Payment-Receipt`-style proof
header pattern, but Safe4 has not been verified field-by-field against the
current x402 spec. Treat field names as Safe4's own contract, not a spec
guarantee.

## 1. Discovery

```
GET /x402/capabilities        # requires Authorization: Bearer <token>
GET /x402/providers           # registered provider adapters
GET /x402/provider-configs    # per-provider trust/settlement configuration
```

`GET /x402/capabilities` reports whether the advanced x402 path is enabled on
this deployment and which settlement-proof types it currently accepts.

## 2. Authentication

Safe4 uses OAuth 2.0 authorization-code with PKCE, matching
`examples/safe4_quickstart.py`:

```
POST /oauth/authorize   { client_id, redirect_uri, scope, code_challenge,
                           code_challenge_method: "S256", subject, agent_id }
  -> { code }

POST /oauth/token       { grant_type: "authorization_code", client_id, code,
                           redirect_uri, code_verifier }
  -> { access_token }
```

Send `Authorization: Bearer <access_token>` on every subsequent call. The
scope needed for authorization is `payment:authorize`.

## 3. The 402 challenge

Call `POST /pay` with your payment request and no proof. An unproven request
always answers `402`:

```json
{
  "error": "PAYMENT_REQUIRED",
  "message": "Micropayment required before authorization can proceed.",
  "details": {
    "how_it_works": "Retry the same request with a valid X-Payment-Receipt header after paying the firewall fee.",
    "pay_to": "0x...",
    "amount_due": "0.010000",
    "currency": "USDC",
    "fee_rate": "0.0025",
    "receipt_issue_endpoint": "/receipts/issue",
    "x402_challenge": {
      "amount": "0.010000",
      "currency": "USDC",
      "recipient_address": "0x...",
      "recipient_addresses": { "arc-testnet": "0x..." },
      "supported_networks": ["arc-testnet"],
      "expiry_seconds": 300,
      "settlement_method": "signed_receipt_fallback",
      "receipt_header": "X-Payment-Receipt",
      "status": "scaffolded",
      "builder_name": "stub"
    }
  }
}
```

Response headers also carry `X-Payment-Required: true`, `X-Pay-To`, and
`X-Amount-Due`.

`details.x402_challenge.settlement_method` tells you which proof format this
deployment expects; `details.x402_challenge.receipt_header` names the header
to present on retry (currently always `X-Payment-Receipt`).

## 4. Proof: which kind is real

Present the value your proof source gives you in the header named by
`receipt_header`. There are three distinct proof sources today. Be precise
about which one you are using — they carry very different evidentiary
weight:

| Proof source | What it is | How real |
|---|---|---|
| `signed_receipt_fallback` (demo fixture) | Issued by `POST /demo/x402/receipt`, gated by an `X-Demo-Access` token. Fixed-fee, exact-recipient, short-lived, rate-limited. | **Guarded demo fixture.** This is what the browser lab and `examples/safe4_quickstart.py` use today so a developer can exercise the full loop against the hosted deployment without operator coordination. It proves nothing about an external payment; Safe4 issues and self-verifies it. |
| Provider receipt (`X402ProviderAdapter`) | An RS256-signed receipt token from a registered provider, verified against the provider's trust anchors and key rotation window (`app/protocols/x402.py`). | **Cryptographically verified**, but provider onboarding (`POST /x402/provider-configs`) is operator-side today, not self-service. A third party cannot yet register their own provider without coordinating with Safe4's operator. |
| Real Arc Testnet transfer | An actual on-chain USDC transfer, RPC-verified. | Used only by Safe4's own presenter-operated live settlement lane (`POST /demo/live/settle`), which runs *after* Safe4 returns ALLOW and is not part of this challenge/proof loop at all. |

For a developer trying the SDK today, the demo fixture is the only proof
source usable without prior coordination. Use it to prove the *decision
loop* — the ALLOW/DENY verdict flip on task/purchase match — not to claim a
real payment occurred.

## 5. Retry with proof

```
POST /pay
Authorization: Bearer <access_token>
X-Payment-Receipt: <proof from step 4>
Idempotency-Key: <UUIDv4>          # optional but recommended
```

Same JSON body as the first call. On success:

```json
{
  "status": "AUTHORIZED",
  "receipt_id": "...",
  "receipt_source": "signed_receipt_fallback",
  "intent_decision": {
    "allowed": true,
    "reason_code": "TASK_PURCHASE_MATCH",
    "matched_concepts": ["..."]
  }
}
```

HTTP 200 plus `status: "AUTHORIZED"` is the only ALLOW shape. Every other
outcome is a denial — inspect `error` (top level) and `details.intent_decision`
(when present) for the reason code.

## 6. Idempotency

`Idempotency-Key` must be a UUIDv4 string (checked against
`INVALID_IDEMPOTENCY_KEY` — see the reason-code table). Replaying the same
key with the same request body returns the identical cached response instead
of re-authorizing. This is a local replay guarantee scoped to this Safe4
deployment; it does not prove exactly-once external settlement.

## 7. Reason codes

Generated from source by `scripts/generate_x402_reason_codes.py` — run
`python scripts/generate_x402_reason_codes.py --check` to confirm this table
still matches `app/main.py`, `app/payment_flow.py`,
`app/payment_entry_checks.py`, `app/payment_finalize.py`,
`app/protocols/x402.py`, `app/protocols/ap2.py`, `app/mcp/payment_policy.py`,
`app/hitl_policy.py`, `app/api/demo_live.py`, and `app/core/intent.py`. A
`?` status means the code is attached to its HTTP status by a caller
elsewhere rather than at the point the code literal appears; `_(see
source)_` means the message is built from a variable, not a fixed string
literal, at that call site.

<!-- BEGIN GENERATED REASON CODES -->
| Reason code | HTTP status | Meaning | Source |
|---|---|---|---|
| `ADVANCED_X402_DISABLED` | 403 | Provider-backed x402 receipts are disabled by the active policy. | `app/payment_entry_checks.py` |
| `AGENT_BUDGET_NOT_FOUND` | 403 | No budget configured for agent. | `app/main.py` |
| `AGENT_DAILY_CAP_EXCEEDED` | 403 | _(see source)_ | `app/main.py` |
| `AGENT_ID_MISMATCH` | 403 | Token agent_id does not match the payment request agent_id. | `app/main.py` |
| `AGENT_TRANSACTION_CAP_EXCEEDED` | 403 | _(see source)_ | `app/main.py` |
| `AP2_ACCEPTED` | ? | AP2 mandate verified and matched against the payment request. | `app/protocols/ap2.py` |
| `AP2_DISABLED` | 403 | AP2 mandate support is currently disabled by policy. | `app/protocols/ap2.py` |
| `AP2_FAMILY_NOT_FOUND` | 404 | _(see source)_ | `app/protocols/ap2.py` |
| `AP2_INVALID_SIGNATURE` | ? | AP2 mandate signature verification failed. | `app/protocols/ap2.py` |
| `AP2_MANDATE_ARCHIVE_BLOCKED_ACTIVE_DESCENDANTS` | 409 | _(see source)_ | `app/protocols/ap2.py` |
| `AP2_MANDATE_CHAIN_INVALID` | ? | AP2 cart mandate must reference a parent intent mandate. | `app/protocols/ap2.py` |
| `AP2_MANDATE_INVALID` | ? | AP2 mandate payload is missing required fields. | `app/protocols/ap2.py` |
| `AP2_MANDATE_LIFECYCLE_INVALID` | ? | _(see source)_ | `app/protocols/ap2.py` |
| `AP2_MANDATE_MISMATCH` | ? | AP2 mandate does not match the payment request. | `app/protocols/ap2.py` |
| `AP2_MANDATE_NOT_FOUND` | 404 | _(see source)_ | `app/protocols/ap2.py` |
| `AP2_NOT_IMPLEMENTED` | ? | AP2 verification is enabled but no concrete mandate verifier is installed yet. | `app/protocols/ap2.py` |
| `AP2_SIGNER_DISABLED` | ? | AP2 mandate signer is disabled. | `app/protocols/ap2.py` |
| `AP2_SIGNER_UNKNOWN` | ? | AP2 mandate signer is not registered. | `app/protocols/ap2.py` |
| `AP2_VERIFIER_UNKNOWN` | ? | AP2 signer references an unknown verifier adapter. | `app/protocols/ap2.py` |
| `BUDGET_NOT_FOUND` | 403 | No budget configured for user. | `app/main.py` |
| `DAILY_CAP_EXCEEDED` | 403 | _(see source)_ | `app/main.py` |
| `HITL_RULE_TRIGGERED` | ? | Human approval is required before this payment can proceed. | `app/hitl_policy.py` |
| `IDEMPOTENCY_KEY_REUSED` | 409 | Idempotency key was already used for a different request body. | `app/payment_entry_checks.py` |
| `INFRASTRUCTURE_IDENTITY_ANOMALY_DENIED` | 403 | Payment denied by the infrastructure identity anomaly policy. | `app/hitl_policy.py` |
| `INFRASTRUCTURE_IDENTITY_POLICY_PASSED` | ? | _(see source)_ | `app/hitl_policy.py` |
| `INTENT_CONTEXT_INVALID` | ? | _(see source)_ | `app/core/intent.py` |
| `INTENT_VERIFICATION_FAILED` | 403 | _(see source)_ | `app/main.py` |
| `INVALID_IDEMPOTENCY_KEY` | 422 | Idempotency-Key must be a UUIDv4 string. | `app/main.py` |
| `INVALID_MCP_CONTEXT` | 422 | mcp_tool_id and mcp_action must be provided together. | `app/main.py` |
| `JUSTIFICATION_TOO_WEAK` | ? | _(see source)_ | `app/core/intent.py` |
| `LEGACY_JUSTIFICATION_ACCEPTED` | ? | _(see source)_ | `app/core/intent.py` |
| `LIVE_ADMIN_REQUIRED` | 403 | _(see source)_ | `app/api/demo_live.py` |
| `LIVE_AMOUNT_CAP_EXCEEDED` | 403 | _(see source)_ | `app/api/demo_live.py` |
| `LIVE_DAILY_CAP_EXCEEDED` | 429 | _(see source)_ | `app/api/demo_live.py` |
| `LIVE_RECIPIENT_NOT_CONFIGURED` | 503 | _(see source)_ | `app/api/demo_live.py` |
| `LIVE_SETTLEMENT_FAILED` | 502 | _(see source)_ | `app/api/demo_live.py` |
| `LIVE_SETTLEMENT_NOT_CONFIGURED` | 503 | _(see source)_ | `app/api/demo_live.py` |
| `LIVE_TRANSACTION_NOT_FROM_THIS_LANE` | 404 | _(see source)_ | `app/api/demo_live.py` |
| `LIVE_WALLET_UNDERFUNDED` | 503 | _(see source)_ | `app/api/demo_live.py` |
| `MCP_HITL_RULE_TRIGGERED` | ? | Human approval is required before this MCP payment can proceed. | `app/hitl_policy.py` |
| `MCP_SERVER_BLOCKED` | 403 | The MCP server for this tool is blocked for payment actions. | `app/mcp/payment_policy.py` |
| `MCP_SERVER_NOT_TRUSTED` | 403 | The MCP server for this tool is not trusted for payment actions. | `app/mcp/payment_policy.py` |
| `MCP_TOOL_ACTION_NOT_ALLOWED` | 403 | The requested MCP tool action is not allowed for this user. | `app/mcp/payment_policy.py` |
| `MCP_TOOL_DAILY_CAP_EXCEEDED` | 403 | The requested amount exceeds the MCP tool permission daily cap. | `app/mcp/payment_policy.py` |
| `MCP_TOOL_HITL_REQUIRED` | ? | Human approval is required before this MCP payment can proceed. | `app/hitl_policy.py` |
| `MCP_TOOL_NOT_REGISTERED` | 403 | The referenced MCP tool is not registered. | `app/mcp/payment_policy.py` |
| `MCP_TOOL_PERMISSION_REQUIRED` | 403 | This MCP tool is default-deny until a permission is granted. | `app/mcp/payment_policy.py` |
| `MCP_TOOL_QUARANTINED` | 403 | The referenced MCP tool is quarantined or blocked. | `app/mcp/payment_policy.py` |
| `MCP_TOOL_TRANSACTION_CAP_EXCEEDED` | 403 | The requested amount exceeds the MCP tool permission transaction cap. | `app/mcp/payment_policy.py` |
| `MCP_UNKNOWN_SERVER_HITL_REQUIRED` | ? | Human approval is required before this MCP payment can proceed. | `app/hitl_policy.py` |
| `PAYMENT_PROVIDER_CONFIRMATION_COUNT_INVALID` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_CONFIRMED_AT_INVALID` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_CONFIRMED_AT_IN_FUTURE` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_CONFIRMED_AT_MISSING` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_ISSUED_AT_INVALID` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_ISSUED_AT_IN_FUTURE` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_ISSUED_AT_MISSING` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_ISSUED_AT_TOO_OLD` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_ISSUER_MISMATCH` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_KEY_ID_MISMATCH` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_KEY_ID_UNKNOWN` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_NETWORK_NOT_ALLOWED` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_NOT_ENABLED` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_RECEIPT_ACCEPTED` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_RECEIPT_ALREADY_USED` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_RECEIPT_EXPIRED` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_RECEIPT_INVALID` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_RECEIPT_INVALID_SIGNATURE` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_RECEIPT_MISMATCH` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_RECEIPT_PENDING` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_RECEIPT_UNSETTLED` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_RECEIPT_VERSION_UNSUPPORTED` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_SETTLEMENT_NOT_CONFIRMED` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_SETTLEMENT_PROOF_MISSING` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_SETTLEMENT_PROOF_TYPE_MISMATCH` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_SETTLEMENT_REFERENCE_MISSING` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_PROVIDER_UNKNOWN` | ? | _(see source)_ | `app/protocols/x402.py` |
| `PAYMENT_RECEIPT_ALREADY_USED` | 402 | Payment receipt has already been consumed by a previous authorization attempt. | `app/payment_entry_checks.py` |
| `PAYMENT_RECEIPT_EXPIRED` | 402 | Payment receipt has expired and can no longer authorize a request. | `app/payment_entry_checks.py` |
| `PAYMENT_RECEIPT_INVALID` | 402 | Payment receipt could not be verified. | `app/payment_entry_checks.py` |
| `PAYMENT_RECEIPT_MISMATCH` | 402 | Payment receipt does not match the required fee for this request. | `app/payment_entry_checks.py` |
| `PAYMENT_REQUIRED` | ? | Micropayment required before authorization can proceed. | `app/payment_flow.py` |
| `PURCHASE_PURPOSE_MISMATCH` | ? | _(see source)_ | `app/core/intent.py` |
| `RATE_LIMITED` | ? | Rate limit exceeded for this endpoint. | `app/main.py` |
| `REQUEST_TOO_LARGE` | ? | Request body exceeds the maximum allowed size. | `app/main.py` |
| `SCOPE_OF_AUTONOMY_MAX_COST_EXCEEDED` | 403 | The requested amount exceeds the presented ScopeOfAutonomy max_cost. | `app/main.py` |
| `SCOPE_OF_AUTONOMY_TOOL_NOT_ALLOWED` | 403 | The requested tool is not allowed by the presented ScopeOfAutonomy. | `app/main.py` |
| `SERVICE_CATEGORY_OUTSIDE_TASK` | ? | _(see source)_ | `app/core/intent.py` |
| `SPEND_TOKEN_ALREADY_USED` | 403 | Spend token has already been consumed. | `app/hitl_policy.py` |
| `SPEND_TOKEN_EXPIRED` | 403 | Spend token has expired. | `app/hitl_policy.py` |
| `SPEND_TOKEN_INVALID` | 403 | Spend token has already been used or revoked. | `app/hitl_policy.py` |
| `SPEND_TOKEN_MISMATCH` | 403 | _(see source)_ | `app/hitl_policy.py` |
| `SPEND_TOKEN_REQUIRED` | 403 | A valid spend token is required to continue this approved payment request. | `app/hitl_policy.py` |
| `TASK_PURCHASE_MATCH` | ? | _(see source)_ | `app/core/intent.py` |
| `TRANSACTION_CAP_EXCEEDED` | 403 | _(see source)_ | `app/main.py` |
| `VELOCITY_LIMIT_EXCEEDED` | 429 | _(see source)_ | `app/main.py` |
<!-- END GENERATED REASON CODES -->

## 8. Errors outside the payment path

`401` with `AUTH_REQUIRED` / `INVALID_ACCESS_TOKEN` / `ACCESS_TOKEN_EXPIRED`
means the OAuth token is missing, malformed, or expired — redo step 2.
`403` with `INSUFFICIENT_SCOPE` means the token lacks `payment:authorize`.

## 9. See also

- [`sdk/python/safe4_client.py`](../../sdk/python/safe4_client.py) — a small
  client wrapping everything on this page.
- [`examples/third_party_agent_demo.py`](../../examples/third_party_agent_demo.py)
  — a worked example of an external agent using the SDK to get one ALLOW and
  one DENY.
- [`docs/hackathon/CLAIM_LEDGER.md`](../hackathon/CLAIM_LEDGER.md) — every
  claim on this page mapped to its evidence.
