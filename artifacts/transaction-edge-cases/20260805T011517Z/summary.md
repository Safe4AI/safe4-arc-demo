# Safe4 local transaction edge-case evidence

Run ID: `20260805T011517Z`

This bundle records local application authorization behavior and separate local
settlement-verifier fixtures. It contains no live chain or settlement execution.

| ID | Evidence class | Primary HTTP | Primary outcome | Reason | Verdict |
|---|---|---:|---|---|---|
| T01 | local_application_authorization | 200 | ALLOW | TASK_PURCHASE_MATCH | PASS |
| T02 | local_application_authorization | 403 | DENY | PURCHASE_PURPOSE_MISMATCH | PASS |
| T03 | local_application_authorization | 403 | DENY | SERVICE_CATEGORY_OUTSIDE_TASK | PASS |
| T04A | local_application_authorization | 200 | ALLOW | LEGACY_JUSTIFICATION_ACCEPTED | PASS |
| T04B | local_application_authorization | 403 | DENY | INTENT_CONTEXT_INVALID | PASS |
| T05 | local_application_authorization | 403 | DENY | AGENT_TRANSACTION_CAP_EXCEEDED | PASS |
| T06 | local_application_authorization | 403 | DENY | TRANSACTION_CAP_EXCEEDED | PASS |
| T07 | local_application_authorization | 403 | DENY | DAILY_CAP_EXCEEDED | PASS |
| T08 | local_application_authorization | 429 | RATE_LIMIT | VELOCITY_LIMIT_EXCEEDED | PASS |
| T09 | local_application_authorization | 200 | ALLOW | TASK_PURCHASE_MATCH | PASS |
| T10 | local_application_authorization | 409 | CONFLICT | IDEMPOTENCY_KEY_REUSED | PASS |
| T11 | local_application_authorization | 402 | CHALLENGE | PAYMENT_RECEIPT_ALREADY_USED | PASS |
| T12 | local_application_authorization | 402 | CHALLENGE | PAYMENT_RECEIPT_EXPIRED | PASS |
| T13 | local_application_authorization | 402 | CHALLENGE | PAYMENT_REQUIRED | PASS |
| T14 | local_application_authorization | 422 | VALIDATION_REJECT | INVALID_IDEMPOTENCY_KEY | PASS |
| T15 | local_application_authorization | 429 | RATE_LIMIT | RATE_LIMITED | PASS |
| T16 | local_application_authorization | 403 | DENY | AGENT_ID_MISMATCH | PASS |
| T17 | local_application_authorization | 413 | VALIDATION_REJECT | REQUEST_TOO_LARGE | PASS |
| T18 | local_application_authorization | 403 | DENY | SCOPE_OF_AUTONOMY_MAX_COST_EXCEEDED | PASS |
| T19 | local_application_authorization | 403 | DENY | BUDGET_NOT_FOUND | PASS |
| T20 | local_application_authorization | 202 | PENDING_APPROVAL | NONE | PASS |
| T21 | local_application_authorization | 422 | VALIDATION_REJECT | INVALID_MCP_CONTEXT | PASS |
| C01 | red_team_canary | 200 | ALLOW | TASK_PURCHASE_MATCH | FAIL |
| C02 | red_team_canary | 200 | ALLOW | TASK_PURCHASE_MATCH | FAIL |
| C03 | red_team_canary | 200 | ALLOW | TASK_PURCHASE_MATCH | FAIL |

## Totals

```json
{
  "allowed": 6,
  "authorization_only_cases": 25,
  "challenge_step_count": 25,
  "challenged": 3,
  "conflict": 1,
  "coverage_verdicts": {
    "FAIL": 3,
    "PASS": 22
  },
  "denied": 9,
  "failed": 3,
  "known_gap_canaries": 3,
  "overall_verdict": "REQUIRED_PASS_WITH_KNOWN_GAPS",
  "passed": 22,
  "pending_approval": 1,
  "primary_outcomes": {
    "ALLOW": 6,
    "CHALLENGE": 3,
    "CONFLICT": 1,
    "DENY": 9,
    "PENDING_APPROVAL": 1,
    "RATE_LIMIT": 2,
    "VALIDATION_REJECT": 3
  },
  "rate_limited": 2,
  "required_scenarios_failed": 0,
  "required_scenarios_passed": 22,
  "scenario_count": 25,
  "settlement_fixtures_failed": 0,
  "settlement_fixtures_passed": 8,
  "validation_rejected": 3
}
```

Independent review verdict: `PASS_WITH_KNOWN_GAPS`. All 22 required scenarios
and eight local settlement fixtures are supported. C01-C03 remain failed
canaries because the current policy authorized each adversarial request.
