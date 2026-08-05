# Reproducing this local evidence

Run ID: `20260805T011517Z`

Source identity: `unversioned snapshot`. No commit was invented for this
workspace. The allowlisted source-manifest SHA-256 is
`8cffd331084696cb54499b67743d2b3bd89c99973c6d0df8cbd5958116569dec`.

Runtime: CPython `3.13.14`.

Independent review verdict: `PASS_WITH_KNOWN_GAPS` (`COMPLETED/PASS` in the
machine schema, qualified by the three failed canaries and the limitations
below).

From the repository root, reproduce a new isolated run with:

```powershell
.\.python313\python.exe scripts\run_edge_case_evidence.py
```

Evidence classes are `local_application_authorization`, `red_team_canary`,
and `local_settlement_fixture`. No RPC, wallet, signing, transfer, or broadcast
was performed. `/pay` transaction aliases are local authorization identifiers,
not settlement identifiers. Standard `/pay` rows report settlement-executor
evidence as `NOT_OBSERVED`.

The SQLite database existed only below ignored `.tmp` during execution and was
deleted before this sanitized bundle was written. One unique run database was
reset between independent scenarios; this run did not use a separate process
and database for every scenario.

## Limitations

- `/pay` authorizes locally and does not expose a settlement executor.
- Idempotency proves one local budget and log write, not exactly-once external
  settlement or concurrency safety.
- Task context is request-supplied and is not principal-bound.
- C01-C03 were authorized and remain failed known-gap canaries.
- T18 recorded an audit but no `DENIED` payment log and left its receipt
  unconsumed.
- The optional historical Arc RPC replay was not run because this execution did
  not receive separate read-only network authorization.
