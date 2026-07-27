# app.ops

## Purpose

Contains operational helpers such as webhook delivery, metrics, outbox behavior,
and anomaly operational surfaces.

## Public Surface Area

- dispatch helpers
- metrics and outbox helpers
- anomaly operational helpers

## Forbidden Imports

- do not import `app.api`
- do not import `app.main`

## Where To Add New Code

- webhook/outbox operations
- anomaly alert operations
- metrics and operational instrumentation helpers

## Codex Context Set

- `app/api/webhooks.py`
- `app/api/ops.py`
- `app/ops/anomalies.py`
- `tests/test_main.py`

## How To Test This Package

```powershell
python -m unittest -q
```
