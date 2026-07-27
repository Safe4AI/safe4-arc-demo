# app.core

## Purpose

Holds shared authorization logic, runtime configuration, payment-flow helpers,
and domain-level helpers that should not depend on FastAPI router modules.

## Public Surface Area

- shared auth helpers
- shared config helpers
- shared payment orchestration helpers

## Forbidden Imports

- do not import `app.api`
- do not import transport-only router modules

## Where To Add New Code

- shared runtime config
- shared domain validation helpers
- cross-subsystem orchestration helpers that are not route modules

## Codex Context Set

- `app/main.py`
- `app/core/config.py`
- `app/auth.py`
- `app/payment_entry_checks.py`
- `app/payment_flow.py`
- `app/payment_finalize.py`
- `tests/test_main.py`

## How To Test This Package

```powershell
python -m unittest -q
```
