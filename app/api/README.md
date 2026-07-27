# app.api

## Purpose

Owns FastAPI routers and transport-facing concerns. Route modules should stay
thin and delegate to core, storage, protocol, MCP, and ops helpers.

## Public Surface Area

- router modules
- request/response transport wiring

## Forbidden Imports

- do not import `app.main`
- do not embed persistence bootstrap directly in routers

## Where To Add New Code

- new FastAPI routers
- transport-only request/response mapping

## Codex Context Set

- `app/main.py`
- `app/api/audit.py`
- `app/api/budgets.py`
- `app/api/hitl.py`
- `app/api/integrations.py`
- `app/api/oauth.py`
- `tests/test_main.py`

## How To Test This Package

```powershell
python -m unittest -q
```
