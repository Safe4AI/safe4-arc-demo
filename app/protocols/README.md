# app.protocols

## Purpose

Contains protocol-specific logic and evidence handling for AP2 and x402.

## Public Surface Area

- protocol verifiers
- protocol config helpers
- protocol evidence readers/writers

## Forbidden Imports

- do not import `app.api`
- do not own FastAPI route registration here

## Where To Add New Code

- AP2 and x402 internals
- protocol evidence helpers
- protocol adapter seams

## Codex Context Set

- `app/protocols/ap2.py`
- `app/protocols/x402.py`
- `app/storage.py`
- `tests/test_main.py`

## How To Test This Package

```powershell
python -m unittest -q
```
