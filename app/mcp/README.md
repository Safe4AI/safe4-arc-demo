# app.mcp

## Purpose

Contains MCP registry, models, permissions, drift and quarantine behavior, and
MCP-specific payment policy.

## Public Surface Area

- MCP registry/admin helpers
- MCP domain models
- MCP-specific authorization helpers

## Forbidden Imports

- do not import `app.api`
- do not import protocol-specific code unless explicitly routed through shared
  core helpers

## Where To Add New Code

- MCP server/tool lifecycle management
- MCP-specific authorization and alert behavior

## Codex Context Set

- `app/mcp/api.py`
- `app/mcp/models.py`
- `app/mcp/payment_policy.py`
- `tests/test_main.py`

## How To Test This Package

```powershell
python -m unittest -q
```
