# app.integrations

## Purpose

This package owns external provider adapters and shared integration interfaces.
It now includes sandbox KYC adapters plus a narrow, provider-backed Range Risk
API screening path.

## Adapter Pattern

- integration clients live behind narrow interfaces
- protocol and ops packages should depend on integration interfaces, not vendor
  SDKs directly
- provider-specific errors should be normalized before they cross package
  boundaries

## Naming Conventions

- `*_client.py` for provider clients
- `interfaces.py` for stable abstract seams
- `catalog.py` for researched provider candidates and domain groupings
- `config.py` for provider runtime configuration and credential-reference models
- `kyc.py` for KYC/KYB-domain adapter contracts and sandbox adapters
- `range.py` for the Range Risk API adapter and screening contracts
- `registry.py` for adapter registration and discovery
- `health.py` for health probes and readiness contracts
- `errors.py` for normalized provider exceptions

## Config And Secrets

- pass config through explicit settings objects or constructor arguments
- do not read environment variables deep inside adapters
- keep secrets outside logs and error messages
- use `ProviderRuntimeConfig` and `ProviderCredentialRef` to describe adapter
  inputs before any live integration is added
- default env-var naming should use:
  - `SAFE4_PROVIDER_<PROVIDER_SLUG>_<FIELD_NAME>`
  - example: `SAFE4_PROVIDER_STRIPE_IDENTITY_API_KEY`

## Planned Runtime Config Surface

- provider slug
- target environment (`sandbox` or `production`)
- endpoint base URL and timeout
- credential references
- optional static headers

## Current Live-Domain Progress

- KYC is the first integration domain
- sandbox adapters currently exist for:
  - Stripe Identity
  - Veriff
- these adapters are deterministic and test-backed; they do not call external
  services yet
- Range Risk API is now wired as a narrow provider-backed crypto-screening path
- the current live operations are:
  - address risk scoring
  - sanctions screening
- Range is exposed through admin-only test endpoints before any decision-path
  rollout

## How To Write Tests

- contract tests for the interface
- provider fixture tests for normalization
- protocol-level tests should use fakes or stubs rather than live providers

## Codex Context Set

- `app/integrations/interfaces.py`
- `app/integrations/catalog.py`
- `app/integrations/config.py`
- `app/integrations/kyc.py`
- `app/integrations/range.py`
- `app/integrations/registry.py`
- `app/integrations/health.py`
- `app/integrations/models.py`
- `app/integrations/errors.py`
- `docs/integrations/PAYPERUSE_PROVIDER_MATRIX.md`
- `docs/integrations/RANGE_RISK_API.md`

## How To Test This Package

```powershell
python -m unittest -q
```
