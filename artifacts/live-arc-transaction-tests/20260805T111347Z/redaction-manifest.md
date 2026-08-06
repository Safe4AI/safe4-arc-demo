# Redaction manifest

This bundle was constructed from an explicit field allowlist. It does not
contain raw response bodies, full headers, application logs, database rows, or
environment dumps.

Excluded categories:

- OAuth access and refresh tokens;
- authorization codes and spend-authorization tokens;
- x402 and local receipt tokens;
- Circle session and wallet-transaction identifiers;
- idempotency keys;
- admin secrets, API keys, private keys, and mnemonic material;
- OTPs, email addresses, and cookies;
- wallet/session storage and complete Circle API responses;
- local database contents and local filesystem user paths; and
- environment values other than explicitly public Arc addresses and network
  identifiers required for read-only verification.

No secret value was copied into this manifest.
