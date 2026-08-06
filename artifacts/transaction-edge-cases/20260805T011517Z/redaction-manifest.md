# Redaction manifest

The runner never writes values from these categories:

- OAuth access and refresh tokens
- OAuth authorization codes and authorization header values
- receipt tokens and receipt-signature material
- administrative secrets
- spend authorization tokens
- private keys, one-time passwords, and email addresses
- cookies, wallet sessions, and browser sessions
- environment variable values
- raw HTTP bodies or headers
- raw application logs or database contents
- absolute filesystem paths
- ambient environment dumps

Application identifiers and synthetic client addresses are mapped to
deterministic per-scenario aliases.
