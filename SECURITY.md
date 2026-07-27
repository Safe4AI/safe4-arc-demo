# Security policy

## Reporting

Do not open a public issue containing exploit details or credentials. Contact
the repository owner privately with the affected area, impact, and reproduction
steps.

## Repository rules

- Never commit wallet private keys, tokens, API keys, `.env` files, databases,
  or credential exports.
- Treat all addresses and transaction hashes as public.
- Supply runtime credentials only through the process environment or a managed
  secret store.
- Use Arc Testnet only for this hackathon build.
- Development defaults are not suitable for production.

## Current limitations

- The public repository is an active hackathon build.
- Arc settlement is proven independently and is being wired into the service.
- Semantic intent verification is not complete.
- Safe4 makes no certification or regulatory-compliance claims.
