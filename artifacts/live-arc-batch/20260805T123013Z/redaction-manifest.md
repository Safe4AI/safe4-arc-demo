# Redaction manifest

The public evidence was constructed from fixed allowlists. Complete CLI, RPC,
HTTP, application, environment, database, and private-journal objects were not
serialized and then redacted.

Excluded categories:

- OAuth access and refresh tokens;
- authorization and device codes;
- Safe4 spend authorization tokens;
- receipt tokens and local receipt-signing material;
- admin secrets and private keys;
- OTPs and email addresses;
- cookies, wallet session data, and Circle transaction IDs;
- all six Safe4/Circle idempotency-key values;
- complete environment values and proxy/CA values;
- complete Circle CLI stdout/stderr and API responses;
- complete RPC responses and application/database rows; and
- private journal plan documents.

Retained categories are public chain identifiers, fixed synthetic scenario
labels, exact transaction hashes, blocks, sender, recipient, amounts, bounded
reason/status codes, source digests, aggregate test results, and journal phase
names/counts.

Review status: PASS. The independent reviewer found zero secret or UUIDv4
idempotency-value findings in the completed bundle.
