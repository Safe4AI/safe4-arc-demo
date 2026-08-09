# Safe4 Python SDK

A small, dependency-light (`httpx` only) client for Safe4's x402
challenge/proof/decision loop. Not published to PyPI — clone and import:

```python
import sys
sys.path.insert(0, "sdk/python")  # or copy safe4_client.py into your project

from safe4_client import Safe4Client

with Safe4Client(base_url="https://demo.safe4.ai", demo_access_token="...") as client:
    decision = client.authorize(
        task="Research competitor pricing using a paid company data service.",
        purchase_purpose="Generate a competitor pricing research brief from company data.",
        amount="0.01",
    )
    print(decision.allowed, decision.reason_code)
```

Read [`docs/x402/CONTRACT.md`](../../docs/x402/CONTRACT.md) first — it
defines the protocol this client wraps, and is explicit about which proof
sources are real cryptographic verification versus a guarded demo fixture.

See [`examples/third_party_agent_demo.py`](../../examples/third_party_agent_demo.py)
for a full worked example, and `tests/test_safe4_client.py` for usage against
a mocked transport.

This is not a certified x402-specification client, and nothing here signs,
broadcasts, or verifies a blockchain transaction.
