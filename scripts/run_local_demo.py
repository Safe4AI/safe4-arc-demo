from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory


LOCAL_DEMO_TOKEN = "safe4-local-demo"
TESTNET_RECIPIENT = "0x530271DA8CC4e44375f22ad9632bC61A55382f88"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the Safe4 hackathon demo with explicit local-only defaults."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8090)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    demo_state = TemporaryDirectory(prefix="safe4-browser-demo-")
    # This entrypoint is intentionally deterministic and isolated. Ignore any
    # shared-database setting inherited from a developer shell and override all
    # values that must match the printed local demo URL.
    os.environ.pop("PAYMENT_FIREWALL_POSTGRES_DSN", None)
    os.environ["PAYMENT_FIREWALL_ENV"] = "development"
    os.environ["PORT"] = str(args.port)
    os.environ["APP_PORT"] = str(args.port)
    os.environ["PAYMENT_FIREWALL_DB_PATH"] = str(
        Path(demo_state.name) / "safe4-browser-demo.db"
    )
    os.environ["PAYMENT_FIREWALL_ADMIN_SECRET"] = "demo-local-admin-only"
    os.environ["PAYMENT_FIREWALL_RECEIPT_SECRET"] = "demo-local-receipt-only"
    os.environ["PAYMENT_FIREWALL_DEMO_ACCESS_TOKEN"] = LOCAL_DEMO_TOKEN
    os.environ["PAYMENT_FIREWALL_DEMO_X402_RECEIPT_ENABLED"] = "true"
    os.environ["PAYMENT_FIREWALL_PAY_TO"] = TESTNET_RECIPIENT
    os.environ["PAYMENT_FIREWALL_FEE_RATE"] = "0.0025"
    os.environ["PAYMENT_FIREWALL_PHASE3_X402_ADVANCED_ENABLED"] = "true"
    os.environ["PAYMENT_FIREWALL_X402_SUPPORTED_NETWORKS"] = "arc-testnet"
    os.environ["PAYMENT_FIREWALL_X402_NETWORK_RECIPIENTS"] = (
        f"arc-testnet:{TESTNET_RECIPIENT}"
    )
    os.environ["PAYMENT_FIREWALL_VELOCITY_LIMIT"] = "30"
    os.environ["PAYMENT_FIREWALL_RATE_LIMIT_REQUESTS"] = "120"

    repository_root = str(Path(__file__).resolve().parents[1])
    if repository_root not in sys.path:
        sys.path.insert(0, repository_root)

    import uvicorn
    from app.main import app

    print("Safe4 storage: isolated temporary SQLite")
    print(f"Safe4 API: http://{args.host}:{args.port}/docs")
    print(
        "Safe4 demo: "
        f"http://{args.host}:{args.port}/demo/x402"
        f"?access_token={LOCAL_DEMO_TOKEN}"
    )
    try:
        uvicorn.run(app, host=args.host, port=args.port, reload=False)
        return 0
    finally:
        demo_state.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
