from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


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
    os.environ.setdefault("PAYMENT_FIREWALL_ENV", "development")
    os.environ.setdefault("PORT", str(args.port))
    os.environ.setdefault("APP_PORT", str(args.port))
    os.environ.setdefault("PAYMENT_FIREWALL_ADMIN_SECRET", "demo-local-admin-only")
    os.environ.setdefault("PAYMENT_FIREWALL_RECEIPT_SECRET", "demo-local-receipt-only")
    os.environ.setdefault("PAYMENT_FIREWALL_DEMO_ACCESS_TOKEN", LOCAL_DEMO_TOKEN)
    os.environ.setdefault("PAYMENT_FIREWALL_PAY_TO", TESTNET_RECIPIENT)

    repository_root = str(Path(__file__).resolve().parents[1])
    if repository_root not in sys.path:
        sys.path.insert(0, repository_root)

    import uvicorn
    from app.main import app

    print(f"Safe4 API: http://{args.host}:{args.port}/docs")
    print(
        "Safe4 demo: "
        f"http://{args.host}:{args.port}/demo/agent-security"
        f"?access_token={LOCAL_DEMO_TOKEN}"
    )
    uvicorn.run(app, host=args.host, port=args.port, reload=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
