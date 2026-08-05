#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# Keep explicit caller overrides while loading committed, non-secret replay
# defaults. This makes the same command usable for historical EOA evidence and
# fresh Circle Agent Wallet (ERC-4337) evidence.
declare -A caller_overrides=()
override_names=(
  SAFE4_DEMO_MODE RPC_URL CHAIN_ID USDC_ADDRESS USDC_DECIMALS
  ARC_ENTRYPOINT_ADDRESS ARC_NATIVE_USDC_ADDRESS ARC_NATIVE_USDC_DECIMALS
  SETTLEMENT_TX SETTLEMENT_FROM SETTLEMENT_TO SETTLEMENT_AMOUNT_UNITS
  SETTLEMENT_IDEMPOTENCY_KEY
)
for name in "${override_names[@]}"; do
  if [[ -v "$name" ]]; then
    caller_overrides["$name"]="${!name}"
  fi
done

if [ -f scripts/demo_golden_path.env ]; then
  set -a
  # Committed public Arc Testnet evidence; contains no credentials.
  . scripts/demo_golden_path.env
  set +a
fi

if [ -f shipline/verify.env ]; then
  set -a
  # Private-workspace verifier values may override the public demo evidence.
  . shipline/verify.env
  set +a
fi

for name in "${!caller_overrides[@]}"; do
  export "$name=${caller_overrides[$name]}"
done

if [ -n "${PYTHON:-}" ]; then
  :
elif [ -x .python313/python.exe ]; then
  PYTHON=.python313/python.exe
elif [ -x .venv/Scripts/python.exe ]; then
  PYTHON=.venv/Scripts/python.exe
elif [ -x .venv/bin/python ]; then
  PYTHON=.venv/bin/python
elif command -v python3 >/dev/null 2>&1; then
  PYTHON=python3
else
  PYTHON=python
fi

exec "$PYTHON" -m scripts.demo_golden_path
