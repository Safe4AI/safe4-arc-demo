#!/usr/bin/env bash
set -euo pipefail

# Public, non-secret evidence from the authorized Circle Agent Wallet transfer.
export SAFE4_DEMO_MODE="circle-rpc-replay"
export SETTLEMENT_TX="0x648ef14e4da7c6bfecce0017d19280ed51fb12635bea94712de926d9f967752c"
export SETTLEMENT_FROM="0x3985a31e4e42a31e437c1099306decbe2f08da4d"

exec bash "$(dirname "$0")/demo_golden_path.sh"
