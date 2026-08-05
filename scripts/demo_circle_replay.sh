#!/usr/bin/env bash
set -euo pipefail

# Public, non-secret evidence from the authorized Circle Agent Wallet transfer.
export SAFE4_DEMO_MODE="circle-rpc-replay"
export SETTLEMENT_TX="0xf9d665cf0eb663e33703826ca599d526718042781860faeec5e7ad089fde775d"
export SETTLEMENT_FROM="0x3985a31e4e42a31e437c1099306decbe2f08da4d"

exec bash "$(dirname "$0")/demo_golden_path.sh"
