[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

# Fixed public evidence only. This wrapper cannot select circle-live mode and
# therefore cannot sign or broadcast a transaction.
$env:SAFE4_DEMO_MODE = "circle-rpc-replay"
$env:RPC_URL = "https://rpc.testnet.arc.network"
$env:CHAIN_ID = "5042002"
$env:USDC_ADDRESS = "0x3600000000000000000000000000000000000000"
$env:USDC_DECIMALS = "6"
$env:ARC_ENTRYPOINT_ADDRESS = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"
$env:ARC_NATIVE_USDC_ADDRESS = "0xfffffffffffffffffffffffffffffffffffffffe"
$env:ARC_NATIVE_USDC_DECIMALS = "18"
$env:SETTLEMENT_TX = "0xf9d665cf0eb663e33703826ca599d526718042781860faeec5e7ad089fde775d"
$env:SETTLEMENT_FROM = "0x3985a31e4e42a31e437c1099306decbe2f08da4d"
$env:SETTLEMENT_TO = "0x530271DA8CC4e44375f22ad9632bC61A55382f88"
$env:SETTLEMENT_AMOUNT_UNITS = "10000"

& (Join-Path $PSScriptRoot "demo_golden_path.ps1")
exit $LASTEXITCODE
