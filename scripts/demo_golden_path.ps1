[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
Set-Location -LiteralPath $repoRoot

# Load only public Arc/replay configuration. Credentials and session material
# are deliberately outside this allowlist and remain owned by Circle CLI.
$allowedNames = @(
    "SAFE4_DEMO_MODE",
    "RPC_URL",
    "CHAIN_ID",
    "USDC_ADDRESS",
    "USDC_DECIMALS",
    "ARC_ENTRYPOINT_ADDRESS",
    "ARC_NATIVE_USDC_ADDRESS",
    "ARC_NATIVE_USDC_DECIMALS",
    "SETTLEMENT_TX",
    "SETTLEMENT_FROM",
    "SETTLEMENT_TO",
    "SETTLEMENT_AMOUNT_UNITS",
    "SETTLEMENT_IDEMPOTENCY_KEY"
)

$callerOverrides = @{}
foreach ($name in $allowedNames) {
    $item = Get-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
    if ($null -ne $item) {
        $callerOverrides[$name] = $item.Value
    }
}

function Import-PublicDemoEnvironment {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return
    }

    foreach ($rawLine in Get-Content -LiteralPath $Path) {
        $line = $rawLine.Trim()
        if (-not $line -or $line.StartsWith("#")) {
            continue
        }
        if ($line -notmatch "^(?<name>[A-Z][A-Z0-9_]*)=(?<value>.*)$") {
            throw "Invalid public demo environment line in ${Path}"
        }
        $name = $Matches.name
        if ($name -notin $allowedNames) {
            continue
        }
        $value = $Matches.value.Trim()
        if (
            $value.Length -ge 2 -and
            (($value.StartsWith('"') -and $value.EndsWith('"')) -or
             ($value.StartsWith("'") -and $value.EndsWith("'")))
        ) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        [Environment]::SetEnvironmentVariable($name, $value, "Process")
    }
}

Import-PublicDemoEnvironment -Path (Join-Path $repoRoot "scripts\demo_golden_path.env")
Import-PublicDemoEnvironment -Path (Join-Path $repoRoot "shipline\verify.env")

foreach ($name in $callerOverrides.Keys) {
    [Environment]::SetEnvironmentVariable(
        $name,
        $callerOverrides[$name],
        "Process"
    )
}

if ($env:SAFE4_DEMO_MODE -eq "circle-live" -and -not $env:SETTLEMENT_IDEMPOTENCY_KEY) {
    throw "SETTLEMENT_IDEMPOTENCY_KEY is required for circle-live mode"
}

$pythonCandidates = @(
    (Join-Path $repoRoot ".python313\python.exe"),
    (Join-Path $repoRoot ".venv\Scripts\python.exe"),
    (Join-Path $repoRoot ".venv\bin\python")
)
$python = $pythonCandidates |
    Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
    Select-Object -First 1
if (-not $python) {
    $python = (Get-Command python3 -ErrorAction SilentlyContinue).Source
}
if (-not $python) {
    $python = (Get-Command python -ErrorAction Stop).Source
}

& $python -m scripts.demo_golden_path
exit $LASTEXITCODE
