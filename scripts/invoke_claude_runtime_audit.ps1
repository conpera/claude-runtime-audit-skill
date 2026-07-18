#Requires -Version 5.1

[CmdletBinding()]
param(
    [AllowEmptyString()]
    [string]$TargetCountry = "US",

    [string]$TargetTimezone = "",

    [switch]$StrictUsWorkstation,
    [switch]$ScanKnownHome,
    [switch]$ScanHome,

    [ValidateRange(1, 100000)]
    [int]$HomeMaxFiles = 600,

    [ValidateRange(1, 100000000)]
    [int]$HomeMaxBytes = 1000000,

    [switch]$NoNetwork,

    [ValidateRange(1, 120)]
    [int]$NetworkTimeout = 8,

    [switch]$Json,
    [string]$OutputPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$auditScript = Join-Path $PSScriptRoot "claude_runtime_audit.py"
if (-not (Test-Path -LiteralPath $auditScript -PathType Leaf)) {
    throw "Audit script not found: $auditScript"
}

$pythonExe = $null
$pythonPrefix = @()
foreach ($candidate in @("py", "python", "python3")) {
    $command = Get-Command $candidate -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        continue
    }

    $pythonExe = $command.Source
    if ($candidate -eq "py") {
        $pythonPrefix = @("-3")
    }
    break
}

if ($null -eq $pythonExe) {
    throw "Python 3.9 or newer is required. Install Python, reopen PowerShell, and run this script again."
}

$auditArgs = @(
    "--target-country", $TargetCountry.ToUpperInvariant(),
    "--home-max-files", $HomeMaxFiles.ToString(),
    "--home-max-bytes", $HomeMaxBytes.ToString(),
    "--network-timeout", $NetworkTimeout.ToString()
)

if ($TargetTimezone) {
    $auditArgs += @("--target-timezone", $TargetTimezone)
}
if ($StrictUsWorkstation) {
    $auditArgs += "--strict-us-workstation"
}
if ($ScanKnownHome) {
    $auditArgs += "--scan-known-home"
}
if ($ScanHome) {
    $auditArgs += "--scan-home"
}
if ($NoNetwork) {
    $auditArgs += "--no-network"
}
if ($Json) {
    $auditArgs += "--json"
}

if ($OutputPath) {
    $resolvedOutput = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    $parent = Split-Path -Parent $resolvedOutput
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    & $pythonExe @pythonPrefix $auditScript @auditArgs | Out-File -LiteralPath $resolvedOutput -Encoding utf8
    $exitCode = $LASTEXITCODE
    if ($exitCode -eq 0) {
        Write-Host "Audit report written to $resolvedOutput"
    }
}
else {
    & $pythonExe @pythonPrefix $auditScript @auditArgs
    $exitCode = $LASTEXITCODE
}

if ($exitCode -ne 0) {
    throw "Claude runtime audit failed with exit code $exitCode."
}
