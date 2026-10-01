[CmdletBinding(DefaultParameterSetName = "Artifacts")]
param(
    # Native Windows mode: transfer an already-built and signed Linux release.
    [Parameter(Mandatory = $true, ParameterSetName = "Artifacts")]
    [string]$Manifest,

    [Parameter(Mandatory = $true, ParameterSetName = "Artifacts")]
    [string]$Binary,

    # Optional prebuilt Windows helios.exe. Cargo is used when omitted.
    [Parameter(ParameterSetName = "Artifacts")]
    [string]$HeliosCtl,

    # One-command development mode: build, sign and transfer inside WSL.
    [Parameter(Mandatory = $true, ParameterSetName = "Wsl")]
    [switch]$BuildInWsl,

    # Absolute Linux path of this repository in the selected WSL distribution.
    [Parameter(Mandatory = $true, ParameterSetName = "Wsl")]
    [ValidatePattern('^/')]
    [string]$WslRepo,

    [Parameter(ParameterSetName = "Wsl")]
    [string]$WslDistribution,

    [Parameter(ParameterSetName = "Wsl")]
    [ValidateSet("testing", "production")]
    [string]$Channel = "production",

    [Parameter(ParameterSetName = "Wsl")]
    [UInt64]$Sequence = 0,

    [Parameter(ParameterSetName = "Wsl")]
    [switch]$SkipFrontend,

    [Parameter(ParameterSetName = "Artifacts")]
    [switch]$Yes,

    [Parameter()]
    [switch]$StageOnly,

    [Parameter()]
    [string]$HeliosUrl = $(
        if ([string]::IsNullOrWhiteSpace($env:HELIOS_URL)) {
            "http://100.64.0.1:8080"
        } else {
            $env:HELIOS_URL
        }
    )
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-LastExitCode([string]$Action) {
    if ($LASTEXITCODE -ne 0) {
        throw "$Action failed with exit code $LASTEXITCODE."
    }
}

try {
    $uri = [System.Uri]$HeliosUrl
} catch {
    throw "HeliosUrl is not a valid absolute URL: $HeliosUrl"
}
if (-not $uri.IsAbsoluteUri -or $uri.Scheme -notin @("http", "https")) {
    throw "HeliosUrl must be an absolute HTTP(S) URL."
}
$HeliosUrl = $HeliosUrl.TrimEnd('/')

$repo = Split-Path -Parent $PSScriptRoot

if ($PSCmdlet.ParameterSetName -eq "Wsl") {
    $wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
    if ($null -eq $wsl) {
        throw "wsl.exe was not found; install WSL or use -Manifest and -Binary."
    }

    $arguments = @()
    if (-not [string]::IsNullOrWhiteSpace($WslDistribution)) {
        $arguments += @("--distribution", $WslDistribution)
    }
    $arguments += @(
        "--cd", $WslRepo,
        "bash", "scripts/deploy-app.sh",
        "--url", $HeliosUrl,
        "--channel", $Channel
    )
    if ($Sequence -gt 0) {
        $arguments += @("--sequence", $Sequence.ToString([System.Globalization.CultureInfo]::InvariantCulture))
    }
    if ($SkipFrontend) {
        $arguments += "--skip-frontend"
    }
    if ($StageOnly) {
        $arguments += "--stage-only"
    }

    Write-Host "==> Build, sign and deploy from WSL: $WslRepo" -ForegroundColor Cyan
    & $wsl.Source @arguments
    Assert-LastExitCode "WSL application deployment"
    return
}

if ($StageOnly -and $Yes) {
    throw "-StageOnly and -Yes cannot be used together."
}

if (-not (Test-Path -LiteralPath $Manifest -PathType Leaf)) {
    throw "Signed manifest not found: $Manifest"
}
if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    throw "heliosd binary not found: $Binary"
}
$Manifest = (Resolve-Path -LiteralPath $Manifest).Path
$Binary = (Resolve-Path -LiteralPath $Binary).Path
if (-not [string]::IsNullOrWhiteSpace($HeliosCtl)) {
    if (-not (Test-Path -LiteralPath $HeliosCtl -PathType Leaf)) {
        throw "helios executable not found: $HeliosCtl"
    }
    $HeliosCtl = (Resolve-Path -LiteralPath $HeliosCtl).Path
}

$arguments = @(
    "--url", $HeliosUrl,
    "app-update",
    "--manifest", $Manifest,
    "--binary", $Binary
)
if ($StageOnly) {
    $arguments += "--stage-only"
} elseif ($Yes) {
    $arguments += "--yes"
}

Push-Location $repo
try {
    Write-Host "==> Transfer the signed release through $HeliosUrl" -ForegroundColor Cyan
    if ([string]::IsNullOrWhiteSpace($HeliosCtl)) {
        $cargo = Get-Command cargo -ErrorAction SilentlyContinue
        if ($null -eq $cargo) {
            throw "cargo was not found; install the Rust toolchain or provide -HeliosCtl."
        }
        & $cargo.Source run --quiet -p helios-ctl -- @arguments
        Assert-LastExitCode "helios-ctl build or application update"
    } else {
        & $HeliosCtl @arguments
        Assert-LastExitCode "application update"
    }
} finally {
    Pop-Location
}
