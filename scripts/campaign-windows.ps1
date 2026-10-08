param(
    # Profil Orion de ce poste : celui dont l'identité est scellée ici.
    [string]$Profile = "poste-windows",
    # Joue aussi les scénarios lents (lien de vivacité : 40 s d'attente).
    [switch]$Soak,
    # URL de l'API interne, joignable seulement une fois le tunnel monté.
    [string]$HeliosUrl = "http://100.64.0.1:8080"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Campagne de la négociation de clé, depuis le poste Windows.
#
# # Pourquoi ici et pas en régression
#
# Les scénarios crypto tournent partout, mais le reste demande ce que seul ce
# poste possède : un profil enrôlé et une identité scellée par DPAPI. La
# régression Linux ne peut donc pas les jouer — elle ne peut que les compiler.
# Cette campagne est l'autre moitié : celle qui parle à la vraie gateway.
#
# # Ce qu'elle fait au pair
#
# Elle négocie pour de vrai. La gateway pose puis retire un PSK sur le plan de
# données : un Orion connecté avec le MÊME profil perd son tunnel. À jouer
# quand le poste ne sert pas.

function Section($Title) {
    Write-Host ""
    Write-Host "══ $Title" -ForegroundColor Cyan
}

$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

$failed = @()

function Step($Name, [scriptblock]$Body) {
    Section $Name
    try {
        & $Body
        if ($LASTEXITCODE -ne 0) { throw "code de sortie $LASTEXITCODE" }
        Write-Host "  OK  $Name" -ForegroundColor Green
    } catch {
        Write-Host "  ÉCHEC  $Name : $_" -ForegroundColor Red
        $script:failed += $Name
    }
}

# 1. Ce qui se vérifie sans rien toucher : le binaire compile avec le vrai
#    backend, et l'outillage répond.
Step "tests de sécurité Orion sur Windows" {
    cargo test -p orion-core --all-features
    cargo test -p orion --all-features
}

Step "compilation du client avec le backend réel" {
    cargo build -p orion --features wireguard
}

Step "compilation de l'outillage opérateur" {
    cargo build -p helios
}

# 2. Le profil, tel que ce poste le détient.
Step "lecture du profil « $Profile »" {
    cargo run -q -p helios -- campaign --only negociation-de-cle --profile $Profile
}

# 3. La campagne complète, y compris les scénarios lents si demandés.
if ($Soak) {
    Step "campagne complète (avec scénarios lents)" {
        cargo run -q -p helios -- campaign --only negociation-de-cle --profile $Profile --soak
    }
}

# 4. Ce qui ne se voit qu'à travers le tunnel : l'API interne. Ignorée si le
#    tunnel n'est pas monté — ce n'est pas un échec de la négociation.
Section "API interne derrière le tunnel"
try {
    $status = Invoke-RestMethod -Uri "$HeliosUrl/api/status" -TimeoutSec 5
    Write-Host "  état de la gateway : $($status.state)" -ForegroundColor Green
    Step "campagne provisioning + plan de données" {
        cargo run -q -p helios -- --url $HeliosUrl campaign --only protocole
    }
} catch {
    Write-Host "  ignoré : $HeliosUrl injoignable (tunnel non monté ?)" -ForegroundColor DarkGray
}

Section "Bilan"
if ($failed.Count -eq 0) {
    Write-Host "  campagne passée" -ForegroundColor Green
    exit 0
}
Write-Host "  $($failed.Count) étape(s) en échec :" -ForegroundColor Red
$failed | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
exit 1
