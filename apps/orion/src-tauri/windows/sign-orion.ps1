param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Artifact
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Chemin non signé, explicite et bruyant. La CI ne détient aucun certificat et
# ne doit pas en détenir (ADR-004 §7) : elle produit un artefact destiné à la
# signature hors ligne. La comparaison est stricte — une valeur approchante ne
# désactive pas la signature — et le job qui emprunte ce chemin renomme les
# fichiers en `-unsigned`, de sorte qu'aucun d'eux ne puisse être confondu avec
# une release.
if ($env:ORION_UNSIGNED_FOR_OFFLINE_SIGNING -eq "1") {
    Write-Warning "ORION_UNSIGNED_FOR_OFFLINE_SIGNING=1 : $Artifact n'est PAS signé."
    Write-Warning "Cet artefact doit être signé hors ligne avant toute distribution."
    exit 0
}

$thumbprint = $env:ORION_SIGNING_CERT_SHA1
if ([string]::IsNullOrWhiteSpace($thumbprint)) {
    throw "ORION_SIGNING_CERT_SHA1 doit contenir l'empreinte du certificat Authenticode installé."
}
$thumbprint = $thumbprint.Replace(" ", "")
if ($thumbprint -notmatch '^[0-9A-Fa-f]{40}$') {
    throw "ORION_SIGNING_CERT_SHA1 doit être une empreinte SHA-1 hexadécimale de 40 caractères."
}

$timestampUrl = $env:ORION_TIMESTAMP_URL
if ([string]::IsNullOrWhiteSpace($timestampUrl)) {
    throw "ORION_TIMESTAMP_URL est obligatoire : aucune signature Orion sans horodatage RFC 3161."
}
$timestampUri = [System.Uri]$timestampUrl
if (-not $timestampUri.IsAbsoluteUri -or $timestampUri.Scheme -notin @("http", "https")) {
    throw "ORION_TIMESTAMP_URL doit être une URL HTTP(S) absolue."
}

$signTool = $env:TAURI_WINDOWS_SIGNTOOL_PATH
if ([string]::IsNullOrWhiteSpace($signTool)) {
    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        throw "signtool.exe est introuvable ; installer le SDK Windows ou définir TAURI_WINDOWS_SIGNTOOL_PATH."
    }
    $signTool = $command.Source
}
if (-not (Test-Path -LiteralPath $Artifact -PathType Leaf)) {
    throw "Artefact à signer introuvable : $Artifact"
}

& $signTool sign /sha1 $thumbprint /fd SHA256 /tr $timestampUrl /td SHA256 /d "Orion" $Artifact
if ($LASTEXITCODE -ne 0) {
    throw "La signature ou l'horodatage Authenticode a échoué pour $Artifact (code $LASTEXITCODE)."
}

& $signTool verify /pa /tw $Artifact
if ($LASTEXITCODE -ne 0) {
    throw "La vérification Authenticode horodatée a échoué pour $Artifact (code $LASTEXITCODE)."
}
