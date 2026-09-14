param(
    [Parameter(Mandatory = $true)]
    [string]$PfxPath,

    [Parameter(Mandatory = $true)]
    [string]$RootCertificatePath,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedThumbprint,

    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Normalize-Thumbprint([string]$Thumbprint) {
    $normalized = $Thumbprint.Replace(" ", "").Replace(":", "").ToUpperInvariant()
    if ($normalized -notmatch '^[0-9A-F]{40}$') {
        throw "ExpectedThumbprint doit être une empreinte SHA-1 hexadécimale de 40 caractères."
    }
    return $normalized
}

if (-not (Test-Path -LiteralPath $PfxPath -PathType Leaf)) {
    throw "PFX introuvable : $PfxPath"
}
if (-not (Test-Path -LiteralPath $RootCertificatePath -PathType Leaf)) {
    throw "Certificat racine introuvable : $RootCertificatePath"
}

$expected = Normalize-Thumbprint $ExpectedThumbprint
$timestampUri = [System.Uri]$TimestampUrl
if (-not $timestampUri.IsAbsoluteUri -or $timestampUri.Scheme -notin @("http", "https")) {
    throw "TimestampUrl doit être une URL HTTP(S) absolue."
}

$signTool = Get-Command signtool.exe -ErrorAction SilentlyContinue | Select-Object -First 1
$signToolPath = if ($null -ne $signTool) { $signTool.Source } else { $null }
if ([string]::IsNullOrWhiteSpace($signToolPath)) {
    $kitsRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    if (Test-Path -LiteralPath $kitsRoot -PathType Container) {
        $signToolPath = Get-ChildItem -LiteralPath $kitsRoot -Filter signtool.exe -Recurse |
            Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
            Sort-Object FullName -Descending |
            Select-Object -First 1 -ExpandProperty FullName
    }
}
if ([string]::IsNullOrWhiteSpace($signToolPath)) {
    throw "signtool.exe est introuvable ; installer le SDK Windows avant de configurer la signature."
}

$password = Read-Host "Mot de passe du PFX Orion" -AsSecureString
$pfx = Get-PfxData -FilePath $PfxPath -Password $password
$leaf = @($pfx.EndEntityCertificates) | Where-Object {
    (Normalize-Thumbprint $_.Thumbprint) -eq $expected
} | Select-Object -First 1
if ($null -eq $leaf) {
    throw "Le PFX ne contient pas le certificat attendu ($expected)."
}
if (-not ($leaf.EnhancedKeyUsageList.ObjectId.Value -contains "1.3.6.1.5.5.7.3.3")) {
    throw "Le certificat attendu ne porte pas l'usage étendu Code Signing."
}
if ($leaf.NotAfter -le (Get-Date)) {
    throw "Le certificat de signature est expiré depuis le $($leaf.NotAfter.ToString('u'))."
}
if ($leaf.NotBefore -gt (Get-Date)) {
    throw "Le certificat de signature ne sera valide qu'à partir du $($leaf.NotBefore.ToString('u'))."
}

$root = Get-PfxCertificate -FilePath $RootCertificatePath
$pfxRoots = @($pfx.OtherCertificates) | Where-Object { $_.Subject -eq $_.Issuer }
if (-not ($pfxRoots.Thumbprint -contains $root.Thumbprint)) {
    throw "Le certificat racine fourni ne correspond pas à la chaîne contenue dans le PFX."
}

# La racine est approuvée seulement pour le compte de signature. Son
# déploiement dans LocalMachine\Root sur les postes Orion reste une opération
# d'administration hors bande.
Import-Certificate `
    -FilePath $RootCertificatePath `
    -CertStoreLocation Cert:\CurrentUser\Root | Out-Null

# Ne pas passer -Exportable : la clé importée ne doit pas pouvoir ressortir du
# magasin du compte Windows dédié au runner de signature.
Import-PfxCertificate `
    -FilePath $PfxPath `
    -CertStoreLocation Cert:\CurrentUser\My `
    -Password $password | Out-Null

$installed = Get-Item "Cert:\CurrentUser\My\$expected" -ErrorAction Stop
if (-not $installed.HasPrivateKey) {
    throw "Le certificat a été importé sans sa clé privée."
}

[Environment]::SetEnvironmentVariable("ORION_SIGNING_CERT_SHA1", $expected, "User")
[Environment]::SetEnvironmentVariable("ORION_TIMESTAMP_URL", $TimestampUrl, "User")
[Environment]::SetEnvironmentVariable("TAURI_WINDOWS_SIGNTOOL_PATH", $signToolPath, "User")

Write-Output "Certificat Orion installé pour $env:USERNAME : $expected"
Write-Output "Horodateur RFC 3161 configuré : $TimestampUrl"
Write-Output "SignTool configuré : $signToolPath"
Write-Output "Redémarrer le runner GitHub après cette installation."
Write-Warning "Supprimer la copie de transfert du PFX après avoir vérifié un premier build signé."
