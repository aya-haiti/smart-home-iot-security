# =====================================================================
# generate-passwords.ps1 (v2)
# =====================================================================
# Genere le fichier de mots de passe Mosquitto pour le broker securise.
#
# Comptes : sensor_user, actuator_user, dashboard_user, admin_user
#
# Options :
#   -Strong   Genere des mots de passe aleatoires forts (24 chars)
#             et les ecrit dans CREDENTIALS.txt (deja ignore par .gitignore)
# =====================================================================

param(
    [switch]$Strong
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $ScriptDir "..")

$ConfigDir = Join-Path (Get-Location) "mosquitto\secure\config"
$PasswordFile = Join-Path $ConfigDir "passwords"
$CredentialsFile = Join-Path (Get-Location) "CREDENTIALS.txt"

if (-not (Test-Path $ConfigDir)) {
    New-Item -ItemType Directory -Path $ConfigDir | Out-Null
}

if (Test-Path $PasswordFile) { Remove-Item $PasswordFile }
New-Item -ItemType File -Path $PasswordFile -Force | Out-Null

function New-StrongPassword {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#%+_-".ToCharArray()
    -join (1..24 | ForEach-Object { $chars | Get-Random })
}

if ($Strong) {
    $accounts = @(
        @{ User = "sensor_user";    Pass = (New-StrongPassword) },
        @{ User = "actuator_user";  Pass = (New-StrongPassword) },
        @{ User = "dashboard_user"; Pass = (New-StrongPassword) },
        @{ User = "admin_user";     Pass = (New-StrongPassword) }
    )
    Write-Host "Generation des mots de passe FORTS (24 chars aleatoires)..." -ForegroundColor Cyan
} else {
    $accounts = @(
        @{ User = "sensor_user";    Pass = "sensor_pass" },
        @{ User = "actuator_user";  Pass = "actuator_pass" },
        @{ User = "dashboard_user"; Pass = "dashboard_pass" },
        @{ User = "admin_user";     Pass = "admin_pass" }
    )
    Write-Host "Generation des mots de passe DEMO (lisibles)..." -ForegroundColor Cyan
    Write-Host "Pour des mots de passe forts : .\scripts\generate-passwords.ps1 -Strong" -ForegroundColor Yellow
}

$MountPath = ($ConfigDir -replace '\\', '/')

foreach ($acc in $accounts) {
    Write-Host ("  - Ajout de " + $acc.User) -ForegroundColor Yellow
    docker run --rm `
        -v "${MountPath}:/mosquitto/config" `
        eclipse-mosquitto:2.0 `
        mosquitto_passwd -b /mosquitto/config/passwords $acc.User $acc.Pass | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Erreur lors de l'ajout de $($acc.User)" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "Fichier passwords genere avec succes !" -ForegroundColor Green

if ($Strong) {
    $content = "# Comptes generes par generate-passwords.ps1 -Strong`n"
    $content += "# CONFIDENTIEL : ne pas committer ce fichier (deja ignore par .gitignore)`n"
    foreach ($acc in $accounts) {
        $content += ("{0,-15} : {1}`n" -f $acc.User, $acc.Pass)
    }
    Set-Content -Path $CredentialsFile -Value $content -Encoding UTF8
    Write-Host "Mots de passe ecrits dans : $CredentialsFile" -ForegroundColor Green
} else {
    Write-Host "Comptes :"
    foreach ($acc in $accounts) {
        Write-Host ("  " + $acc.User + " / " + $acc.Pass)
    }
}
