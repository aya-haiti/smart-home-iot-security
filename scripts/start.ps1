# =====================================================================
# start.ps1 (v2)
# =====================================================================
# Demarre la stack Docker (Mosquitto vulnerable + Mosquitto securise TLS
# + Node-RED).
# =====================================================================

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $ScriptDir "..")

# Verifier passwords
$PasswordFile = "mosquitto\secure\config\passwords"
if (-not (Test-Path $PasswordFile) -or (Get-Item $PasswordFile).Length -eq 0) {
    Write-Host "Le fichier passwords est manquant. Generation..." -ForegroundColor Yellow
    & (Join-Path $ScriptDir "generate-passwords.ps1")
}

# Verifier certificats TLS
$CertFile = "mosquitto\secure\certs\server.crt"
if (-not (Test-Path $CertFile)) {
    Write-Host "Les certificats TLS sont manquants. Generation..." -ForegroundColor Yellow
    & (Join-Path $ScriptDir "generate-certs.ps1")
}

Write-Host "Demarrage des conteneurs..." -ForegroundColor Cyan
docker compose up -d

if ($LASTEXITCODE -ne 0) {
    Write-Host "Erreur lors du demarrage." -ForegroundColor Red
    exit 1
}

Start-Sleep -Seconds 3

Write-Host ""
Write-Host "=========================================================" -ForegroundColor Green
Write-Host " Smart Home IoT Security v2 - stack demarree" -ForegroundColor Green
Write-Host "=========================================================" -ForegroundColor Green
Write-Host ""
Write-Host " Broker MQTT VULNERABLE : tcp://localhost:1883" -ForegroundColor Yellow
Write-Host "   (acces anonyme autorise - DEMO UNIQUEMENT)" -ForegroundColor DarkYellow
Write-Host ""
Write-Host " Broker MQTT SECURISE TLS : tls://localhost:8883" -ForegroundColor Green
Write-Host "   (TLS 1.2 + auth + ACL + anti-DoS)" -ForegroundColor DarkGreen
Write-Host "   CA : mosquitto\secure\certs\ca.crt" -ForegroundColor DarkGreen
Write-Host ""
Write-Host " Node-RED Editor    : http://localhost:1880" -ForegroundColor Cyan
Write-Host " Node-RED Dashboard : http://localhost:1880/ui" -ForegroundColor Cyan
Write-Host ""
Write-Host "Logs : docker compose logs -f"
Write-Host "Arret : .\scripts\stop.ps1"
