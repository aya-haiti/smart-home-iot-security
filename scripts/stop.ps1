# =====================================================================
# stop.ps1
# =====================================================================
# Arrete et supprime les conteneurs Docker du projet.
# =====================================================================

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $ScriptDir "..")

Write-Host "Arret des conteneurs..." -ForegroundColor Cyan
docker compose down
Write-Host "Stack arretee." -ForegroundColor Green
