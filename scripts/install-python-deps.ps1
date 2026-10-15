# =====================================================================
# install-python-deps.ps1
# =====================================================================
# Cree un environnement virtuel Python local et installe paho-mqtt.
# =====================================================================

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $ScriptDir "..")

if (-not (Test-Path ".venv")) {
    Write-Host "Creation de l'environnement virtuel .venv ..." -ForegroundColor Cyan
    python -m venv .venv
}

Write-Host "Activation du venv et installation des dependances..." -ForegroundColor Cyan
& ".\.venv\Scripts\Activate.ps1"
python -m pip install --upgrade pip
python -m pip install -r devices\requirements.txt

Write-Host ""
Write-Host "Dependances installees." -ForegroundColor Green
Write-Host "Pour activer le venv dans un nouveau terminal :"
Write-Host "  .\.venv\Scripts\Activate.ps1"
