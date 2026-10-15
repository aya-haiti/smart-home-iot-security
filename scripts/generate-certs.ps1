# =====================================================================
# generate-certs.ps1
# =====================================================================
# Genere des certificats TLS auto-signes pour le broker MQTT securise.
# Utilise OpenSSL via le conteneur Docker eclipse-mosquitto:2.0
# (qui contient openssl), donc PAS d'installation OpenSSL requise sous
# Windows.
# =====================================================================

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $ScriptDir "..")
$CertsDir = Join-Path (Get-Location) "mosquitto\secure\certs"

if (-not (Test-Path $CertsDir)) {
    New-Item -ItemType Directory -Path $CertsDir | Out-Null
}

$MountPath = ($CertsDir -replace '\\', '/')

Write-Host "Generation des certificats TLS..." -ForegroundColor Cyan

# Tout faire dans un seul conteneur jetable pour eviter les problemes de chemin
docker run --rm `
    -v "${MountPath}:/certs" `
    --entrypoint sh `
    eclipse-mosquitto:2.0 -c @"
cd /certs
# CA
openssl genrsa -out ca.key 2048 2>/dev/null
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
    -subj '/C=MA/ST=Fes/L=Fes/O=SmartHomeIoT-Demo/OU=CA/CN=SmartHomeIoT-CA'
# Server
openssl genrsa -out server.key 2048 2>/dev/null
openssl req -new -key server.key -out server.csr \
    -subj '/C=MA/ST=Fes/L=Fes/O=SmartHomeIoT-Demo/OU=Broker/CN=localhost'
cat > server.ext <<EOF
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
DNS.2 = mosquitto-secure
IP.1  = 127.0.0.1
EOF
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365 -extfile server.ext
rm -f server.csr server.ext ca.srl
chmod 644 ca.crt server.crt
chmod 600 server.key ca.key
"@

if ($LASTEXITCODE -ne 0) {
    Write-Host "Erreur lors de la generation des certificats" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Certificats generes dans : $CertsDir" -ForegroundColor Green
Get-ChildItem $CertsDir | Format-Table Name, Length, LastWriteTime
Write-Host ""
Write-Host "Astuce : importer ca.crt dans MQTT Explorer pour eviter le warning" -ForegroundColor Yellow
Write-Host "         'certificat non verifiable'." -ForegroundColor Yellow
