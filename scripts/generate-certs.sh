#!/usr/bin/env bash
# =====================================================================
# generate-certs.sh
# =====================================================================
# Genere des certificats TLS auto-signes pour le broker MQTT securise.
# Cree :
#   - une autorite de certification (CA) locale
#   - un certificat serveur signe par cette CA
#
# Les fichiers sont places dans mosquitto/secure/certs/
# =====================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CERTS_DIR="$PROJECT_ROOT/mosquitto/secure/certs"

mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

echo "=========================================================="
echo " Generation des certificats TLS pour Mosquitto securise"
echo "=========================================================="

# 1) Cle privee de la CA + certificat de la CA (validite 10 ans)
echo "[1/3] Generation de l'autorite de certification (CA)..."
openssl genrsa -out ca.key 2048 2>/dev/null
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
    -subj "/C=MA/ST=Fes/L=Fes/O=SmartHomeIoT-Demo/OU=CA/CN=SmartHomeIoT-CA" 2>/dev/null

# 2) Cle privee + CSR pour le serveur Mosquitto
echo "[2/3] Generation du certificat serveur..."
openssl genrsa -out server.key 2048 2>/dev/null
openssl req -new -key server.key -out server.csr \
    -subj "/C=MA/ST=Fes/L=Fes/O=SmartHomeIoT-Demo/OU=Broker/CN=localhost" 2>/dev/null

# Extension pour autoriser localhost et 127.0.0.1 dans le SAN
cat > server.ext <<EOF
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
DNS.2 = mosquitto-secure
IP.1  = 127.0.0.1
EOF

# 3) Signature du CSR par la CA (validite 1 an)
echo "[3/3] Signature du certificat par la CA..."
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365 -extfile server.ext 2>/dev/null

# Permissions correctes pour Mosquitto (uid 1883 dans l'image officielle)
chmod 644 ca.crt server.crt
chmod 600 server.key ca.key

# Cleanup des fichiers intermediaires
rm -f server.csr server.ext ca.srl

echo ""
echo "Certificats generes dans : $CERTS_DIR"
ls -la "$CERTS_DIR"
echo ""
echo "Pour les clients MQTT, utiliser :"
echo "  --cafile $CERTS_DIR/ca.crt"
echo ""
echo "Astuce : importer ca.crt dans MQTT Explorer pour eviter le warning"
echo "         'certificat non verifiable'."
