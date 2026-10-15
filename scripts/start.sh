#!/usr/bin/env bash
# =====================================================================
# start.sh
# =====================================================================
# Demarre la stack Docker (Mosquitto vulnerable + Mosquitto securise TLS
# + Node-RED) et affiche les URLs et ports utiles.
# =====================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# Verifier passwords
if [[ ! -s "mosquitto/secure/config/passwords" ]]; then
    echo "Le fichier passwords est manquant. Generation..."
    bash "$SCRIPT_DIR/generate-passwords.sh"
fi

# Verifier certificats TLS
if [[ ! -f "mosquitto/secure/certs/server.crt" ]]; then
    echo "Les certificats TLS sont manquants. Generation..."
    bash "$SCRIPT_DIR/generate-certs.sh"
fi

echo "Demarrage des conteneurs..."
docker compose up -d

sleep 3

cat <<EOF

=========================================================
 Smart Home IoT Security v2 - stack demarree
=========================================================

 Broker MQTT VULNERABLE : tcp://localhost:1883
   (acces anonyme autorise - DEMO UNIQUEMENT)

 Broker MQTT SECURISE TLS : tls://localhost:8883
   (TLS 1.2 + auth + ACL + anti-DoS)
   CA : mosquitto/secure/certs/ca.crt

 Node-RED Editor    : http://localhost:1880
 Node-RED Dashboard : http://localhost:1880/ui

Logs en direct  : docker compose logs -f
Arret           : ./scripts/stop.sh
EOF
