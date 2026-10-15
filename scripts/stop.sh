#!/usr/bin/env bash
# =====================================================================
# stop.sh
# =====================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$(dirname "$SCRIPT_DIR")"
echo "Arret des conteneurs..."
docker compose down
echo "Stack arretee."
