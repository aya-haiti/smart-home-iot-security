#!/usr/bin/env bash
# =====================================================================
# install-python-deps.sh
# =====================================================================
# Cree un environnement virtuel Python local et installe paho-mqtt.
# =====================================================================

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$(dirname "$SCRIPT_DIR")"

if [[ ! -d ".venv" ]]; then
    echo "Creation du venv .venv ..."
    python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r devices/requirements.txt

echo ""
echo "Dependances installees."
echo "Pour activer le venv dans un nouveau terminal :"
echo "  source .venv/bin/activate"
