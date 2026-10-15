#!/usr/bin/env bash
# =====================================================================
# generate-passwords.sh
# =====================================================================
# Genere le fichier de mots de passe Mosquitto pour le broker securise.
# Utilise le binaire mosquitto_passwd present dans l'image Docker
# eclipse-mosquitto, donc Mosquitto N'A PAS besoin d'etre installe en
# local.
#
# Comptes crees :
#   sensor_user    / sensor_pass        (ou genere si --strong)
#   actuator_user  / actuator_pass
#   dashboard_user / dashboard_pass
#   admin_user     / admin_pass
#
# Options :
#   --strong   Genere des mots de passe aleatoires forts (24 chars)
#              et les ecrit dans CREDENTIALS.txt
# =====================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="$PROJECT_ROOT/mosquitto/secure/config"
PASSWORD_FILE="$CONFIG_DIR/passwords"
CREDENTIALS_FILE="$PROJECT_ROOT/CREDENTIALS.txt"

STRONG=false
if [[ "${1:-}" == "--strong" ]]; then
    STRONG=true
fi

mkdir -p "$CONFIG_DIR"
rm -f "$PASSWORD_FILE"
touch "$PASSWORD_FILE"

# Genere un mot de passe fort (24 chars alpha-num + symboles surs)
gen_password() {
    # OpenSSL est partout (souvent), tr -dc filtre les caracteres surs
    LC_ALL=C tr -dc 'A-Za-z0-9!@#%+_-' < /dev/urandom | head -c 24
}

if $STRONG; then
    SENSOR_PASS=$(gen_password)
    ACTUATOR_PASS=$(gen_password)
    DASHBOARD_PASS=$(gen_password)
    ADMIN_PASS=$(gen_password)
    MODE="MODE FORT (mots de passe aleatoires 24 chars)"
else
    SENSOR_PASS="sensor_pass"
    ACTUATOR_PASS="actuator_pass"
    DASHBOARD_PASS="dashboard_pass"
    ADMIN_PASS="admin_pass"
    MODE="MODE DEMO (mots de passe lisibles)"
fi

echo "Generation du fichier passwords ($MODE)..."

# On execute mosquitto_passwd dans un conteneur jetable
MOUNT_PATH="$CONFIG_DIR"

for entry in "sensor_user:$SENSOR_PASS" \
             "actuator_user:$ACTUATOR_PASS" \
             "dashboard_user:$DASHBOARD_PASS" \
             "admin_user:$ADMIN_PASS"; do
    user="${entry%%:*}"
    pass="${entry#*:}"
    echo "  - Ajout de $user"
    docker run --rm \
        -v "${MOUNT_PATH}:/mosquitto/config" \
        eclipse-mosquitto:2.0 \
        mosquitto_passwd -b /mosquitto/config/passwords "$user" "$pass" \
        > /dev/null
done

echo ""
echo "Fichier passwords genere : $PASSWORD_FILE"
echo ""

if $STRONG; then
    cat > "$CREDENTIALS_FILE" <<EOF
# Comptes generes par generate-passwords.sh --strong
# CONFIDENTIEL : ne pas committer ce fichier (deja ignore par .gitignore)
sensor_user    : $SENSOR_PASS
actuator_user  : $ACTUATOR_PASS
dashboard_user : $DASHBOARD_PASS
admin_user     : $ADMIN_PASS
EOF
    chmod 600 "$CREDENTIALS_FILE"
    echo "Mots de passe ecrits dans : $CREDENTIALS_FILE"
    echo "(deja ignore par .gitignore)"
else
    echo "Comptes crees :"
    echo "  sensor_user    / sensor_pass"
    echo "  actuator_user  / actuator_pass"
    echo "  dashboard_user / dashboard_pass"
    echo "  admin_user     / admin_pass"
    echo ""
    echo "Pour des mots de passe forts : ./scripts/generate-passwords.sh --strong"
fi
