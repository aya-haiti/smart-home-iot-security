"""
run_all_devices.py (v2)
=======================
Lance toute la maison connectee en une seule commande.

Nouveautes v2 :
 - support TLS via --ca (broker securise sur 8883)

Usage :
    # Mode VULNERABLE (broker sans authentification)
    python run_all_devices.py --port 1883

    # Mode SECURISE TLS (broker avec auth + ACL + TLS)
    python run_all_devices.py --port 8883 --secure-multi-user \
        --ca ../mosquitto/secure/certs/ca.crt
"""

import argparse
import logging
import threading
import time

from temperature_sensor import TemperatureSensor
from gas_sensor import GasSensor
from door_sensor import DoorSensor
from light_device import LightDevice
from ac_device import ACDevice


def start_device(device):
    """Demarre un device. A executer dans un thread."""
    try:
        device.start()
    except Exception as e:
        logging.error("Erreur device %s : %s", device.device_id, e)


def main():
    parser = argparse.ArgumentParser(
        description="Lance tous les devices de la maison connectee"
    )
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=1883)
    parser.add_argument("--user", default=None)
    parser.add_argument("--password", default=None)
    parser.add_argument(
        "--secure-multi-user", action="store_true",
        help="Utilise un compte distinct par role (sensor_user / actuator_user)",
    )
    parser.add_argument(
        "--ca", default=None,
        help="Chemin vers le certificat CA (active TLS)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    )

    if args.secure_multi_user:
        sensor_user = ("sensor_user", "sensor_pass")
        actuator_user = ("actuator_user", "actuator_pass")
    else:
        sensor_user = (args.user, args.password)
        actuator_user = (args.user, args.password)

    common = {
        "broker_host": args.host,
        "broker_port": args.port,
        "tls_ca_path": args.ca,
    }

    devices = [
        TemperatureSensor(
            device_id="temp-01", room="salon",
            username=sensor_user[0], password=sensor_user[1],
            publish_interval=5, **common,
        ),
        GasSensor(
            device_id="gas-01", room="cuisine",
            username=sensor_user[0], password=sensor_user[1],
            publish_interval=5, **common,
        ),
        DoorSensor(
            device_id="door-01", room="entree",
            username=sensor_user[0], password=sensor_user[1],
            publish_interval=6, **common,
        ),
        LightDevice(
            device_id="light-01", room="salon",
            username=actuator_user[0], password=actuator_user[1],
            publish_interval=10, **common,
        ),
        ACDevice(
            device_id="ac-01", room="chambre",
            username=actuator_user[0], password=actuator_user[1],
            publish_interval=10, **common,
        ),
    ]

    threads = []
    for device in devices:
        t = threading.Thread(target=start_device, args=(device,), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.3)

    print("\n" + "=" * 60)
    print(" Maison connectee demarree. Ctrl+C pour arreter.")
    print("=" * 60 + "\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nArret en cours ...")
        for device in devices:
            device.stop()


if __name__ == "__main__":
    main()
