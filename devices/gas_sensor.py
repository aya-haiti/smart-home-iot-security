"""
gas_sensor.py
=============
Capteur de gaz simule.
Publie un niveau de gaz (en ppm) et un statut sur le topic :
    home/<piece>/gas/state
Si le niveau depasse un seuil, un statut ALERT est emis.
"""

import argparse
import logging
import random

from base_device import BaseDevice


class GasSensor(BaseDevice):
    """Capteur de gaz : valeur normale autour de 100 ppm, alerte au-dessus de 400."""

    ALERT_THRESHOLD = 400  # ppm

    def __init__(self, device_id, room, **kwargs):
        super().__init__(
            device_id=device_id,
            room=room,
            device_type="gas",
            **kwargs,
        )
        self._current_ppm = 100.0

    def _build_state_payload(self) -> dict:
        # Variation aleatoire, avec parfois un pic pour simuler une fuite
        if random.random() < 0.05:
            # 5% de chance d'un pic pour la demo
            self._current_ppm += random.uniform(50, 350)
        else:
            self._current_ppm += random.uniform(-15, 15)
        self._current_ppm = max(50.0, min(800.0, self._current_ppm))

        status = "ALERT" if self._current_ppm > self.ALERT_THRESHOLD else "OK"

        return {
            "device_id": self.device_id,
            "room": self.room,
            "type": "gas",
            "value": round(self._current_ppm, 0),
            "unit": "ppm",
            "status": status,
        }


def main():
    parser = argparse.ArgumentParser(description="Capteur de gaz MQTT")
    parser.add_argument("--id", default="gas-01")
    parser.add_argument("--room", default="cuisine")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=1883)
    parser.add_argument("--user", default=None)
    parser.add_argument("--password", default=None)
    parser.add_argument("--interval", type=int, default=5)
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    )

    sensor = GasSensor(
        device_id=args.id,
        room=args.room,
        broker_host=args.host,
        broker_port=args.port,
        username=args.user,
        password=args.password,
        publish_interval=args.interval,
    )
    sensor.start()


if __name__ == "__main__":
    main()
