"""
temperature_sensor.py
=====================
Capteur de temperature simule.
Publie une valeur (en degres Celsius) sur le topic :
    home/<piece>/temperature/state
"""

import argparse
import logging
import random

from base_device import BaseDevice


class TemperatureSensor(BaseDevice):
    """Capteur de temperature : publie une mesure realiste autour de 22 C."""

    def __init__(self, device_id, room, **kwargs):
        super().__init__(
            device_id=device_id,
            room=room,
            device_type="temperature",
            **kwargs,
        )
        # Temperature de depart proche de 22 C
        self._current_temp = 22.0

    def _build_state_payload(self) -> dict:
        # Variation aleatoire pour simuler la realite
        self._current_temp += random.uniform(-0.4, 0.4)
        # Bornage entre 15 et 30 C
        self._current_temp = max(15.0, min(30.0, self._current_temp))
        return {
            "device_id": self.device_id,
            "room": self.room,
            "type": "temperature",
            "value": round(self._current_temp, 1),
            "unit": "C",
        }


def main():
    parser = argparse.ArgumentParser(description="Capteur de temperature MQTT")
    parser.add_argument("--id", default="temp-01", help="Identifiant du device")
    parser.add_argument("--room", default="salon", help="Piece de la maison")
    parser.add_argument("--host", default="localhost", help="Hote du broker MQTT")
    parser.add_argument("--port", type=int, default=1883, help="Port du broker")
    parser.add_argument("--user", default=None, help="Nom d'utilisateur MQTT")
    parser.add_argument("--password", default=None, help="Mot de passe MQTT")
    parser.add_argument("--interval", type=int, default=5, help="Intervalle (s)")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    )

    sensor = TemperatureSensor(
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
