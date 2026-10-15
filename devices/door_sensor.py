"""
door_sensor.py
==============
Capteur de porte simule (ouverte/fermee).
Publie un etat sur le topic :
    home/<piece>/door/state
"""

import argparse
import logging
import random

from base_device import BaseDevice


class DoorSensor(BaseDevice):
    """Capteur de porte : OPEN ou CLOSED, change parfois aleatoirement."""

    def __init__(self, device_id, room, **kwargs):
        super().__init__(
            device_id=device_id,
            room=room,
            device_type="door",
            **kwargs,
        )
        self._state = "CLOSED"

    def _build_state_payload(self) -> dict:
        # 15% de chance que la porte change d'etat a chaque cycle
        if random.random() < 0.15:
            self._state = "OPEN" if self._state == "CLOSED" else "CLOSED"

        return {
            "device_id": self.device_id,
            "room": self.room,
            "type": "door",
            "state": self._state,
        }


def main():
    parser = argparse.ArgumentParser(description="Capteur de porte MQTT")
    parser.add_argument("--id", default="door-01")
    parser.add_argument("--room", default="entree")
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

    sensor = DoorSensor(
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
