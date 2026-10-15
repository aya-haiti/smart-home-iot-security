"""
light_device.py
===============
Lampe connectee simulee (actionneur).

Publie son etat sur :       home/<piece>/light/state
Ecoute des commandes sur :  home/<piece>/light/cmd

Format des commandes acceptees :
    {"action": "ON"}    -> allume la lampe
    {"action": "OFF"}   -> eteint la lampe
    {"intensity": 75}   -> regle l'intensite (0-100)
"""

import argparse
import logging

from base_device import BaseDevice


class LightDevice(BaseDevice):
    """Lampe connectee : ON/OFF + intensite 0-100."""

    def __init__(self, device_id, room, **kwargs):
        super().__init__(
            device_id=device_id,
            room=room,
            device_type="light",
            **kwargs,
        )
        self._state = "OFF"
        self._intensity = 0

    def _listens_to_commands(self) -> bool:
        return True

    def _build_state_payload(self) -> dict:
        return {
            "device_id": self.device_id,
            "room": self.room,
            "type": "light",
            "state": self._state,
            "intensity": self._intensity,
        }

    def _on_command(self, payload) -> None:
        """Traite une commande recue sur le topic cmd."""
        if not isinstance(payload, dict):
            self.logger.warning("Commande invalide (format) : %s", payload)
            return

        if "action" in payload:
            action = str(payload["action"]).upper()
            if action in ("ON", "OFF"):
                self._state = action
                if action == "ON" and self._intensity == 0:
                    self._intensity = 50  # intensite par defaut
                if action == "OFF":
                    self._intensity = 0
                self.logger.info("Lampe -> %s (intensite=%s)", self._state, self._intensity)

        if "intensity" in payload:
            try:
                value = int(payload["intensity"])
                value = max(0, min(100, value))
                self._intensity = value
                self._state = "ON" if value > 0 else "OFF"
                self.logger.info("Intensite reglee a %s", value)
            except (TypeError, ValueError):
                self.logger.warning("Intensite invalide : %s", payload["intensity"])

        # Re-publication immediate de l'etat apres commande
        import json
        self.client.publish(
            self.state_topic, json.dumps(self._build_state_payload()), qos=0
        )


def main():
    parser = argparse.ArgumentParser(description="Lampe connectee MQTT")
    parser.add_argument("--id", default="light-01")
    parser.add_argument("--room", default="salon")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=1883)
    parser.add_argument("--user", default=None)
    parser.add_argument("--password", default=None)
    parser.add_argument("--interval", type=int, default=10)
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    )

    light = LightDevice(
        device_id=args.id,
        room=args.room,
        broker_host=args.host,
        broker_port=args.port,
        username=args.user,
        password=args.password,
        publish_interval=args.interval,
    )
    light.start()


if __name__ == "__main__":
    main()
