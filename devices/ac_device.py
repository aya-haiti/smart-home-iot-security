"""
ac_device.py
============
Climatisation connectee simulee (actionneur).

Publie son etat sur :       home/<piece>/ac/state
Ecoute des commandes sur :  home/<piece>/ac/cmd

Format des commandes acceptees :
    {"action": "ON"}              -> allume la clim
    {"action": "OFF"}             -> eteint la clim
    {"target_temp": 21}           -> regle la temperature cible (16-30)
    {"mode": "COOL"|"HEAT"|"FAN"} -> change le mode
"""

import argparse
import logging

from base_device import BaseDevice


class ACDevice(BaseDevice):
    """Climatisation : ON/OFF, mode (COOL/HEAT/FAN), temperature cible."""

    VALID_MODES = ("COOL", "HEAT", "FAN")

    def __init__(self, device_id, room, **kwargs):
        super().__init__(
            device_id=device_id,
            room=room,
            device_type="ac",
            **kwargs,
        )
        self._state = "OFF"
        self._mode = "COOL"
        self._target_temp = 22

    def _listens_to_commands(self) -> bool:
        return True

    def _build_state_payload(self) -> dict:
        return {
            "device_id": self.device_id,
            "room": self.room,
            "type": "ac",
            "state": self._state,
            "mode": self._mode,
            "target_temp": self._target_temp,
        }

    def _on_command(self, payload) -> None:
        if not isinstance(payload, dict):
            self.logger.warning("Commande invalide (format) : %s", payload)
            return

        if "action" in payload:
            action = str(payload["action"]).upper()
            if action in ("ON", "OFF"):
                self._state = action
                self.logger.info("Climatisation -> %s", self._state)

        if "mode" in payload:
            mode = str(payload["mode"]).upper()
            if mode in self.VALID_MODES:
                self._mode = mode
                self.logger.info("Mode -> %s", mode)
            else:
                self.logger.warning("Mode invalide : %s", payload["mode"])

        if "target_temp" in payload:
            try:
                temp = int(payload["target_temp"])
                temp = max(16, min(30, temp))
                self._target_temp = temp
                self.logger.info("Temperature cible -> %s C", temp)
            except (TypeError, ValueError):
                self.logger.warning("Temperature invalide : %s", payload["target_temp"])

        import json
        self.client.publish(
            self.state_topic, json.dumps(self._build_state_payload()), qos=0
        )


def main():
    parser = argparse.ArgumentParser(description="Climatisation MQTT")
    parser.add_argument("--id", default="ac-01")
    parser.add_argument("--room", default="chambre")
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

    ac = ACDevice(
        device_id=args.id,
        room=args.room,
        broker_host=args.host,
        broker_port=args.port,
        username=args.user,
        password=args.password,
        publish_interval=args.interval,
    )
    ac.start()


if __name__ == "__main__":
    main()
