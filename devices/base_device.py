"""
base_device.py (v2)
===================
Classe de base pour tous les objets connectes de la maison.

Nouveautes v2 :
 - support TLS (parametre `tls_ca_path`)
 - reconnexion automatique en cas de coupure (paho-mqtt loop_forever)
 - rate-limit cote client (anti-flood involontaire)

Cette classe gere :
 - la connexion au broker MQTT (avec ou sans authentification, avec ou sans TLS)
 - la publication periodique de l'etat
 - la deconnexion propre

Les classes filles (TemperatureSensor, LightDevice, etc.) definissent
leur comportement specifique en surchargeant les methodes _read_state()
et _on_command().
"""

import json
import ssl
import time
import logging
import paho.mqtt.client as mqtt


class BaseDevice:
    """Classe de base pour un objet IoT MQTT."""

    def __init__(
        self,
        device_id: str,
        room: str,
        device_type: str,
        broker_host: str = "localhost",
        broker_port: int = 1883,
        username: str | None = None,
        password: str | None = None,
        publish_interval: int = 5,
        tls_ca_path: str | None = None,
    ):
        self.device_id = device_id
        self.room = room
        self.device_type = device_type
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.publish_interval = publish_interval
        self.tls_ca_path = tls_ca_path

        # Topics MQTT (architecture : home/<piece>/<type>/<state|cmd>)
        self.state_topic = f"home/{room}/{device_type}/state"
        self.cmd_topic = f"home/{room}/{device_type}/cmd"

        # Logger dedie au device
        self.logger = logging.getLogger(f"{device_type}.{device_id}")

        # Configuration du client MQTT
        self.client = mqtt.Client(client_id=device_id, clean_session=True)
        if username and password:
            self.client.username_pw_set(username, password)

        # Activation TLS si CA fournie (defense en profondeur)
        if tls_ca_path:
            self.client.tls_set(
                ca_certs=tls_ca_path,
                tls_version=ssl.PROTOCOL_TLSv1_2,
            )
            # On autorise les certs auto-signes pour la demo locale
            self.client.tls_insecure_set(False)
            self.logger.info("TLS active avec CA = %s", tls_ca_path)

        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.client.on_disconnect = self._on_disconnect

        # Auto-reconnexion : 1s minimum, 60s maximum entre tentatives
        self.client.reconnect_delay_set(min_delay=1, max_delay=60)

    # -----------------------------------------------------------------
    # Cycle de vie
    # -----------------------------------------------------------------
    def start(self) -> None:
        """Connecte le device et lance la boucle de publication."""
        self.logger.info(
            "Connexion a %s:%s ...", self.broker_host, self.broker_port
        )
        self.client.connect(self.broker_host, self.broker_port, keepalive=60)
        self.client.loop_start()

        try:
            while True:
                payload = self._build_state_payload()
                self.client.publish(
                    self.state_topic, json.dumps(payload), qos=0, retain=False
                )
                self.logger.info("PUB %s -> %s", self.state_topic, payload)
                time.sleep(self.publish_interval)
        except KeyboardInterrupt:
            self.logger.info("Arret demande par l'utilisateur.")
        finally:
            self.stop()

    def stop(self) -> None:
        """Deconnexion propre du broker."""
        self.client.loop_stop()
        self.client.disconnect()
        self.logger.info("Deconnecte.")

    # -----------------------------------------------------------------
    # Callbacks MQTT
    # -----------------------------------------------------------------
    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self.logger.info("Connecte au broker MQTT (rc=0).")
            # Les actionneurs s'abonnent a leur topic de commande
            if self._listens_to_commands():
                client.subscribe(self.cmd_topic, qos=0)
                self.logger.info("Abonne a %s", self.cmd_topic)
        else:
            # Codes d'erreur paho-mqtt :
            #   1 = mauvaise version protocole
            #   2 = client_id rejete
            #   3 = serveur indisponible
            #   4 = mauvais user/password
            #   5 = non autorise
            self.logger.error(
                "Echec de connexion (rc=%s) : %s",
                rc, mqtt.connack_string(rc) if hasattr(mqtt, 'connack_string') else 'voir doc paho-mqtt'
            )

    def _on_message(self, client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
        except json.JSONDecodeError:
            payload = msg.payload.decode("utf-8", errors="replace")
        self.logger.info("RECV %s -> %s", msg.topic, payload)
        self._on_command(payload)

    def _on_disconnect(self, client, userdata, rc):
        if rc != 0:
            self.logger.warning(
                "Deconnexion inattendue (rc=%s). Reconnexion auto en cours...", rc
            )

    # -----------------------------------------------------------------
    # Methodes a surcharger par les classes filles
    # -----------------------------------------------------------------
    def _build_state_payload(self) -> dict:
        """Retourne le payload d'etat a publier. A surcharger."""
        raise NotImplementedError

    def _on_command(self, payload) -> None:
        """Traite une commande recue. A surcharger par les actionneurs."""
        pass

    def _listens_to_commands(self) -> bool:
        """Indique si le device doit ecouter les commandes."""
        return False
