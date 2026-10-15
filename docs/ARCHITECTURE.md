# Architecture du projet (v2)

## Vue d'ensemble

```
+-----------------------------------------------------------+
|                  Hote (Linux/macOS/Windows)               |
|                  + Docker Desktop / Engine                |
|                                                           |
|  +---------------------+      +----------------------+    |
|  | Mosquitto vulnerable|      | Mosquitto securise   |    |
|  |   port 1883 (TCP)   |      |   port 8883 (TLS)    |    |
|  |   anonyme: oui      |      |   TLS 1.2 + auth     |    |
|  |   ACL: non          |      |   ACL: oui           |    |
|  |                     |      |   max_connections=50 |    |
|  +----------+----------+      +----------+-----------+    |
|             ^                            ^                |
|             |                            |                |
|  +----------+----------------------------+-----------+    |
|  |              Node-RED (port 1880)                 |    |
|  |  Dashboard + controleurs (lampe, clim)            |    |
|  |  + detection d'anomalies (anti-flood)             |    |
|  +---------------------------------------------------+    |
+-----------------------------------------------------------+
              ^                            ^
              |                            |
   +---------------------+      +---------------------+
   | Devices Python      |      | MQTT Explorer       |
   | - temperature       |      | (visualisation +    |
   | - gaz               |      |  scenarios attaque) |
   | - porte             |      +---------------------+
   | - lampe             |
   | - climatisation     |
   +---------------------+
```

## Topics MQTT

L'arborescence suit la convention `home/<piece>/<type>/<state|cmd>` :

| Topic | Sens | Producteur | Consommateurs |
|---|---|---|---|
| `home/salon/temperature/state` | etat | TemperatureSensor | Node-RED, admin |
| `home/cuisine/gas/state` | etat + alerte | GasSensor | Node-RED, admin |
| `home/entree/door/state` | etat | DoorSensor | Node-RED, admin |
| `home/salon/light/state` | etat | LightDevice | Node-RED, admin |
| `home/salon/light/cmd` | commande | Node-RED / admin | LightDevice |
| `home/chambre/ac/state` | etat | ACDevice | Node-RED, admin |
| `home/chambre/ac/cmd` | commande | Node-RED / admin | ACDevice |

## Roles et ACL (broker securise)

| Compte | Role | Droits |
|---|---|---|
| `sensor_user` | Capteurs (temperature, gaz, porte) | Ecriture seule sur `home/+/{temperature,gas,door}/state` |
| `actuator_user` | Actionneurs (lampe, climatisation) | Lecture des `cmd`, ecriture des `state` correspondants |
| `dashboard_user` | Interface (Node-RED) | Lecture de tous les `state`, ecriture des `cmd` uniquement |
| `admin_user` | Supervision globale | Lecture/ecriture sur `home/#` |

Cette segmentation applique le **principe du moindre privilege** :
meme si un compte est compromis, l'attaquant n'a acces qu'aux topics
necessaires a son role.

## Configuration TLS (NOUVEAU v2)

### Certificats

Generation : `scripts/generate-certs.sh` (ou `.ps1`).

- **CA (Certificate Authority)** auto-signee, validite 10 ans.
  Permet de signer des certificats serveur sans dependre d'une PKI externe.
- **Certificat serveur** signe par la CA, valide 1 an.
  Subject Alternative Names : `localhost`, `mosquitto-secure`, `127.0.0.1`.

### Mosquitto config

```conf
listener 8883 0.0.0.0
cafile   /mosquitto/certs/ca.crt
certfile /mosquitto/certs/server.crt
keyfile  /mosquitto/certs/server.key
tls_version tlsv1.2
require_certificate false
```

`require_certificate false` signifie que le **client** n'a pas besoin
de presenter un certificat — l'authentification client passe par
username/password. Le **serveur** s'authentifie aupres du client (qui
verifie via la CA fournie).

### Cote client Python

```python
import ssl
client.tls_set(ca_certs="ca.crt", tls_version=ssl.PROTOCOL_TLSv1_2)
client.username_pw_set("sensor_user", "sensor_pass")
client.connect("localhost", 8883)
```

### Cote MQTT Explorer

1. Settings -> Advanced -> Certificates
2. Add CA file -> selectionner `mosquitto/secure/certs/ca.crt`
3. Nouvelle connexion : Host=localhost, Port=8883, **Validate certificate=ON**

## Hardening (NOUVEAU v2)

| Parametre Mosquitto | Valeur | Protection contre |
|---|---|---|
| `max_connections` | 50 | Saturation par creation massive de connexions |
| `max_inflight_messages` | 20 | Saturation memoire par messages QoS>0 non confirmes |
| `max_queued_messages` | 100 | Saturation memoire par retain ou QoS>0 |
| `message_size_limit` | 8192 octets | Payload geant (DoS) |
| `tls_version tlsv1.2` | minimum | Protocoles TLS obsoletes (1.0, 1.1) |

## Format des messages

### Capteur de temperature

Topic : `home/salon/temperature/state`
```json
{
  "device_id": "temp-01",
  "room": "salon",
  "type": "temperature",
  "value": 22.4,
  "unit": "C"
}
```

### Capteur de gaz (avec champ `status`)

Topic : `home/cuisine/gas/state`
```json
{
  "device_id": "gas-01",
  "room": "cuisine",
  "type": "gas",
  "value": 142,
  "unit": "ppm",
  "status": "OK"
}
```
`status` peut valoir `"OK"` ou `"ALERT"` (au-dessus de 400 ppm).

### Capteur de porte

Topic : `home/entree/door/state`
```json
{ "device_id": "door-01", "room": "entree", "type": "door", "state": "OPEN" }
```

### Lampe

Topic etat `home/salon/light/state` :
```json
{ "device_id":"light-01", "room":"salon", "type":"light",
  "state":"ON", "intensity":75 }
```

Topic commande `home/salon/light/cmd` (entree) :
```json
{ "action": "ON" }
{ "action": "OFF" }
{ "intensity": 60 }
```

### Climatisation

Topic etat `home/chambre/ac/state` :
```json
{ "device_id":"ac-01", "room":"chambre", "type":"ac",
  "state":"ON", "mode":"COOL", "target_temp":22 }
```

Topic commande `home/chambre/ac/cmd` :
```json
{ "action":"ON", "mode":"COOL", "target_temp":21 }
```

## Choix techniques

### Pourquoi deux brokers en parallele ?

Pour faciliter la demonstration **en direct** : on bascule entre
vulnerable et securise en changeant simplement le port (1883 -> 8883),
sans redemarrer ni reconfigurer.

### Pourquoi Docker ?

- Pas d'installation de Mosquitto ni d'OpenSSL en local.
- Configuration reproductible.
- Reset simple : `docker compose down -v && ./scripts/start.sh`.

### Pourquoi paho-mqtt en Python ?

- Bibliotheque MQTT de reference, simple a comprendre.
- Les capteurs reels (Raspberry Pi, ESP32) utilisent souvent la meme API.
- Support TLS natif via `tls_set()`.

### Pourquoi Node-RED ?

- Outil **impose par le sujet**.
- Dashboard sans coder en HTML/CSS/JS.
- Excellent pour montrer visuellement l'effet des attaques.
- v2 : un noeud `function` realise la detection d'anomalies en
  comptant les messages par topic dans une fenetre glissante de 60s.

### TLS : choix d'implementation

**Pourquoi TLS sans mTLS ?** L'authentification mutuelle (le client
presente aussi un certificat) est plus robuste mais complique fortement
la gestion des credentials et la demonstration. Pour un projet
pedagogique, TLS serveur + auth username/password offre un bon
equilibre lisibilite/realisme.

**Pourquoi auto-signe ?** Une vraie autorite (Let's Encrypt) ne signe
pas pour `localhost`. La CA auto-signee est le standard pour les
deploiements internes IoT.
