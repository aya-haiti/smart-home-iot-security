# Smart Home IoT Security v2 — Demonstration MQTT

> **Démo en ligne (simulation sûre dans le navigateur) :** le dossier [`web-demo/`](web-demo/) rejoue
> les scénarios (espionnage, injection, falsification, flood, broker sécurisé) sans exposer aucun broker.
> La stack Docker ci-dessous contient un broker **volontairement vulnérable** : à exécuter uniquement en local
> ou sur un réseau isolé, jamais exposé sur Internet.

> Projet pedagogique de cybersecurite IoT : simulation d'une maison
> connectee, mise en evidence des risques d'un broker MQTT non protege,
> et application de contre-mesures (TLS + authentification + ACL +
> detection d'anomalies).

**Technologies** : Mosquitto · Node-RED · MQTT Explorer · Python (paho-mqtt) · Docker Compose · TLS

---

## Nouveautes v2

| Amelioration | Detail |
|---|---|
| **TLS 1.2** sur le broker securise | Trafic chiffre, mots de passe et donnees plus interceptables |
| Generation auto des certificats | Script `generate-certs.sh/.ps1` (CA + cert serveur, validite 1 an) |
| **Mots de passe forts** optionnels | `generate-passwords.sh --strong` -> 24 chars aleatoires |
| **Hardening** broker securise | `max_connections`, `message_size_limit`, `tls_version tlsv1.2` |
| 5e scenario : `flood` (DoS) | + `tls-blocked` qui valide automatiquement les protections |
| **Detection d'anomalies** Node-RED | Alerte si > 30 msg/min sur un topic, graphique du taux |
| Script `demo.py` automatique | Sequence pedagogique en 1 commande pour la soutenance |
| Scripts **bash** Linux/macOS | En plus des scripts PowerShell Windows |
| Documentation **STRIDE/MITRE** | Mapping aux modeles de menace academiques |

---

## Sommaire

1. [Objectifs pedagogiques](#objectifs-pedagogiques)
2. [Architecture](#architecture)
3. [Structure du projet](#structure-du-projet)
4. [Prerequis](#prerequis)
5. [Installation rapide](#installation-rapide)
6. [Lancer la maison connectee](#lancer-la-maison-connectee)
7. [Demonstrations de securite](#demonstrations-de-securite)
8. [Demo automatique pour la soutenance](#demo-automatique)
9. [Documentation complementaire](#documentation-complementaire)
10. [Depannage](#depannage)
11. [Avertissement et ethique](#avertissement)

---

## Objectifs pedagogiques

Ce projet repond au sujet :

> *Securite des systemes IoT (Smart Home) : simuler une maison
> connectee avec capteurs/objets, montrer les risques lies a l'absence
> de securite ou a un acces non protege, puis proposer des solutions.*

A la fin de la demonstration, on aura prouve concretement :

- qu'un broker MQTT mal configure laisse fuiter **toutes** les donnees ;
- qu'un attaquant peut **prendre le controle** des actionneurs ;
- qu'il peut **falsifier** les mesures (faux niveau de gaz) ;
- qu'il peut **saturer** le broker par flood (DoS) ;
- qu'une configuration durcie (**TLS** + `allow_anonymous false` +
  `password_file` + `acl_file` + hardening) **bloque les quatre risques**
  sans changer une ligne de code des capteurs.

## Architecture

```
+----------------------------------------------------------+
|                                                          |
|   +-----------------+        +-----------------+         |
|   | MQTT VULNERABLE |        | MQTT SECURISE   |         |
|   |   port 1883     |        | port 8883 (TLS) |         |
|   |   anonyme: oui  |        | TLS+auth+ACL    |         |
|   +-----------------+        +-----------------+         |
|             ^                          ^                 |
|             +-----------+--------------+                 |
|                         |                                |
|                  +------+-------+                        |
|                  |   Node-RED   |  http://localhost:1880 |
|                  | + detect.    |                        |
|                  |   anomalies  |                        |
|                  +--------------+                        |
+----------------------------------------------------------+

   ^                                          ^
   |   capteurs/actionneurs Python            |   MQTT Explorer
   |   (temperature, gaz, porte, lampe, AC)   |   (visualisation, attaques)
```

Detail dans **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** et
**[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)** (STRIDE + MITRE).

## Structure du projet

```
smart-home-iot-security-v2/
|
|-- docker-compose.yml              # 2 brokers + Node-RED
|-- README.md                       # ce fichier
|-- .gitignore
|
|-- mosquitto/
|   |-- vulnerable/
|   |   `-- config/mosquitto.conf   # allow_anonymous true (DEMO)
|   `-- secure/
|       |-- config/
|       |   |-- mosquitto.conf      # TLS + auth + ACL + hardening
|       |   |-- aclfile             # autorisations par role
|       |   `-- passwords           # genere par script
|       `-- certs/                  # genere par script
|           |-- ca.crt              # CA auto-signee
|           |-- server.crt          # certificat serveur
|           `-- server.key
|
|-- devices/                        # capteurs/actionneurs Python
|   |-- base_device.py              # classe MQTT commune (TLS supporte)
|   |-- temperature_sensor.py
|   |-- gas_sensor.py
|   |-- door_sensor.py
|   |-- light_device.py
|   |-- ac_device.py
|   |-- run_all_devices.py
|   |-- attack_demo.py              # 5 scenarios sniff/inject/spoof/flood/tls-blocked
|   |-- demo.py                     # demo automatique pour soutenance (NOUVEAU)
|   `-- requirements.txt
|
|-- node-red/
|   `-- flows/smart-home-flow.json  # flow + dashboard + detection d'anomalies
|
|-- scripts/
|   |-- generate-passwords.sh/.ps1  # mots de passe (option --strong)
|   |-- generate-certs.sh/.ps1      # certificats TLS (NOUVEAU v2)
|   |-- start.sh/.ps1
|   |-- stop.sh/.ps1
|   `-- install-python-deps.sh/.ps1
|
`-- docs/
    |-- ARCHITECTURE.md             # topics, ACL, formats JSON
    |-- SCENARIOS.md                # 5 scenarios de demo detailles
    `-- THREAT_MODEL.md             # mapping STRIDE + MITRE ATT&CK ICS
```

## Prerequis

| Logiciel | Version min. | Verification |
|---|---|---|
| Docker Desktop | 4.x | `docker --version` |
| Docker Compose | inclus | `docker compose version` |
| Python | 3.10+ | `python --version` |
| MQTT Explorer | 0.4+ | telecharger sur https://mqtt-explorer.com |

> Aucune installation de Mosquitto ni d'OpenSSL en local : tout passe
> par l'image Docker `eclipse-mosquitto:2.0`.

## Installation rapide

### Linux / macOS

```bash
chmod +x scripts/*.sh
./scripts/generate-passwords.sh           # ou --strong pour des mots de passe aleatoires
./scripts/generate-certs.sh
./scripts/install-python-deps.sh
./scripts/start.sh
```

### Windows (PowerShell)

```powershell
# Si l'execution de scripts est bloquee :
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

.\scripts\generate-passwords.ps1          # ou -Strong
.\scripts\generate-certs.ps1
.\scripts\install-python-deps.ps1
.\scripts\start.ps1
```

A l'issue, on doit voir :

```
Broker MQTT VULNERABLE   : tcp://localhost:1883
Broker MQTT SECURISE TLS : tls://localhost:8883
Node-RED Editor          : http://localhost:1880
Node-RED Dashboard       : http://localhost:1880/ui
```

## Lancer la maison connectee

### Mode VULNERABLE (port 1883, sans authentification)

```bash
source .venv/bin/activate                  # Linux/macOS
# .\.venv\Scripts\Activate.ps1             # Windows

cd devices
python run_all_devices.py --port 1883
```

### Mode SECURISE TLS (port 8883)

```bash
cd devices
python run_all_devices.py --port 8883 --secure-multi-user \
    --ca ../mosquitto/secure/certs/ca.crt
```

> `--secure-multi-user` utilise `sensor_user` pour les capteurs et
> `actuator_user` pour les actionneurs (conforme aux ACL).
> `--ca` active TLS avec verification du certificat serveur.

## Demonstrations de securite

5 scenarios sont detailles dans **[docs/SCENARIOS.md](docs/SCENARIOS.md)** :

| # | Scenario | Broker | Resultat attendu |
|---|---|---|---|
| 1 | Tout fonctionne, tout est expose | 1883 | MQTT Explorer voit tout, sans mot de passe |
| 2 | Sniff (`attack_demo.py --scenario sniff`) | 1883 | Toutes les mesures interceptees |
| 3 | Injection (`attack_demo.py --scenario inject`) | 1883 | Lampe et clim controlees a distance |
| 4 | Flood DoS (`attack_demo.py --scenario flood`) | 1883 | Dashboard sature + alerte Node-RED |
| 5 | Le broker securise bloque tout (`--scenario tls-blocked`) | 8883 | Auth + ACL + TLS bloquent tout |

Lancer une demo :

```bash
cd devices

# Espionnage 30 secondes
python attack_demo.py --scenario sniff --port 1883

# Injection
python attack_demo.py --scenario inject --port 1883

# Falsification
python attack_demo.py --scenario spoof --port 1883

# DoS / flood
python attack_demo.py --scenario flood --port 1883 --count 500

# Validation des protections (broker securise)
python attack_demo.py --scenario tls-blocked --port 8883 \
    --ca ../mosquitto/secure/certs/ca.crt
```

## Demo automatique

Pour la soutenance, **un seul script** execute toute la sequence avec
sortie colorisee :

```bash
cd devices
python demo.py                 # version complete (~3 min)
python demo.py --quick         # version courte (~1 min)
python demo.py --secure-only   # uniquement les tests sur le broker securise
```

Pre-requis : devices Python lances dans un autre terminal sur le port 1883.

## Documentation complementaire

- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — topics, formats JSON, roles ACL.
- **[docs/SCENARIOS.md](docs/SCENARIOS.md)** — 5 scenarios pas-a-pas (a lire avant la presentation).
- **[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)** — mapping STRIDE et MITRE ATT&CK ICS.

## Depannage

### MQTT Explorer ne se connecte pas en TLS sur 8883

Importer le certificat `mosquitto/secure/certs/ca.crt` dans MQTT
Explorer (Advanced -> Certificates -> Add CA file).

### `docker compose up` echoue avec "port already in use"

Verifier qu'aucun autre service n'utilise les ports :
```bash
ss -tlnp | grep -E '1883|8883|1880'   # Linux
netstat -ano | findstr "1883 8883 1880"  # Windows
```

### Node-RED ne se connecte pas au broker

Depuis le conteneur Node-RED, `localhost` ne pointe pas vers l'hote.
Utiliser :
- `mosquitto-vulnerable` (nom du service Docker) ou `host.docker.internal`
- `mosquitto-secure` pour le broker TLS

### Reset complet

```bash
docker compose down -v
rm -rf mosquitto/vulnerable/data/* mosquitto/secure/data/* node-red/data/flows*
./scripts/generate-passwords.sh
./scripts/generate-certs.sh
./scripts/start.sh
```

## Avertissement

Ce projet est strictement **pedagogique** et **local**. Les scripts
dits "d'attaque" :
- ne contiennent **aucune** technique d'exploitation reelle ;
- utilisent uniquement l'API MQTT standard (les memes appels que les
  devices legitimes) ;
- ne fonctionnent qu'a partir du moment ou **vous-meme** avez demarre
  le broker vulnerable sur votre machine.

> Ne jamais executer ces scripts contre un broker que vous ne possedez pas.

---

**Module** : Securite des systemes IoT
**Annee** : 2025-2026
**Sujet 12** : Securite des systemes IoT (Smart Home)
