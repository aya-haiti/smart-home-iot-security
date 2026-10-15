# Scenarios de demonstration v2

Ce document detaille **5 scenarios** a montrer pendant la presentation
du projet (4 dans la v1, le 5e ajoute en v2 avec TLS et flood).

Chaque scenario suit la meme structure :
1. **Mise en place** : ce qui doit tourner avant
2. **Demonstration** : les actions a faire ecran a l'appui
3. **Ce que la professeure doit observer**
4. **Lecon de securite**

> Ports :
> - **1883** = broker **VULNERABLE** (acces anonyme)
> - **8883** = broker **SECURISE TLS** (TLS + auth + ACL)

> **Astuce** : pour la soutenance, le script `python devices/demo.py`
> execute automatiquement les 4 premiers scenarios avec sortie colorisee.

---

## Scenario 1 : Tout fonctionne, tout est expose

**Objectif :** montrer que la maison fonctionne... mais que tout le monde voit tout.

### Mise en place

```bash
# Terminal 1 : stack Docker
./scripts/start.sh                  # Linux/macOS
.\scripts\start.ps1                 # Windows

# Terminal 2 : devices Python connectes au broker VULNERABLE
source .venv/bin/activate           # Linux/macOS
python devices/run_all_devices.py --port 1883
```

### Demonstration

1. Ouvrir **http://localhost:1880/ui** -> tout s'affiche (temperature, gaz, porte, lampe, clim).
2. Ouvrir **MQTT Explorer**, cliquer **+** :
   - Host : `localhost`, Port : `1883`, **Aucun** username/password.
3. **Connect** -> connexion immediate.
4. Deplier l'arborescence : tous les topics `home/...` defilent.

### A observer

- Aucune authentification demandee.
- Toutes les mesures defilent en clair.
- Les commandes envoyees par Node-RED sont aussi visibles (`home/salon/light/cmd`).

### Lecon

> Un broker MQTT qui autorise l'acces anonyme expose **toutes** les
> donnees a quiconque peut atteindre le port 1883. Sur un Wi-Fi
> domestique mal segmente ou un broker expose sur Internet, n'importe
> qui peut espionner.

---

## Scenario 2 : Espionnage des donnees (sniffing)

**Objectif :** prouver qu'on peut intercepter toutes les mesures.

### Mise en place

Comme scenario 1, plus :

```bash
# Terminal 3
python devices/attack_demo.py --scenario sniff --port 1883 --duration 30
```

### Demonstration et observations

```
[+] Connecte SANS authentification (broker vulnerable !)
[+] Abonne a # (TOUS les topics)
[INTERCEPTE] home/salon/temperature/state -> {"value": 22.4, ...}
[INTERCEPTE] home/cuisine/gas/state       -> {"value": 142, ...}
[INTERCEPTE] home/entree/door/state       -> {"state": "OPEN"}
```

### Lecon

> Un attaquant peut **deduire les habitudes des habitants** : heures
> d'ouverture des portes, presence/absence (capteur de gaz qui change
> quand on cuisine), etc., **sans avoir attaque** quoi que ce soit.

> **Mapping STRIDE** : Information disclosure
> **MITRE ATT&CK ICS** : T0830 (Adversary-in-the-Middle)

---

## Scenario 3 : Injection de commande non autorisee

**Objectif :** prouver qu'on peut **prendre le controle** des actionneurs.

### Demonstration

#### Variante A — via MQTT Explorer (visuel)

1. Topic : `home/salon/light/cmd`
2. Payload (raw) :
   ```json
   {"action":"ON","intensity":100}
   ```
3. **Publish** -> la lampe passe a ON, intensite 100.
4. Refaire avec :
   ```
   home/chambre/ac/cmd  ->  {"action":"ON","mode":"HEAT","target_temp":30}
   ```

#### Variante B — via le script

```bash
python devices/attack_demo.py --scenario inject --port 1883
```

### A observer

- Le dashboard Node-RED reflete en temps reel l'etat **modifie par l'attaquant**.
- Aucune authentification n'a ete necessaire.

### Lecon

> Sans authentification ni controle d'acces, un attaquant peut commander
> **physiquement** les objets de la maison : lumieres, chauffage, et dans
> des cas reels serrures, alarmes, electromenager.

> **Mapping STRIDE** : Spoofing + Elevation of privilege
> **MITRE ATT&CK ICS** : T0855 (Unauthorized Command Message)

---

## Scenario 4 : Flood / Deni de service (NOUVEAU v2)

**Objectif :** demontrer qu'un broker non protege peut etre rendu
inutilisable par sur-publication.

### Demonstration

```bash
# Lancer la maison sur le broker vulnerable (terminal 2)
python devices/run_all_devices.py --port 1883

# Lancer le flood (terminal 3)
python devices/attack_demo.py --scenario flood --port 1883 --count 500
```

### A observer

- Sur le dashboard Node-RED, la jauge de gaz **saute partout** (l'attaquant
  injecte 500 messages avec `value=999`).
- Le **panneau "Detection d'anomalies"** (nouveau v2) declenche une alerte :
  `ANOMALIE : 500 msg/min sur home/cuisine/gas/state`.
- Le graphique "Messages/min par topic" montre un pic visible.

### Lecon

> Sans rate-limiting cote broker, un seul client malveillant peut :
> - **saturer** le dashboard avec du bruit ;
> - **noyer** une vraie alerte (une vraie fuite de gaz devient invisible
>   dans le flot de fausses mesures) ;
> - **epuiser** les ressources du broker (memoire, CPU, file d'attente).

> **Mapping STRIDE** : Denial of Service
> **MITRE ATT&CK ICS** : T0814 (Denial of Service)

> La v2 ajoute aussi une **detection cote Node-RED** qui leve une
> alerte quand un topic depasse 30 msg/min.

---

## Scenario 5 : Le broker securise bloque tout cela (TLS + auth + ACL)

**Objectif :** montrer que la version securisee resoud les 4 risques precedents.

### Mise en place

```bash
# (une seule fois) generer passwords + certificats
./scripts/generate-passwords.sh         # ou .ps1
./scripts/generate-certs.sh             # ou .ps1

# Stack
./scripts/start.sh

# Devices sur le broker SECURISE TLS (port 8883)
python devices/run_all_devices.py --port 8883 --secure-multi-user \
    --ca ./mosquitto/secure/certs/ca.crt
```

### Demonstration

#### Etape A — connexion anonyme refusee

1. MQTT Explorer : Host=`localhost`, Port=`8883`, **TLS active** dans MQTT Explorer
   (importer `mosquitto/secure/certs/ca.crt` dans les settings TLS).
2. Pas de username/password.
3. **Connect** -> *Connection Refused: not authorised*.

#### Etape B — connexion legitime mais limitee

1. Reconnecter avec `sensor_user` / `sensor_pass`.
2. Souscrire a `#` -> aucun message (l'ACL refuse la lecture).
3. Tenter `home/salon/light/cmd` en publish -> rejete cote broker.

#### Etape C — reproduire les attaques, elles echouent

```bash
python devices/attack_demo.py --scenario tls-blocked --port 8883 \
    --ca ./mosquitto/secure/certs/ca.crt
```

Resultat : 3 sous-tests, tous "SUCCES" (anonyme refuse, fausses creds
refusees, escalade ACL bloquee).

#### Etape D — utilisateur legitime fonctionne

1. MQTT Explorer avec `dashboard_user` / `dashboard_pass`.
2. Publier sur `home/salon/light/cmd` -> accepte.
3. Tenter d'ecrire sur `home/salon/temperature/state` -> rejete.

### A observer

Logs Mosquitto (`docker compose logs -f mosquitto-secure`) :
```
... New client connected from ... as sensor_user
... Denied PUBLISH from sensor_user to home/salon/light/cmd
```

### Lecon

> Quatre mecanismes complementaires protegent le systeme :
> 1. **TLS 1.2** -> impossible de sniffer (meme sur un Wi-Fi public).
> 2. **`allow_anonymous false`** -> impossible de se connecter sans compte.
> 3. **`password_file`** -> chaque client a un identifiant unique tracable.
> 4. **ACL par topic** -> meme avec un compte valide, on ne peut acceder
>    qu'aux topics correspondant a son role (principe du moindre privilege).

> **Mapping** :
> - STRIDE : couvre Spoofing, Tampering, Information disclosure, Elevation
> - MITRE  : controle "M0807 — Network Allowlists" et "M0937 — Filter Network Traffic"

---

## Tableau recapitulatif

| Risque | Broker vulnerable (1883) | Broker securise v2 (8883) |
|---|---|---|
| Connexion anonyme | Acceptee | Refusee |
| Sniff du trafic | Tout en clair | TLS chiffre tout |
| Lecture de tous les capteurs | Possible | Bloquee par ACL |
| Commande non autorisee | Possible | Bloquee par ACL |
| Falsification (spoof) | Possible | Bloquee par ACL en ecriture |
| Flood / DoS | Possible | Limite (`max_connections`) + alerte Node-RED |
| Tracabilite | Aucune | Logs avec username |

---

## Pour aller plus loin

- **Authentification mutuelle TLS (mTLS)** : exiger un certificat client.
- **Externaliser l'auth** : `auth-plugin` Mosquitto + LDAP/Keycloak.
- **Rate limiting fin** : EMQX ou HiveMQ supportent un rate-limit par client.
- **Detection d'anomalies par ML** : entrainer un modele sur le trafic
  normal et alerter sur les deviations.
- **Segmentation reseau** : VLAN dedie IoT, broker derriere un firewall.
