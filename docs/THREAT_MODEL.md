# Modele de menaces (Threat Model)

Ce document mappe les attaques demontrees par le projet aux modeles
de menaces academiques standard : **STRIDE** (Microsoft) et
**MITRE ATT&CK for ICS / IoT**. Cela permet d'inscrire la demonstration
dans un cadre theorique reconnu en cybersecurite.

---

## 1. Analyse STRIDE

STRIDE classe les menaces en 6 categories (Spoofing, Tampering,
Repudiation, Information disclosure, Denial of service, Elevation
of privilege).

### Tableau de couverture

| Categorie STRIDE | Risque sur le broker vulnerable | Contre-mesure v2 implementee |
|---|---|---|
| **S**poofing identite | N'importe qui peut se connecter sans s'identifier ; l'attaquant publie sous l'identite de `gas-01` | `allow_anonymous false` + `password_file` -> chaque client a un compte unique tracable |
| **T**ampering (alteration) | L'attaquant publie de fausses mesures sur `home/cuisine/gas/state` (scenario `spoof`) | ACL en ECRITURE limitee aux comptes capteurs sur leurs propres topics |
| **R**epudiation | Aucun log ne permet de savoir qui a allume la lampe | `connection_messages true` + `log_type all` -> chaque PUBLISH est trace avec son username |
| **I**nformation disclosure | Le scenario `sniff` montre que tout le trafic fuite ; sans TLS, meme un attaquant sur le Wi-Fi local intercepte | TLS 1.2 chiffre tout le trafic + ACL en LECTURE par role |
| **D**enial of service | Le scenario `flood` sature le broker ; le dashboard est noye | `max_connections 50`, `max_inflight_messages 20`, `message_size_limit 8192` ; alerte Node-RED si > 30 msg/min/topic |
| **E**levation of privilege | Le scenario `inject` montre un attaquant non authentifie qui controle la lampe | ACL stricte par role : meme un compte capteur valide ne peut PAS commander un actionneur |

### Synthese

Les 6 piliers STRIDE sont adresses par la combinaison **TLS + auth + ACL +
hardening + monitoring** mise en place par la version securisee. Aucune
seule de ces mesures ne suffit ; c'est leur defense en profondeur qui
protege le systeme.

---

## 2. Mapping MITRE ATT&CK

MITRE ATT&CK decrit les techniques utilisees par les attaquants dans
des matrices verifiees (Enterprise, ICS, Mobile). Voici comment les
trois scenarios du projet se rattachent a la matrice ATT&CK ICS :

| Scenario du projet | Tactique MITRE ATT&CK ICS | Technique |
|---|---|---|
| `attack_demo --scenario sniff` | **Collection** | T0830 — Adversary-in-the-Middle / sniffing du trafic non chiffre |
| `attack_demo --scenario inject` | **Inhibit Response Function** ou **Impair Process Control** | T0855 — Unauthorized Command Message |
| `attack_demo --scenario spoof` | **Impair Process Control** | T0856 — Spoof Reporting Message |
| `attack_demo --scenario flood` | **Inhibit Response Function** | T0814 — Denial of Service |
| `attack_demo --scenario tls-blocked` | (defense) | M0937 — Filter Network Traffic, M0807 — Network Allowlists |

### Pourquoi c'est important

Les techniques T0855 (Unauthorized Command Message) et T0856 (Spoof
Reporting Message) sont parmi les plus utilisees dans les attaques
documentees contre les systemes industriels et IoT, notamment dans
les rapports d'incidents publics (Stuxnet, attaques sur smart grids,
etc.). Demontrer ces techniques contre un broker MQTT vulnerable —
puis montrer que les contre-mesures classiques (auth, ACL, TLS) les
bloquent — est exactement le type d'exercice attendu en formation
cybersecurite.

---

## 3. Lien avec les normes IoT

Les contre-mesures v2 sont egalement alignees avec :

- **OWASP IoT Top 10** : couvre directement
  - I1 — Weak/guessable passwords (option `--strong` pour les mots de passe)
  - I2 — Insecure Network Services (TLS sur 8883)
  - I3 — Insecure Ecosystem Interfaces (ACL par role)
  - I7 — Insecure Data Transfer/Storage (TLS)
- **ETSI EN 303 645** (cybersecurite IoT consommateur) :
  - clause 5.1 (no default passwords) — `--strong` genere des mots de passe uniques
  - clause 5.5 (communication securisee) — TLS
  - clause 5.6 (minimiser la surface d'attaque) — ACL minimal
- **NIST SP 800-213** (IoT for federal systems) : authentification (3.1.1),
  chiffrement (3.4.2), logging (3.8.1).

---

## 4. Limites assumees du projet

Le projet est pedagogique et **n'implemente pas** :
- L'authentification mutuelle TLS (mTLS) — le client ne presente pas de certificat.
- Le rate limiting individuel par client (Mosquitto OSS ne le supporte pas nativement).
- La rotation automatique des secrets.
- Une vraie gestion d'identites (LDAP, OAuth2 Device Flow, SCRAM-SHA-512...).

Ces ameliorations seraient pertinentes en production mais sortent du
perimetre d'une demonstration academique.
