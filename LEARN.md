# LEARN — Concepts SOC / SIEM & préparation entretien

Document d'apprentissage en français qui accompagne le projet **SOC Detection
Lab**. Il résume les concepts clés, l'architecture Wazuh, les Event IDs utilisés,
Sigma, la corrélation et le réglage des faux positifs, puis propose 15 questions
d'entretien avec réponses modèles et une ligne de CV honnête.

---

## 1. Qu'est-ce qu'un SIEM ?

Un **SIEM** (*Security Information and Event Management*) centralise les journaux
(logs) de tout le parc (serveurs, postes, pare-feu, applications), les **normalise**,
les **corrèle** avec des règles de détection, puis **alerte** les analystes et
conserve les évènements pour l'investigation. Fonctions principales :
- **Collecte & normalisation** : amener des logs hétérogènes à un schéma commun.
- **Détection** : règles (signatures, seuils, corrélation) → alertes.
- **Corrélation** : relier plusieurs évènements en un scénario (ex. force brute →
  succès → création de compte admin).
- **Investigation & réponse** : recherche, tableaux de bord, triage, workflow.

Le **detection engineering** est la discipline qui consiste à **écrire, tester et
maintenir** ces règles (couverture ATT&CK, réduction des faux positifs).

---

## 2. Architecture de Wazuh

Wazuh est une plateforme XDR/SIEM open source composée de :

| Composant | Rôle |
|-----------|------|
| **Agent** | Installé sur chaque hôte. Collecte logs, inventaire, FIM, et les envoie au manager (port 1514). |
| **Manager** (analysisd) | Cœur de la détection : **décodeurs** (extraction de champs) puis **règles** (décision + niveau + ATT&CK). Déclenche les alertes. |
| **Indexer** | Moteur de recherche/stockage (basé sur OpenSearch) : indexe les alertes et évènements. |
| **Dashboard** | Interface web (basée sur OpenSearch Dashboards) : visualisation, recherche, tableaux de bord, modules (MITRE, conformité). |

Flux : `Agent → Manager (décodeur → règle) → Indexer → Dashboard`.

- **Décodeur** : transforme une ligne brute en champs (ex. `srcip`, `user`).
- **Règle** : teste les champs décodés ; possède un `id`, un `level` (0–15), une
  description, un mapping `<mitre>`, et peut **corréler** via `frequency`,
  `timeframe`, `if_matched_sid`, `same_source_ip`, etc.

---

## 3. Sysmon — Event IDs utilisés dans ce lab

**Sysmon** (System Monitor, Sysinternals) enrichit la télémétrie Windows bien
au-delà du journal Security natif. Event IDs clés :

| EID | Signification | Usage dans le lab |
|-----|---------------|-------------------|
| **1** | Création de processus (image, ligne de commande, parent) | PowerShell encodé, schtasks, Defender off, Office→shell |
| **3** | Connexion réseau | Scan de ports (ports distincts par source) |
| 7 | Chargement de DLL | (non utilisé ici) |
| 11 | Création de fichier | (piste web shell côté hôte) |
| 13 | Modification de registre | (piste persistance) |

Journal **Windows Security** natif utilisé :

| EID | Signification |
|-----|---------------|
| **4624** | Connexion réussie |
| **4625** | Échec de connexion |
| **4720** | Création d'un compte utilisateur local |
| **4732** | Membre ajouté à un groupe local de sécurité (ex. Administrators). Attention : `TargetUserName`/`TargetSid` = le **groupe**, `MemberSid` = le compte ajouté |
| **4698** | Création d'une tâche planifiée (nécessite l'audit « Other Object Access Events », désactivé par défaut) |
| 5001 (Defender/Operational) | Protection en temps réel de Defender désactivée |
| **1102** | Journal d'audit de sécurité effacé |

**LogonType** utiles : 2 (interactif), 3 (réseau), 10 (RemoteInteractive/RDP),
7 (déverrouillage). Piège classique : avec **NLA** (défaut), un **échec** RDP est
journalisé en 4625 **LogonType 3** (l'authentification se fait avant la session),
tandis que la connexion réussie apparaît en 4624 LogonType 10.

**Statut 4625** : `Status 0xC000006D` + `SubStatus 0xC000006A` = mauvais mot de
passe ; `SubStatus 0xC0000064` = compte inexistant (signe de pulvérisation /
énumération de comptes).

---

## 4. Sigma — le format de règle générique

**Sigma** est un format **YAML ouvert et générique** pour décrire des détections
indépendamment du SIEM. On écrit la règle une fois, puis un convertisseur
(`sigma-cli` / pySigma + *backends*) la traduit en requête Splunk, Elastic, Wazuh,
Sentinel, etc. Structure :
- `logsource` : produit / service / catégorie ciblés (ex. `process_creation`).
- `detection` : `selection` (conditions) + `condition` (logique).
- `level`, `tags` (`attack.tXXXX`), `falsepositives`, `fields`.

Intérêt : **portabilité** et **partage communautaire** des détections. Ici, chaque
règle Wazuh a son équivalent Sigma dans `rules/sigma/`.

---

## 5. Corrélation

La **corrélation** relie plusieurs évènements plutôt que d'alerter sur un seul.
Types implémentés dans le moteur offline (`detector/engine.py`) :

- **threshold** : N évènements correspondants dans une fenêtre glissante, groupés
  par clé (ex. 8 échecs SSH / 120 s par IP source).
- **distinct** : N **valeurs distinctes** d'un champ dans une fenêtre (ex. 15 ports
  de destination distincts / 60 s → scan).
- **sequence** : étapes **ordonnées** dans une fenêtre (ex. 8 échecs **puis** un
  succès ; ou création de compte **puis** ajout à Administrators).
- **single** : un évènement unique suffit (ex. journal effacé, Defender désactivé).

Dans Wazuh, la corrélation s'exprime avec `frequency` + `timeframe`,
`if_matched_sid`, `same_source_ip`, `same_field`, etc.

---

## 6. Réglage des faux positifs (FP tuning)

Un **faux positif** est une alerte sur une activité légitime. Approche :
1. **Référence (baseline)** : connaître le trafic/comportement normal.
2. **Seuils** : ajuster N et la fenêtre (ex. un scanner de vulnérabilités autorisé
   fait beaucoup de connexions → l'exclure ou relever le seuil).
3. **Listes d'exclusion** : comptes de service, IP d'outils d'administration,
   plages de maintenance.
4. **Contexte / enrichissement** : géolocalisation, réputation IP, heure ouvrée.
5. **Mesure** : suivre taux de FP vs. vrais positifs, itérer. Dans ce lab, chaque
   règle est **testée** pour se déclencher sur l'attaque **et** rester silencieuse
   sur une base bénigne (0 FP sur 215 évènements).

Compromis fondamental : seuil trop bas → bruit (fatigue d'alerte) ; trop haut →
angles morts (faux négatifs).

---

## 7. 15 questions d'entretien (avec réponses modèles)

**Q1. Différence entre IDS, SIEM et EDR ?**
Un **IDS** détecte des intrusions réseau/hôte via signatures/anomalies. Un **SIEM**
agrège et corrèle des logs de multiples sources pour détecter et investiguer. Un
**EDR** se concentre sur l'endpoint (processus, mémoire, réponse). Ils sont
complémentaires ; Wazuh couvre SIEM + une partie XDR/EDR.

**Q2. Qu'apporte Sysmon par rapport au journal Security natif ?**
Une télémétrie beaucoup plus riche : lignes de commande complètes, processus
**parent**, hachages, connexions réseau, chargements de DLL, modifications de
registre — essentiel pour détecter l'exécution (ex. Office qui lance cmd.exe).

**Q3. Comment détecter une force brute et éviter les faux positifs ?**
Compter les échecs par source dans une fenêtre (seuil + timeframe), grouper par IP
et/ou compte. Pour les FP : exclure comptes de service, ajuster le seuil, et
surtout **corréler** avec un succès ultérieur pour prioriser les cas critiques.

**Q4. Pourquoi « succès après plusieurs échecs » est-il plus grave qu'une simple
force brute ?**
La force brute seule peut échouer ; un **succès** juste après la rafale indique une
**compromission effective** du compte — priorité d'investigation plus élevée.

**Q5. Qu'est-ce que MITRE ATT&CK et pourquoi mapper les règles ?**
Une base de connaissances des **tactiques et techniques** adverses. Mapper les
règles permet de mesurer la **couverture**, communiquer en langage commun et
identifier les angles morts.

**Q6. Expliquez un décodeur vs une règle dans Wazuh.**
Le **décodeur** extrait des champs d'une ligne brute ; la **règle** prend une
décision à partir de ces champs (niveau, description, ATT&CK, corrélation). Sans
décodeur correct, la règle n'a pas de champs à tester.

**Q7. Comment fonctionne la corrélation par fenêtre glissante ?**
On ordonne les évènements par temps et on maintient une fenêtre `[t, t+Δ]` ; si le
nombre (ou le nombre de valeurs distinctes) d'évènements dans la fenêtre atteint le
seuil, on alerte. C'est exactement ce que fait `engine.py` (deux pointeurs).

**Q8. Qu'est-ce que Sigma et quel est son intérêt ?**
Un format YAML générique de détection, convertible vers de nombreux SIEM. Il rend
les détections **portables** et **partageables** (règles communautaires).

**Q9. EventID 4720 vs 4732 ?**
4720 = **création** d'un compte local ; 4732 = **ajout** d'un membre à un groupe
local. La séquence 4720 → 4732 (Administrators) signale un nouveau compte
administrateur (persistance/élévation).

**Q10. Pourquoi l'effacement du journal (1102) est-il critique ?**
C'est une action **anti-forensique** (T1685.005 *Clear Windows Event Logs* depuis
ATT&CK v19 ; anciennement T1070.001) : l'attaquant tente d'effacer ses traces.
Effacer un autre journal que Security produit l'EventID **104** (journal System). D'où l'intérêt d'**exporter les logs en temps réel** vers le SIEM.

**Q11. Comment détecter un PowerShell malveillant ?**
Surveiller les lignes de commande : `-EncodedCommand`, `-nop`, `IEX`,
`DownloadString`, `FromBase64String`, exécution par un parent inhabituel. Idéal :
activer le **Script Block Logging** (EventID 4104).

**Q12. Qu'est-ce qu'un faux positif et comment le réduire ?**
Une alerte sur une activité légitime. On réduit via baseline, seuils, listes
d'exclusion, enrichissement contextuel, et mesure continue (voir §6).

**Q13. Détecter un scan de ports — quelle logique ?**
Compter les **ports de destination distincts** contactés par une même source dans
une courte fenêtre (corrélation `distinct`). Exclure les scanners autorisés.

**Q14. Qu'est-ce que la « defense evasion » ? Donnez deux exemples.**
Tactique visant à éviter la détection : ex. **désactiver l'antivirus**,
**effacer les journaux**. Les deux sont couverts ici en niveau critique/élevé.
Point d'actualité à connaître en entretien : **ATT&CK v19 (avril 2026)** a scindé
Defense Evasion (TA0005) en **Stealth** (TA0005) et **Defense Impairment**
(TA0112) ; T1562.001 est devenu **T1685** (*Disable or Modify Tools*) et
T1070.001 est devenu **T1685.005**. Beaucoup d'outils (dont la base MITRE
intégrée à Wazuh 4.x) utilisent encore les anciens identifiants.

**Q15. Comment valider qu'une règle de détection est bonne ?**
Elle doit (1) se déclencher sur l'attaque ciblée (vrai positif), (2) rester
silencieuse sur l'activité normale (pas de FP), (3) être mappée ATT&CK, (4) être
**testable** et reproductible. Ce lab le fait via `pytest` : 11/11 détections,
0 FP sur la base bénigne. **Limite à dire honnêtement :** la base bénigne vient du
même générateur que les attaques ; il faut aussi tester des **variantes** de
l'attaque (ex. `-e`/`-ec` au lieu de `-EncodedCommand`, test ajouté) et rejouer
la règle sur de vrais journaux avant de la déclarer fiable.

---

## 8. Ligne de CV (honnête)

> **Projet — SOC Detection Lab (detection engineering, défensif).** Conception de
> 11 détections mappées MITRE ATT&CK au format **Wazuh (XML)** et **Sigma (YAML,
> validées par `sigma check`)**, et développement d'un **moteur de détection Python
> offline** (corrélation par seuil / valeurs distinctes / séquence) exécuté sur des
> **journaux synthétiques** (Linux, Windows Security, Sysmon, Apache) — **11/11
> détections déclenchées, 0 faux positif** sur la base bénigne synthétique,
> **31 tests pytest**. *Moteur et règles réalisés ;
> le déploiement Wazuh (manager/indexer/dashboard + agent + Sysmon) est documenté
> pour un déploiement personnel sur ma machine.*
