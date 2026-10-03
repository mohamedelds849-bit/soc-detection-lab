# LEARN — Concepts SOC / SIEM & préparation entretien

Document d'apprentissage en français qui accompagne le projet **SOC Detection
Lab**. Il résume les concepts clés, l'architecture Wazuh, les Event IDs utilisés,
Sigma, la corrélation, la validation des règles en CI (detection-as-code) et le
réglage des faux positifs, puis propose 20 questions
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
  succès ; ou création de compte **puis** ajout à Administrators). Le moteur
  regarde **en arrière** depuis l'évènement final (le succès) : il faut au moins
  N échecs dans les 180 s qui le précèdent. Une étape peut lire la clé de
  corrélation dans un autre champ (`alias`) : le SID du compte est `TargetSid`
  dans 4720 mais `MemberSid` dans 4732.
- **single** : un évènement unique suffit (ex. journal effacé, Defender désactivé).

Dans Wazuh, la corrélation s'exprime avec `frequency` + `timeframe`,
`if_matched_sid`, `same_source_ip`, `same_field`, etc. Deux pièges : (1) **ordre des
règles sœurs** : la lecture du code source de Wazuh 4.9.2 laissait penser que les
enfants d'un même parent sont essayés par **niveau décroissant** ; **la CI a
montré que c'est faux en pratique** : les enfants intégrés, chargés avant
`local_rules.xml`, capturent l'évènement avant une règle locale sœur de niveau
plus élevé (voir §5 bis). La parade robuste est de rattacher la règle locale
**sous** les enfants intégrés qui peuvent capturer l'évènement (100110 enfant de
5763, 100121 de 60204, 100122 de 92653, 100123 de 92652, 100192 de 31108) ; (2) `frequency="8"` se déclenche bien au 8ᵉ
évènement (le code retire 2 à la valeur lue et compte l'évènement courant), et la
fenêtre est mesurée sur l'heure de **réception** par le manager.

---

## 5 bis. Detection-as-code : valider les règles en CI

**Idée.** Traiter les règles de détection comme du code : versionnées dans Git,
**testées automatiquement** à chaque modification, et un changement qui casse une
détection fait échouer le build (comme un test unitaire qui casse).

**Dans ce lab** (`.github/workflows/wazuh-validation.yml`), à chaque push qui touche
`rules/**`, `lab/**` ou `datasets/wazuh_logtest/**`, GitHub Actions :
1. démarre un vrai manager `wazuh/wazuh-manager:4.9.2` dans Docker ;
2. charge `rules/wazuh/local_rules.xml` et le valide (`wazuh-analysisd -t`) ;
3. rejoue les 18 fichiers de `datasets/wazuh_logtest/` dans `wazuh-logtest`
   (`lab/run_all.sh`) ;
4. `lab/check_results.py` compare la **règle finale de chaque ligne** avec
   `lab/expected.json` (y compris des « cette règle ne doit PAS se déclencher »
   pour les cas négatifs) et échoue au moindre écart.

Résultat au 2026-10-03 : **18/18**, après 4 runs.

**L'histoire à raconter en entretien (ordre de chargement).** J'avais relu le code
source de Wazuh et conclu que les règles sœurs étaient essayées par niveau
décroissant : mes règles de niveau 13 devaient donc passer avant les règles
intégrées de niveau 3 ou 6. La CI a dit le contraire :
- run 1 : échec avant tout test (bug du contrôle de disponibilité dans
  `lab/start.sh`) ;
- run 2 : tous les cas Windows tombaient sur la règle 1002, car mon patch de test
  de la règle 60000 n'enlevait pas `<category>ossec</category>` (je l'ai comparé
  au `runtests.py` officiel de Wazuh) ; et 100192 ne se déclenchait jamais car la
  règle intégrée **31108** (« simple queries », niveau 0) capturait le POST sans
  query string ;
- run 3 : 15/18. **92653** (succès RDP, niveau 3) capturait le 4624 avant 100122
  (niveau 13), **92652** (succès NTLM) avant 100123, et 2 des 15 connexions Sysmon
  finissaient sur **92106** via 92105, donc le compteur du scan de ports n'arrivait
  qu'à 13 ;
- correctif : rattacher les règles locales sous ces enfants intégrés
  (`if_sid 60106, 92653`, `if_sid 60106, 92652`, `if_sid 61605, 92101…92110`,
  `if_sid 31100,31108`) ; run 4 : 18/18.

Morale : **l'analyse statique ne remplace pas l'exécution**. Sans test automatique,
4 règles auraient été « écrites et relues » mais muettes une fois déployées.

**Ce que la CI ne prouve pas.** Les lignes sont synthétiques et rejouées dans
`wazuh-logtest` ; il n'y a pas encore d'agent Windows sur une vraie machine (cas 19
de `docs/WAZUH-VALIDATION.md` : agent + Sysmon + vraie connexion RDP). Les taux de
faux positifs sur de vrais journaux ne sont pas mesurés.

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
   sur une base bénigne (0 FP sur 246 évènements, dont des quasi-attaques : 7
   échecs puis succès, ajout d'un compte existant aux Administrateurs,
   `/search?q=evaluation`). Les anciennes règles 04 et 10 donnaient 3 faux
   positifs sur ces quasi-attaques.

Compromis fondamental : seuil trop bas → bruit (fatigue d'alerte) ; trop haut →
angles morts (faux négatifs).

---

## 7. 20 questions d'entretien (avec réponses modèles)

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
**testable** et reproductible. Ce lab le fait via `pytest` : 12/12 détections, tests
de bornes (7 contre 8 échecs, 14 contre 15 ports, fenêtre de 180 s contre 181 s),
0 FP sur la base bénigne. **Limite à dire honnêtement :** la base bénigne vient du
même générateur que les attaques ; il faut aussi tester des **variantes** de
l'attaque (ex. `-e`/`-ec` au lieu de `-EncodedCommand`, test ajouté) et rejouer
la règle sur de vrais journaux avant de la déclarer fiable.

**Q16. Comment détectez-vous un RDP réussi après une force brute ? Pourquoi
LogonType 3 avec NTLM, et pas seulement 10 ?**
On corrèle par **IP source** : au moins 8 évènements **4625** (LogonType 3 ou 10)
puis, dans les 180 s, un **4624** réussi depuis la même IP (règle 12, T1110 pour
la force brute + **T1078 Valid Accounts** car l'attaquant utilise désormais un vrai
compte). Le succès est un 4624 **LogonType 10** (RemoteInteractive, la session RDP)
**ou** un **LogonType 3 avec `AuthenticationPackageName = NTLM`** : avec **NLA**
(défaut de Windows), la vérification du mot de passe RDP est une ouverture de
session réseau type 3, et les échecs eux-mêmes sont des 4625 type 3 ; NTLM type 3
depuis l'extérieur correspond aussi à une devinette de mot de passe SMB/WinRM ou à
du pass-the-hash. On exclut Kerberos type 3, qui est le bruit normal d'un domaine.
On ne groupe **pas** par compte : en password spraying, le compte qui réussit
n'est pas forcément celui qui a échoué. Côté Wazuh, la règle est un enfant de
60106 (4624) **et** de la règle intégrée 92653 (RDP) / 92652 (NTLM), qui
capturait sinon l'évènement en premier, avec `if_matched_sid` sur l'alerte de
force brute et `same_field win.eventdata.ipAddress`, au niveau 13. Réponse
honnête : « la logique est testée dans mon moteur et en Sigma, et côté Wazuh elle
est validée en CI sur un vrai manager 4.9.2 par rejeu `wazuh-logtest` (positif,
négatif 7 échecs, négatif Kerberos) ; je ne l'ai pas encore vue sur un vrai agent
Windows avec une vraie connexion RDP ». Suite
de l'investigation : traiter le compte comme compromis et chercher ce qu'il a fait
ensuite (4720/4732, 4698, 1102) — dans ce lab, c'est `administrator` qui crée
`svc_helper` 7 minutes plus tard.

**Q17. Pourquoi mettre des règles de détection en CI ?**
Parce qu'une règle jamais exécutée n'est qu'une hypothèse. La CI rejoue des cas
positifs **et** négatifs sur un vrai moteur Wazuh à chaque modification, et bloque
toute régression (une mise à jour du ruleset intégré ou une règle voisine peut
masquer la vôtre sans aucune erreur visible). C'est reproductible, gratuit
(GitHub Actions + image Docker officielle), et le résultat est une preuve
vérifiable, pas une affirmation.

**Q18. Qu'est-ce qui a cassé, et comment l'avez-vous trouvé ?**
Run 1 : bug du contrôle de disponibilité du manager dans mon script de démarrage.
Run 2 : tous les cas Windows tombaient sur la règle 1002, ce qui m'a fait comparer
mon patch de la règle 60000 avec le `runtests.py` officiel : il fallait aussi
retirer `<category>ossec</category>`. Run 3 : 15/18 ; le comparateur
`check_results.py` affichait, ligne par ligne, la règle obtenue (92653, 92652,
92106) à la place de la règle attendue, ce qui désignait directement la règle
intégrée qui « volait » l'évènement. Run 4 : 18/18.

**Q19. Pourquoi la règle intégrée 31108 a-t-elle capturé l'évènement de 100192 ?**
100192 (POST réussi vers un script dans un dossier d'upload) était enfant de 31100
(accès web). Mais 31108 (« simple queries », niveau 0), autre enfant de 31100,
chargée avant `local_rules.xml`, correspondait aussi au POST sans query string et
gagnait : l'évènement s'arrêtait sur une règle de niveau 0, donc **aucune alerte**.
Le niveau plus élevé de 100192 n'a pas suffi. Correctif : `if_sid 31100,31108`,
pour que 100192 soit aussi évaluée comme enfant de 31108.

**Q20. Qu'est-ce qui n'est pas encore validé ?**
Le bout en bout : un vrai agent Wazuh sur Windows avec Sysmon, une vraie
connexion RDP, et l'alerte 100122/100123 dans le dashboard (cas 19). La CI valide
la logique des règles sur des lignes synthétiques rejouées dans `wazuh-logtest`,
avec un patch temporaire de la règle 60000 propre au test ; elle ne valide ni la
collecte par l'agent, ni le timing réel de corrélation, ni le taux de faux
positifs sur de vrais journaux. Et la règle 100131 garde sa limite connue (pas de
jointure par SID dans Wazuh).

---

## 8. Ligne de CV (honnête)

> **Projet — SOC Detection Lab (detection engineering, défensif).** Conception de
> 12 détections mappées MITRE ATT&CK au format **Wazuh (XML)** et **Sigma (YAML,
> validées par `sigma check`)**, validées automatiquement en CI (GitHub Actions)
> sur un vrai manager Wazuh 4.9.2 : 18/18 cas wazuh-logtest, dont négatifs ;
> développement d'un **moteur de détection Python offline** (corrélation par seuil
> / valeurs distinctes / séquence) exécuté sur des **journaux synthétiques**
> (Linux, Windows Security, Sysmon, Apache) : **12/12 détections déclenchées**,
> aucune alerte sur la base bénigne synthétique avec quasi-attaques, **145 tests
> pytest**. *Agent Windows réel (Sysmon + RDP de bout en bout) : à venir.*

À ne **pas** dire : « Wazuh déployé en production » ou « supervision en direct ».
Il s'agit d'un manager en conteneur, en CI, qui rejoue des lignes synthétiques.
