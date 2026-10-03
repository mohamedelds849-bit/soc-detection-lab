# Wazuh lab — suivi pas à pas

## Mise à jour 2026-10-03 : chemin CI / Codespaces (sans installation sur le PC)

Le manager Wazuh a été validé **sans WSL** grâce à GitHub Actions
(`.github/workflows/wazuh-validation.yml`, scripts dans `lab/`, voir aussi
`lab/README-CODESPACES.md` pour le faire à la main dans un Codespace).

| # | Étape (chemin CI) | Preuve | Statut |
|---|-------------------|--------|--------|
| C1 | Manager `wazuh/wazuh-manager:4.9.2` déployé dans Docker par la CI (`lab/start.sh`) | logs du job GitHub Actions | ✅ |
| C2 | `local_rules.xml` chargé et validé (`wazuh-analysisd -t`) | logs du job | ✅ |
| C3 | 18 cas `wazuh-logtest` rejoués (`lab/run_all.sh`) | `lab/results/*.txt` (artefact du job) | ✅ |
| C4 | Contrôle automatique vs `lab/expected.json` (`lab/check_results.py`) | build vert, **18/18** (run 4) | ✅ |
| C5 | Règles KO corrigées (100122, 100123, 100170, 100192) + docs mises à jour | commits 6d72235, 621d18f + docs | ✅ |
| C6 | **Agent Wazuh sur une vraie machine Windows + Sysmon** | capture du dashboard | ⏳ |
| C7 | **Cas 19** : vraie connexion RDP après échecs → alerte 100122/100123 | capture du dashboard | ⏳ |

Ce qui reste : uniquement le bout en bout réel (C6, C7) et les tests bénins réels
(étape 9 ci-dessous). Les étapes 0-4 et 8 du chemin WSL ne sont plus nécessaires
pour valider les règles ; elles restent utiles pour un lab complet avec dashboard.

## Chemin WSL (lab complet avec indexer + dashboard + agent)

Chaque étape : **Mohamed fait** → envoie la capture / le texte → **vérification** → étape suivante.
Détails techniques de chaque étape : `docs/SETUP.md`.

| # | Étape | Qui | Preuve attendue | Statut |
|---|-------|-----|-----------------|--------|
| 0 | Libérer de l'espace disque (objectif ≥ 25 Go libres sur C:) | Mohamed | « étape 0 faite » (vérif. automatique) | ⏳ |
| 1 | (Option sans installation : voir `lab/README-CODESPACES.md`) `wsl --install -d Ubuntu-22.04` (PowerShell admin) + redémarrage + utilisateur Ubuntu | Mohamed | capture de la fenêtre Ubuntu | ⏳ |
| 2 | systemd actif (`ps -p 1 -o comm=` → `systemd`) | Mohamed | texte affiché | ⏳ |
| 3 | `wazuh-install.sh -a -i` (Wazuh 4.9 all-in-one) + noter le mot de passe admin | Mohamed | dernières lignes du script (sans le mot de passe) | ⏳ |
| 3b | Désactiver la détection de vulnérabilités (gain disque/RAM) | Mohamed | — | ⏳ |
| 4 | `sudo bash tools/deploy_rules_wsl.sh` (sauvegarde + validation + redémarrage) | Mohamed | « OK: wazuh-manager active » | ⏳ |
| 5 | Politique d'audit 4698 (`auditpol`, SETUP §3 bis) | Mohamed | sortie `auditpol /get` | ⏳ |
| 6 | Agent Wazuh Windows (dashboard → Deploy new agent) → *Active* | Mohamed | capture du dashboard | ⏳ |
| 7 | Sysmon + config SwiftOnSecurity + canaux dans `ossec.conf` de l'agent | Mohamed | capture d'évènements Sysmon dans Discover | ⏳ |
| 8 | Rejouer les cas de `WAZUH-VALIDATION.md` dans `wazuh-logtest` | CI | cas 1-18 : **18/18 en CI** (voir C3-C4) ; cas 19 : voir C7 | ✅ (1-18) / ⏳ (19) |
| 9 | 2-3 tests bénins réels (`ATTACK-SIMULATION.md`) → alertes dans le dashboard | Mohamed | captures | ⏳ |
| 10 | Corriger les règles KO, mettre à jour README / CV / guide PDF | Claude | commits + PDF régénéré | ✅ règles + docs / ⏳ PDF |

Fichiers préparés : `C:\Users\VIET\.wslconfig` (6 Go RAM, 4 CPU, réseau `mirrored`),
`tools/deploy_rules_wsl.sh`, `datasets/wazuh_logtest/*.log` (lignes prêtes à coller).
