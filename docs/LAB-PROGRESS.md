# Wazuh lab — suivi pas à pas

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
| 8 | Rejouer les 19 cas de `WAZUH-VALIDATION.md` dans `wazuh-logtest` | Mohamed | tableau OK/KO + captures dans `docs/screenshots/` | ⏳ |
| 9 | 2-3 tests bénins réels (`ATTACK-SIMULATION.md`) → alertes dans le dashboard | Mohamed | captures | ⏳ |
| 10 | Corriger les règles KO, mettre à jour README / CV / guide PDF | Claude | commits + PDF régénéré | ⏳ |

Fichiers préparés : `C:\Users\VIET\.wslconfig` (6 Go RAM, 4 CPU, réseau `mirrored`),
`tools/deploy_rules_wsl.sh`, `datasets/wazuh_logtest/*.log` (lignes prêtes à coller).
