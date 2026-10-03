# Lab Wazuh dans GitHub Codespaces (rien à installer sur le PC)

> Préparé le 2026-10-03, **pas encore exécuté** : la première exécution est la tienne.
> Si une étape échoue, copie le message d'erreur et envoie-le.

Ce qu'on déploie : un **manager Wazuh 4.9.2** dans Docker (sans indexer ni dashboard, pour tenir dans
une petite machine Codespaces). C'est le composant qui contient le moteur de règles et `wazuh-logtest`,
donc suffisant pour valider les 19 cas de `docs/WAZUH-VALIDATION.md`.

## Étapes

1. **Publier ce dépôt sur GitHub** (on le fait ensemble une fois ton compte créé).
2. Sur la page du dépôt : bouton vert **Code → Codespaces → Create codespace on main**.
   Attendre que VS Code s'ouvre dans le navigateur (1 à 3 min la première fois).
3. Dans le **terminal** en bas :
   ```bash
   bash lab/start.sh
   ```
   → doit finir par `OK: lab rules loaded.` (le premier téléchargement de l'image prend quelques minutes).
4. Rejouer tous les cas :
   ```bash
   bash lab/run_all.sh
   ```
   → une ligne par fichier avec les IDs de règles déclenchées. Fais une **capture d'écran** du tableau.
5. Pour regarder un cas en détail (et faire une capture pour le CV) :
   ```bash
   cat lab/results/03_rdp_bruteforce_then_rdp_success.txt | tail -40
   ```
6. Envoie-moi la sortie de `run_all.sh`. Je compare avec la colonne « attendu » de
   `WAZUH-VALIDATION.md`, je corrige les règles KO, puis tu relances `bash lab/deploy_rules.sh && bash lab/run_all.sh`.
7. **Arrêter le Codespace** quand tu as fini (menu Codespaces → Stop) pour ne pas consommer ton quota gratuit.

## Ce que tu pourras dire en entretien
« J'ai déployé un manager Wazuh 4.9.2 dans un conteneur Docker (GitHub Codespaces), chargé mes règles,
et je les ai validées avec `wazuh-logtest` sur 19 cas, dont des cas négatifs. » Ne dis pas que tu as
supervisé un vrai parc : il n'y a pas d'agent sur une vraie machine dans cette version.

## Scripts
| Script | Rôle |
|---|---|
| `lab/start.sh` | démarre le conteneur, attend le moteur, charge les règles |
| `lab/deploy_rules.sh` | recopie `rules/wazuh/local_rules.xml`, valide (`wazuh-analysisd -t`), redémarre ; restaure la sauvegarde si erreur |
| `lab/windows_mode.sh on/off` | astuce de test pour les évènements Windows collés dans `wazuh-logtest` (règle 60000, voir WAZUH-VALIDATION §0) |
| `lab/run_all.sh` | rejoue les 18 fichiers de `datasets/wazuh_logtest/`, sauvegarde les sorties dans `lab/results/` |
