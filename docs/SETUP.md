# SETUP — Déploiement du lab Wazuh (plan)

> Ce document est un **plan de déploiement** à exécuter par Mohamed sur **sa
> propre machine**. Rien n'est installé par ce dépôt. Objectif : un petit lab
> Wazuh fonctionnel tenant dans **~10–12 Go** de disque, sur Windows 11 Pro avec
> ~22 Go libres, 8–16 Go de RAM, sans Docker, Python 3.11.

## 0. Vue d'ensemble

On déploie **Wazuh 4.x all-in-one** (manager + indexer + dashboard) dans une
**Ubuntu 22.04 sous WSL2** (option recommandée, légère), puis on installe
l'**agent Wazuh + Sysmon** sur l'hôte Windows pour envoyer les évènements.

| Composant | Où | Disque estimé | RAM |
|-----------|-----|---------------|-----|
| Ubuntu 22.04 (WSL2) | Windows | ~2–3 Go | — |
| Wazuh all-in-one (manager+indexer+dashboard) | dans WSL2 | ~6–8 Go | 3–4 Go au repos |
| Agent Wazuh (Windows) | hôte Windows | ~100 Mo | faible |
| Sysmon + config | hôte Windows | ~50 Mo | faible |
| **Total** | | **~9–11 Go** | **≥ 4 Go conseillée** |

> Alternative sans WSL2 : une petite VM VirtualBox Ubuntu Server (2 vCPU, 4 Go RAM,
> disque dynamique 15 Go). Plus lourde en disque, mais plus isolée. Les étapes
> Wazuh sont identiques.

---

## 1. Prérequis Windows

1. Vérifier l'espace disque : **≥ 15 Go libres** recommandés avant de commencer.
2. Activer WSL2 (PowerShell **administrateur**) :
   ```powershell
   wsl --install -d Ubuntu-22.04
   wsl --set-default-version 2
   ```
   Redémarrer si demandé, puis créer l'utilisateur Ubuntu.
3. Limiter la RAM de WSL2 (évite que l'indexer prenne tout) — fichier
   `C:\Users\<toi>\.wslconfig` :
   ```ini
   [wsl2]
   memory=5GB
   processors=2
   swap=2GB
   ```
   Puis `wsl --shutdown` et rouvrir Ubuntu.

---

## 2. Installer Wazuh all-in-one (dans Ubuntu/WSL2)

> Référence officielle : documentation.wazuh.com → « Quickstart ».

```bash
sudo apt update && sudo apt upgrade -y
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
sudo bash ./wazuh-install.sh -a -i
```

- `-a` = installation all-in-one (manager + indexer + dashboard).
- À la fin, le script affiche l'**URL du dashboard** (https://<ip-wsl>:443), le
  login `admin` et le **mot de passe généré** (le noter).
- Récupérer l'IP WSL : `ip addr show eth0 | grep inet`.

### Démarrage / arrêt des services
```bash
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard
# WSL2 ancien sans systemd : utiliser `sudo service <nom> start`
```
> Astuce WSL2 : activer systemd via `/etc/wsl.conf` →
> `[boot]\nsystemd=true`, puis `wsl --shutdown`.

---

## 3. Déployer les règles personnalisées du lab

Copier le fichier de règles de ce dépôt dans le manager :

```bash
sudo cp rules/wazuh/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-logtest   # tester quelques lignes de log
sudo systemctl restart wazuh-manager
```

---

## 4. Installer l'agent Wazuh sur Windows

1. Dans le dashboard Wazuh → **Agents → Deploy new agent** → choisir *Windows*,
   renseigner l'IP du manager (IP WSL2) → copier la commande d'installation
   fournie (MSI + `WAZUH_MANAGER`).
2. Exécuter la commande dans PowerShell **administrateur**, puis :
   ```powershell
   net start WazuhSvc
   ```
3. L'agent doit apparaître **Active** dans le dashboard.

---

## 5. Installer Sysmon avec une config communautaire

1. Télécharger **Sysmon** depuis Microsoft Sysinternals.
2. Utiliser une configuration communautaire reconnue :
   **SwiftOnSecurity/sysmon-config** (`sysmonconfig-export.xml`) ou la config
   **Olaf Hartong / sysmon-modular**.
3. Installer :
   ```powershell
   .\Sysmon64.exe -accepteula -i .\sysmonconfig-export.xml
   ```
4. Dire à l'agent Wazuh de remonter le canal Sysmon — dans
   `C:\Program Files (x86)\ossec-agent\ossec.conf`, ajouter :
   ```xml
   <localfile>
     <location>Microsoft-Windows-Sysmon/Operational</location>
     <log_format>eventchannel</log_format>
   </localfile>
   ```
   S'assurer aussi que le canal **Security** est remonté (souvent présent par
   défaut). Puis `Restart-Service WazuhSvc`.

---

## 6. Vérification (le lab fonctionne)

1. **Agent connecté** : dashboard → Agents → statut *Active*.
2. **Évènements qui arrivent** : dashboard → Discover / Security events,
   filtrer sur l'agent Windows ; on doit voir des évènements Sysmon et Security.
3. **Règle qui se déclenche** : lancer un test bénin de
   `docs/ATTACK-SIMULATION.md` (ex. vider un journal de test, commande PowerShell
   encodée inoffensive) et vérifier l'alerte correspondante dans le dashboard.
4. **Test des règles sans agent** : sur le manager,
   `sudo /var/ossec/bin/wazuh-logtest` puis coller une ligne de
   `datasets/auth.log` → la règle `100110` doit matcher après 8 lignes.

---

## 7. Désinstallation propre

### Côté Windows
```powershell
# Agent Wazuh
net stop WazuhSvc
msiexec /x "wazuh-agent-4.x.msi" /qn      # ou via Panneau de config > Programmes
# Sysmon
.\Sysmon64.exe -u
```

### Côté WSL2 / Wazuh
```bash
# désinstaller Wazuh proprement
sudo bash ./wazuh-install.sh --uninstall
```
Puis, pour **tout** supprimer et récupérer l'espace disque :
```powershell
wsl --shutdown
wsl --unregister Ubuntu-22.04   # supprime la distribution et son disque virtuel
```
Enfin, supprimer `C:\Users\<toi>\.wslconfig` si tu ne veux plus limiter WSL2.

---

## 8. Dépannage rapide

| Symptôme | Piste |
|----------|-------|
| Dashboard inaccessible | vérifier l'IP WSL2 (change à chaque reboot), services `wazuh-dashboard` actifs |
| Indexer qui ne démarre pas | manque de RAM → augmenter `memory` dans `.wslconfig` ou réduire `-Xms/-Xmx` JVM |
| Agent en *Never connected* | pare-feu Windows : ouvrir le port **1514/1515** vers le manager |
| Pas d'évènements Sysmon | canal mal déclaré dans `ossec.conf` ou Sysmon non installé |
| `wazuh-logtest` ne matche pas | vérifier le SID parent du décodeur (varie selon version) |

> **Rappel sécurité** : ce lab reste sur ta propre machine. Ne jamais tester de
> techniques offensives contre des systèmes qui ne t'appartiennent pas.
