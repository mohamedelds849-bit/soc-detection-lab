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
| **Total** | | **~9–11 Go** (au départ) | **≥ 4 Go pour WSL2, 6 Go conseillés** |

> **Réalisme disque/RAM.** Wazuh recommande officiellement 4 vCPU / 8 Go de RAM
> pour un all-in-one ; 4–6 Go fonctionnent pour un lab d'un seul agent mais
> l'indexer (OpenSearch/JVM) est le premier à tomber en manque de mémoire. Avec
> 8 Go de RAM physique sur l'hôte, préférer `memory=4GB` et fermer les
> applications lourdes ; avec 16 Go, `memory=6GB`. Côté disque, l'estimation est
> celle d'une installation fraîche : les index d'alertes grossissent avec le
> temps et la détection de vulnérabilités (activée par défaut depuis 4.8) peut
> ajouter plusieurs Go → la désactiver pour le lab (voir §2). Le disque virtuel
> `ext4.vhdx` de WSL2 **ne rétrécit pas tout seul** quand on supprime des
> fichiers (voir §7).

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
   Option (Windows 11 22H2+) : ajouter `networkingMode=mirrored` sous `[wsl2]`
   pour que WSL2 partage le réseau de l'hôte — l'IP du manager ne change plus à
   chaque redémarrage (sinon l'agent perd le manager, voir §8).
4. **Activer systemd — OBLIGATOIRE avant d'installer Wazuh.** L'assistant
   `wazuh-install.sh` crée, active et démarre des services **systemd** ; sans
   systemd l'installation échoue. Vérifier dans Ubuntu :
   ```bash
   ps -p 1 -o comm=        # doit afficher : systemd
   ```
   Sinon, éditer `/etc/wsl.conf` (`sudo nano /etc/wsl.conf`) et ajouter :
   ```ini
   [boot]
   systemd=true
   ```
   puis `wsl --shutdown` côté Windows et rouvrir Ubuntu. Nécessite une version
   récente de WSL (`wsl --version` ; sinon `wsl --update`).

---

## 2. Installer Wazuh all-in-one (dans Ubuntu/WSL2)

> Référence officielle : documentation.wazuh.com → « Quickstart ».

```bash
sudo apt update && sudo apt upgrade -y
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
sudo bash ./wazuh-install.sh -a -i
```

- `-a` = installation all-in-one (manager + indexer + dashboard).
- `-i` = **ignorer la vérification des prérequis matériels** (CPU/RAM) de
  l'assistant. Utile dans WSL2 avec peu de RAM, mais c'est un choix conscient :
  si l'indexer plante ensuite, c'est la RAM (voir §8).
- À la fin, le script affiche l'**URL du dashboard** (https://<ip-wsl>:443), le
  login `admin` et le **mot de passe généré** (le noter).
- Récupérer l'IP WSL : `ip addr show eth0 | grep inet`.

### Démarrage / arrêt des services
```bash
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard
sudo systemctl stop wazuh-dashboard wazuh-indexer wazuh-manager   # libère la RAM
```

### (Recommandé pour le lab) désactiver la détection de vulnérabilités
Dans `/var/ossec/etc/ossec.conf`, bloc `<vulnerability-detection>` →
`<enabled>no</enabled>`, puis `sudo systemctl restart wazuh-manager`. Économise
plusieurs Go de disque et de la RAM ; inutile pour ce projet de détection.

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

## 3 bis. Politique d'audit Windows (sinon certaines règles restent muettes)

Par défaut Windows 11 journalise les connexions (4624/4625), la gestion des
comptes (4720) et des groupes de sécurité (4732), mais **pas** la création de
tâches planifiées (**4698**). Dans PowerShell **administrateur** (GUID utilisés
car les noms de sous-catégories sont traduits sur un Windows français) :

```powershell
# Other Object Access Events -> EventID 4698
auditpol /set /subcategory:"{0CCE9227-69AE-11D9-BED3-08002B30309D}" /success:enable
# vérifier Logon, User Account Management, Security Group Management
auditpol /get /subcategory:"{0CCE9215-69AE-11D9-BED3-08002B30309D},{0CCE9235-69AE-11D9-BED3-08002B30309D},{0CCE9237-69AE-11D9-BED3-08002B30309D}"
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
   S'assurer aussi que le canal **Security** est remonté (présent par défaut).
   Pour la règle Defender 5001 (100181), ajouter de la même façon le canal
   `Microsoft-Windows-Windows Defender/Operational`.
   Puis `Restart-Service WazuhSvc`.

> **Limite Sysmon EID 3 (scan de ports).** Sysmon ne journalise que les
> connexions qu'un processus de l'hôte a réellement établies/acceptées : un scan
> vers des ports **fermés** ne produit aucun EID 3, et la config SwiftOnSecurity
> filtre fortement EID 3. La règle de scan (100171) ne verra donc qu'une partie
> du scan. Pour un vrai lab de détection de scan, journaliser le pare-feu Windows
> (sous-catégorie *Filtering Platform Connection*, EventID 5156/5157) ou des logs
> réseau (Zeek, pare-feu).

---

## 6. Vérification (le lab fonctionne)

1. **Agent connecté** : dashboard → Agents → statut *Active*.
2. **Évènements qui arrivent** : dashboard → Discover / Security events,
   filtrer sur l'agent Windows ; on doit voir des évènements Sysmon et Security.
3. **Règle qui se déclenche** : lancer un test bénin de
   `docs/ATTACK-SIMULATION.md` (ex. vider un journal de test, commande PowerShell
   encodée inoffensive) et vérifier l'alerte correspondante dans le dashboard.
4. **Test des règles sans agent** : sur le manager,
   `sudo /var/ossec/bin/wazuh-logtest` puis coller **8 lignes** « Failed
   password » de `datasets/auth.log` (même IP source) → la règle `100110` doit
   matcher à la 8ᵉ. Les fichiers `*.jsonl` du dépôt utilisent un schéma simplifié
   (pas le JSON `win.system.*` de l'eventchannel Wazuh) : ils ne se collent pas
   tels quels dans `wazuh-logtest` ; tester les règles Windows avec de vrais
   évènements (§6.3).

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

> **Récupérer de l'espace sans tout désinstaller :** supprimer des fichiers dans
> Ubuntu ne réduit pas `ext4.vhdx`. Avec WSL ≥ 2.0 :
> `wsl --manage Ubuntu-22.04 --set-sparse true` (le disque rend alors l'espace
> libéré). `wsl --unregister` reste la seule méthode qui libère tout.

---

## 8. Dépannage rapide

| Symptôme | Piste |
|----------|-------|
| Dashboard inaccessible | vérifier l'IP WSL2 (change à chaque reboot), services `wazuh-dashboard` actifs |
| Indexer qui ne démarre pas | manque de RAM → augmenter `memory` dans `.wslconfig` ou réduire `-Xms/-Xmx` JVM |
| Agent en *Never connected* / *Disconnected* | l'IP WSL2 a changé (mettre à jour `<address>` dans l'`ossec.conf` de l'agent, ou passer en `networkingMode=mirrored`) ; vérifier que le manager écoute sur **1514/1515** (`sudo ss -tlnp`) |
| Pas d'évènements Sysmon | canal mal déclaré dans `ossec.conf` ou Sysmon non installé |
| `wazuh-logtest` ne matche pas | vérifier le SID parent du décodeur (varie selon version) |

> **Rappel sécurité** : ce lab reste sur ta propre machine. Ne jamais tester de
> techniques offensives contre des systèmes qui ne t'appartiennent pas.
