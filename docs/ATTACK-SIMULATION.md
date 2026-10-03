# ATTACK-SIMULATION — Tests bénins pour déclencher les règles

> **Cadre strict.** Ces manipulations sont **uniquement** à réaliser sur **TA
> propre machine de lab** (ta VM / ton WSL2 / ton Windows de test), jamais contre
> un système tiers. Il n'y a **aucun logiciel malveillant** ici : uniquement des
> actions bénignes et bien connues (échecs de connexion volontaires, création puis
> suppression d'un utilisateur de test, commande PowerShell inoffensive encodée,
> effacement d'un journal de test). Le but est de **vérifier que chaque règle se
> déclenche**, pas de nuire.

Après chaque test, vérifier l'alerte dans le dashboard Wazuh
(*Security events*) ou via `sudo /var/ossec/bin/wazuh-logtest`.

---

## 1. Force brute SSH — T1110 (règle `ssh_bruteforce` / Wazuh 100110)

Sur **ta** VM Linux, depuis une machine de lab, tenter plusieurs connexions avec
un mauvais mot de passe sur un **compte de test que tu possèdes** :

```bash
# 10 tentatives volontairement erronées vers TON hôte de lab
for i in $(seq 1 10); do
  ssh testuser@192.168.56.20 -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no exit
done
```
➜ Doit déclencher la détection de force brute (8+ échecs / 120 s).

---

## 2. Force brute RDP / connexions Windows — T1110 (`rdp_bruteforce` / 100121)

Sur **ta** machine de test, provoquer plusieurs échecs de connexion réseau :

```powershell
# 10 tentatives avec un mauvais mot de passe sur un compte de test local
1..10 | ForEach-Object {
  net use \\LAB-WIN11\IPC$ /user:testuser MauvaisMotDePasse 2>$null
}
```
➜ Génère des EventID 4625 (LogonType 3, réseau) → détection de force brute.
Remarque : avec NLA (défaut sur Windows 11), les échecs RDP réels sont eux aussi
journalisés en LogonType **3**, pas 10 — c'est pourquoi les règles acceptent 3 et 10.

---

## 3. Succès après échecs — T1110 (`success_after_failures` / 100111)

Enchaîner plusieurs échecs (test 1) **puis** une connexion correcte avec le bon
mot de passe de ton compte de test. ➜ Doit remonter la règle de compromission
probable.

**Variante Windows — règle n°12 `rdp_success_after_bruteforce` (Wazuh 100122 /
100123, T1110 + T1078).** Depuis une **deuxième machine de lab** (pas depuis
LAB-WIN11 lui-même : une connexion depuis 127.0.0.1 tombe sur la règle intégrée
92656), faire le test 2 (≥ 8 échecs en moins de 2 minutes), **puis** se connecter
avec le bon mot de passe du compte de test :

```powershell
# succès réseau NTLM type 3 -> 100123
net use \\LAB-WIN11\IPC$ /user:LAB-WIN11\testuser BonMotDePasseDeTest
net use \\LAB-WIN11\IPC$ /delete
```
ou ouvrir une session **RDP** (`mstsc /v:LAB-WIN11`) avec le bon mot de passe
➜ 4624 LogonType 10 → 100122. Avec NLA, on observe souvent d'abord un 4624 type 3
(vérification NLA) puis le type 10 : les deux règles peuvent sortir.
Nettoyage : fermer la session, `net user testuser /delete` si le compte a été créé
pour l'occasion.

---

## 4. Nouveau compte admin — T1136.001 / T1098 (`new_local_admin` / 100131)

```powershell
# création PUIS suppression immédiate d'un utilisateur de test
net user labtest P@ssForLabOnly! /add        # -> EventID 4720
net localgroup Administrators labtest /add    # -> EventID 4732
# Windows en français : le groupe s'appelle "Administrateurs"
#   net localgroup Administrateurs labtest /add
# (les règles Wazuh/Sigma utilisent le SID S-1-5-32-544, indépendant de la langue)
# ... vérifier l'alerte ...
net localgroup Administrators labtest /delete
net user labtest /delete                      # nettoyage
```
➜ La séquence 4720 puis 4732 (Administrators) déclenche la règle.
(Adapter aussi le nom du groupe dans les deux commandes de nettoyage.)

---

## 5. PowerShell encodé — T1059.001 (`encoded_powershell` / 100140)

Charge **totalement inoffensive** (`Write-Output hello`) encodée en base64 :

```powershell
$cmd = 'Write-Output hello'
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -NoProfile -EncodedCommand $enc
```
➜ Sysmon EID 1 avec `-EncodedCommand` → détection.

---

## 6. Tâche planifiée — T1053.005 (`scheduled_task_creation` / 100150)

```powershell
schtasks /create /tn "LabUpdater" /tr "cmd.exe /c whoami" /sc minute /mo 5
# ... vérifier l'alerte ...
schtasks /delete /tn "LabUpdater" /f        # nettoyage
```
➜ EventID 4698 et/ou schtasks.exe → détection. **4698 n'apparaît que si la
sous-catégorie d'audit « Other Object Access Events » est activée** (voir
`SETUP.md` §3 bis) ; sinon seule la règle Sysmon (100151) se déclenche.

---

## 7. Journal d'évènements effacé — T1685.005, ex-T1070.001 (`event_log_cleared` / 100160)

> À faire **uniquement sur la machine/VM de lab**, jamais sur un poste de prod.
> L'EventID 1102 n'est produit **que** par l'effacement du journal **Security**
> (effacer un autre journal produit l'EventID 104 dans le journal System, que
> cette règle ne couvre pas). Ce test efface donc les traces des tests
> précédents : **exporter d'abord**.

```powershell
wevtutil epl Security C:\lab\security-avant-test.evtx   # sauvegarde
wevtutil cl Security                                      # -> EventID 1102
```
➜ EventID 1102 → détection d'effacement de journaux (l'évènement a déjà été
transmis au manager Wazuh : c'est tout l'intérêt de la centralisation).

---

## 8. Scan de ports — T1046 (`port_scan` / 100171)

Depuis une machine de lab, scanner **ton propre** hôte de test :

```bash
# nmap sur TON hôte de lab uniquement
nmap -sT -p 1-1000 10.10.0.12
```
➜ Nombreux ports distincts contactés depuis une même source (Sysmon EID 3) →
détection de scan. **Limite :** Sysmon ne journalise que les connexions
réellement acceptées par un processus de l'hôte (ports ouverts) et la config
SwiftOnSecurity filtre EID 3 ; il est donc normal que peu d'évènements
remontent (voir `SETUP.md` §5). Résultat négatif = limite de la source de
données, pas forcément de la règle.

---

## 9. Defender désactivé — T1685, ex-T1562.001 (`defender_disabled` / 100180, 100181)

> Sur **ta** VM de test uniquement. **Réactiver** aussitôt après.
> Si la **Protection contre les falsifications** (Tamper Protection, active par
> défaut) est activée, la commande est bloquée : la règle 100180 (ligne de
> commande, Sysmon EID 1) se déclenche quand même — c'est une *tentative* — mais
> pas la règle 100181 (EventID 5001, changement d'état réel).

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true    # -> alerte critique
# ... vérifier l'alerte ...
Set-MpPreference -DisableRealtimeMonitoring $false   # réactivation immédiate
```

---

## 10. Requête type web shell — T1505.003 (`web_shell_request` / 100190)

Sur **ton** serveur web de lab, envoyer des requêtes inoffensives qui ont le
**comportement** d'une interaction web shell (aucun fichier `.php` n'est déposé) :

```bash
curl "http://127.0.0.1/index.php?cmd=whoami"      # 100190 : commande système dans un paramètre (même en 404)
curl "http://127.0.0.1/index.php?cmd=Y2F0IC9ldGMvcGFzc3dk"   # 100191 : charge base64
curl "http://127.0.0.1/search?q=evaluation"       # NE DOIT RIEN déclencher (test négatif)
```
➜ Les deux premières lignes du journal d'accès déclenchent la règle ; la troisième
non. L'indicateur « POST réussi vers un `.php` dans `uploads/` » (100192) demande un
statut 2xx : il n'est testable qu'avec un script **inoffensif** que tu crées toi-même
dans un dossier `uploads/` de ton serveur de lab (par ex. un fichier qui affiche
`ok`), à supprimer juste après.

---

## 11. Office lance un shell — T1204.002 (`office_spawns_shell` / 100200)

Pour simuler **sans macro malveillante**, on reproduit la relation parent→enfant
en lançant un shell depuis Word via son modèle de processus. La méthode la plus
simple et sûre est de créer une macro de test **inoffensive** dans un document de
lab qui exécute `cmd.exe /c whoami`, puis de la supprimer. À défaut, documenter
que la détection repose sur `ParentImage = WINWORD.EXE` et `Image = cmd.exe` dans
Sysmon EID 1.

> ⚠️ Ne jamais activer de macros provenant de documents externes. Utiliser
> exclusivement un document créé par toi, dans la VM de lab, avec une commande
> inoffensive.

---

## 12. Succès distant après force brute — T1110 + T1078 (`rdp_success_after_bruteforce` / 100122, 100123)

Voir la variante Windows du §3 : ≥ 8 échecs 4625 depuis une machine de lab, puis
une connexion réussie (RDP ou `net use` NTLM) depuis **la même IP** en moins de
3 minutes. Test négatif : 7 échecs seulement, puis succès ➜ aucune alerte.

---

## Nettoyage final

- Supprimer les comptes/tâches de test créés.
- Réactiver Microsoft Defender.
- Retirer les éventuels fichiers de test du serveur web.
- Vérifier que la VM de lab est revenue à un état propre.
