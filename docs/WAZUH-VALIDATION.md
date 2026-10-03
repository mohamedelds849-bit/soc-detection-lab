# WAZUH-VALIDATION — Checklist de validation des règles sur un vrai Wazuh

> **Statut au 2026-10-03 : AUCUNE règle Wazuh de ce dépôt n'a encore été exécutée
> sur un manager réel.** Les 19 règles de `rules/wazuh/local_rules.xml` (100110 à
> 100200) sont **non testées**. Ce qui a été vérifié : XML bien formé, SID parents
> et ordre d'évaluation relus dans le **code source** de Wazuh v4.9.2
> (`ruleset/rules/*.xml`, `src/analysisd/rules_list.c`, `eventinfo.c`, `rules.c`),
> et regex web shell (100190-100192) exécutées en Python par `pytest` sur les mêmes
> exemples positifs/négatifs que le moteur. Cette checklist sert à remplacer
> « non testé » par un vrai résultat, **règle par règle**.
>
> Ce travail (déployer Wazuh, rejouer, faire les captures) est à faire par
> Mohamed lui-même (révision n°1 de l'audit).

---

## 0. Ce qu'il faut savoir avant de commencer

1. **Version.** Noter la version exacte : `sudo /var/ossec/bin/wazuh-control info`.
   Les SID parents ont été relus pour **4.9.2** ; ils peuvent changer.
2. **Installer les règles** : voir `docs/SETUP.md` §3, puis
   `sudo systemctl restart wazuh-manager`. Vérifier qu'il n'y a pas d'erreur :
   `sudo grep -i "error\|warn" /var/ossec/logs/ossec.log | tail`.
3. **Ordre des règles sœurs.** Dans Wazuh, les enfants d'une règle sont essayés
   par **niveau décroissant**, puis dans l'ordre de chargement (les règles
   intégrées avant `local_rules.xml`). Une règle intégrée de même niveau ou de
   niveau supérieur, sur le même parent, gagne donc en premier. C'est pour cela que
   100110 et 100121 sont maintenant des **enfants** des règles intégrées 5763 et
   60204, et que 100111/100122/100123 sont au niveau 13 (au-dessus de 40112).
   **À confirmer en logtest** : c'est la première chose qu'un analyste N2 vérifiera.
4. **Corrélation = heure de réception.** Les règles `frequency` / `if_matched_sid`
   comptent avec l'heure à laquelle le manager **reçoit** la ligne, pas avec le
   `systemTime` du log. Coller les lignes d'un même cas **en moins de 2 minutes**.
   Entre deux cas, **quitter `wazuh-logtest` (Ctrl+C) et le relancer** : une session
   garde l'état de corrélation, sinon les cas se mélangent.
5. **Logs texte** (SSH, Apache) : se collent directement dans `wazuh-logtest`.
6. **Logs Windows (JSON)** : sur un manager standard, une ligne JSON collée dans
   `wazuh-logtest` est décodée par le décodeur `json`, alors que la règle racine
   Windows **60000** exige `<decoded_as>windows_eventchannel</decoded_as>`. Les règles
   Windows **ne matchent donc pas** en logtest par défaut. Deux options :
   - **Option A (recommandée, bout en bout).** Générer les vrais évènements sur
     Windows avec `docs/ATTACK-SIMULATION.md`, puis chercher l'alerte dans le
     dashboard ou dans `/var/ossec/logs/alerts/alerts.json`
     (`sudo grep '"id":"100122"' /var/ossec/logs/alerts/alerts.json | tail -1`).
   - **Option B (logtest, temporaire).** Faire comme le banc de test officiel de
     Wazuh (`ruleset/testing/runtests.py`, fonction
     `enable_win_eventlog_test_actions`) : dans
     `/var/ossec/ruleset/rules/0575-win-base_rules.xml`, règle 60000, remplacer
     `<category>ossec</category>` + `<decoded_as>windows_eventchannel</decoded_as>`
     par `<decoded_as>json</decoded_as>`. **Sauvegarder le fichier avant**, et le
     **restaurer après les tests** (puis redémarrer) : ne jamais laisser cette
     modification en place.
     ```bash
     sudo cp /var/ossec/ruleset/rules/0575-win-base_rules.xml /root/0575.bak
     # ... éditer la règle 60000, sudo systemctl restart wazuh-manager, tester ...
     sudo cp /root/0575.bak /var/ossec/ruleset/rules/0575-win-base_rules.xml
     sudo systemctl restart wazuh-manager
     ```
7. **Fichiers à coller.** `python tools/make_wazuh_samples.py` génère
   `datasets/wazuh_logtest/NN_*.log` (une ligne = un évènement, dans l'ordre où il
   faut les coller). Les lignes Windows y sont au format eventchannel
   (`{"win":{"system":…,"eventdata":…}}`, champs en camelCase).
8. **Captures.** Mettre les captures dans `docs/screenshots/` avec le nom indiqué
   dans la colonne « Capture ». Une capture logtest doit montrer la **Phase 3** :
   `id`, `level`, `description`.

---

## 1. Tableau de résultats (à remplir)

Légende « Attendu » : chaîne de règles prévue d'après le code source 4.9.2.
« Risque » : ce qui peut faire échouer le test.

| # | Règle(s) | Fichier à coller | Attendu | Risque à surveiller | Résultat (OK / KO + règle obtenue) | Capture |
|---|----------|------------------|---------|---------------------|-------------------------------------|---------|
| 1 | 100110, 100111 | `01_ssh_bruteforce_then_success.log` (9 lignes) | l.1-7 : **5760** (niv. 5) ; l.8 : **5763 → 100110** (niv. 10) ; l.9 : **100111** (niv. 13) | Décodeur `sshd` ; 40112 (niv. 12) si 100111 ne gagne pas | | `01-logtest-ssh.png` |
| 2 | 100110, 100111 (négatif) | `02_ssh_7_failures_then_success_NEGATIVE.log` (8) | l.1-7 : 5760 ; l.8 : **5715** (niv. 3). **Pas** de 100110 / 100111 | — | | `02-logtest-ssh-neg.png` |
| 3 | 100121, **100122** | `03_rdp_bruteforce_then_rdp_success.log` (9) | l.1-7 : **60122** (niv. 5) ; l.8 : **60204 → 100121** (niv. 10) ; l.9 : **100122** (niv. 13) | Option A/B obligatoire ; 92653 (niv. 3) ou 40112 (niv. 12) à la place de 100122 | | `03-logtest-rdp-success.png` |
| 4 | 100121, **100123** | `04_network_bruteforce_then_ntlm_success.log` (9) | l.8 : 100121 ; l.9 : **100123** (niv. 13) | 92652 (NTLM, niv. 6) à la place de 100123 | | `04-logtest-ntlm-success.png` |
| 5 | 100123 (négatif) | `05_network_bruteforce_then_kerberos_success_NEGATIVE.log` (9) | l.8 : 100121 ; l.9 : **pas** 100122/100123 (attendu 92651 niv. 0, ou 40112) | — | | `05-logtest-kerberos-neg.png` |
| 6 | 100121, 100122 (négatif) | `06_rdp_7_failures_then_success_NEGATIVE.log` (8) | l.1-7 : 60122 ; l.8 : **92653** (niv. 3). **Pas** de 100121 / 100122 | — | | `06-logtest-rdp-neg.png` |
| 7 | 100130, 100131 | `07_new_account_added_to_admins.log` (2) | l.1 : **100130** (niv. 6, parent 60109) ; l.2 : **60154 → 100131** (niv. 10) | 60154 (niv. 12) reste l'alerte si 100131 ne matche pas | | `07-logtest-new-admin.png` |
| 8 | 100131 (limite connue) | `08_unrelated_account_added_to_admins_KNOWN_LIMITATION.log` (2) | **100131 se déclenche quand même** (Wazuh ne peut pas joindre `targetSid` 4720 et `memberSid` 4732). Le moteur et Sigma, eux, ne déclenchent pas | Documenter le résultat tel quel | | `08-logtest-admin-limitation.png` |
| 9 | 100140 | `09_encoded_powershell.log` (1) | **100140** (niv. 10) | **92057** (niv. 12) gagne si le parent est `powershell.exe` | | `09-logtest-encoded-ps.png` |
| 10 | 100150 | `10_scheduled_task_4698.log` (1) | 60228 → **100150** (niv. 7) | — | | `10-logtest-4698.png` |
| 11 | 100151 | `11_scheduled_task_schtasks.log` (1) | **100151** (niv. 7) | Règle Sysmon intégrée de niveau ≥ 7 sur `schtasks` | | `11-logtest-schtasks.png` |
| 12 | 100160 | `12_security_log_cleared.log` (1) | 63103 (ou 60117) → **100160** (niv. 12) | Parent différent selon `providerName` | | `12-logtest-1102.png` |
| 13 | 100170, 100171 | `13_port_scan_15_connections.log` (15) | l.1-14 : **100170** (niv. 3) ; l.15 : **100171** (niv. 10) | Compte des **connexions**, pas des ports distincts | | `13-logtest-portscan.png` |
| 14 | 100180 | `14_defender_disable_command.log` (1) | **100180** (niv. 12), essayée avant 92007 (niv. 3) | — | | `14-logtest-defender-cmd.png` |
| 15 | 100181 | `15_defender_5001.log` (1) | 62152 → **100181** (niv. 12) | Canal Defender / severityValue | | `15-logtest-defender-5001.png` |
| 16 | 100200 | `16_office_spawns_shell.log` (1) | **100200** (niv. 10) | 92047 (mshta) ne s'applique pas ici | | `16-logtest-office.png` |
| 17 | 100190, 100191, 100192 | `17_web_shell_requests.log` (4) | l.1 : **100190** ; l.2 : **100190** ; l.3 : **100192** ; l.4 : **100191** (tous niv. 10) | Décodeur `web-accesslog` : vérifier `srcip`, `protocol`, `url`, `id` en Phase 2 | | `17-logtest-webshell.png` |
| 18 | 100190-100192 (négatif) | `18_web_lookalikes_NEGATIVE.log` (10) | **aucune** règle 1001xx (31100 / 31108, niv. 0) | `/search?q=evaluation` ne doit plus rien déclencher | | `18-logtest-web-neg.png` |
| 19 | Bout en bout | ATTACK-SIMULATION §2 + §3 bis (RDP réel) | Alerte **100122** ou **100123** dans le dashboard | NLA : la réussite peut être 4624 type 3 puis type 10 | | `19-dashboard-rdp-success.png` |

Après le remplissage : reporter le tableau OK / KO dans le README (section
« Limitations ») et corriger chaque règle KO (souvent : la rattacher comme enfant
de la règle intégrée qui gagne, avec `if_sid`).

---

## 2. Lignes à coller

### Cas 1 — SSH force brute puis succès (100110, 100111)
Coller la 1ʳᵉ ligne **8 fois** (ou les 8 premières lignes du fichier), puis la ligne « Accepted » :
```
Mar 10 08:35:06 lab-web01 sshd[7222]: Failed password for mohamed from 203.0.113.66 port 49996 ssh2
Mar 10 08:36:00 lab-web01 sshd[1378]: Accepted password for mohamed from 203.0.113.66 port 59731 ssh2
```

### Cas 2 — 7 échecs puis succès (négatif)
```
Mar 10 08:10:00 lab-web01 sshd[4242]: Failed password for backup from 10.10.0.31 port 50100 ssh2
Mar 10 08:10:40 lab-web01 sshd[4243]: Accepted password for backup from 10.10.0.31 port 50110 ssh2
```
(1ʳᵉ ligne ×7, puis la 2ᵉ.)

### Cas 3 — RDP : 8 échecs puis connexion RDP réussie (100121, 100122)
4625 ×8 :
```
{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","eventID":"4625","channel":"Security","computer":"LAB-WIN11","severityValue":"AUDIT_FAILURE","systemTime":"2026-03-10T08:50:05.000Z"},"eventdata":{"targetUserName":"administrator","logonType":"10","ipAddress":"198.51.100.77","status":"0xC000006D","subStatus":"0xC000006A"}}}
```
puis 4624 :
```
{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","eventID":"4624","channel":"Security","computer":"LAB-WIN11","severityValue":"AUDIT_SUCCESS","systemTime":"2026-03-10T08:50:59.000Z"},"eventdata":{"targetUserName":"administrator","logonType":"10","ipAddress":"198.51.100.77","authenticationPackageName":"Negotiate"}}}
```

### Cas 4 — 8 échecs réseau puis succès NTLM type 3 (100121, 100123)
4625 (type 3) ×8 :
```
{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","eventID":"4625","channel":"Security","computer":"LAB-WIN11","severityValue":"AUDIT_FAILURE","systemTime":"2026-03-10T08:50:05.000Z"},"eventdata":{"targetUserName":"administrator","logonType":"3","ipAddress":"198.51.100.77","status":"0xC000006D","subStatus":"0xC000006A"}}}
```
puis :
```
{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","eventID":"4624","channel":"Security","computer":"LAB-WIN11","severityValue":"AUDIT_SUCCESS","systemTime":"2026-03-10T08:50:59.000Z"},"eventdata":{"targetUserName":"administrator","logonType":"3","ipAddress":"198.51.100.77","authenticationPackageName":"NTLM"}}}
```

### Cas 5 — idem mais succès Kerberos (négatif)
Mêmes 8 lignes que le cas 4, puis :
```
{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","eventID":"4624","channel":"Security","computer":"LAB-WIN11","severityValue":"AUDIT_SUCCESS","systemTime":"2026-03-10T08:50:59.000Z"},"eventdata":{"targetUserName":"administrator","logonType":"3","ipAddress":"198.51.100.77","authenticationPackageName":"Kerberos"}}}
```

### Cas 6 — 7 échecs RDP puis succès (négatif)
4625 ×7 puis 4624 :
```
{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","eventID":"4625","channel":"Security","computer":"LAB-WIN11","severityValue":"AUDIT_FAILURE","systemTime":"2026-03-10T08:12:00.000Z"},"eventdata":{"targetUserName":"yassine","logonType":"10","ipAddress":"10.10.0.30","status":"0xC000006D","subStatus":"0xC000006A"}}}
{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","eventID":"4624","channel":"Security","computer":"LAB-WIN11","severityValue":"AUDIT_SUCCESS","systemTime":"2026-03-10T08:12:40.000Z"},"eventdata":{"targetUserName":"yassine","logonType":"10","ipAddress":"10.10.0.30","authenticationPackageName":"Negotiate"}}}
```

### Cas 7 — nouveau compte puis ajout aux Administrateurs (100130, 100131)
```
{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","eventID":"4720","channel":"Security","computer":"LAB-WIN11","severityValue":"AUDIT_SUCCESS","systemTime":"2026-03-10T08:58:00.000Z"},"eventdata":{"targetUserName":"svc_helper","targetSid":"S-1-5-21-1111111111-2222222222-3333333333-1005","subjectUserName":"administrator"}}}
{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","eventID":"4732","channel":"Security","computer":"LAB-WIN11","severityValue":"AUDIT_SUCCESS","systemTime":"2026-03-10T08:58:08.000Z"},"eventdata":{"targetUserName":"Administrators","targetSid":"S-1-5-32-544","memberName":"-","memberSid":"S-1-5-21-1111111111-2222222222-3333333333-1005","subjectUserName":"administrator"}}}
```

### Cas 8 — compte A créé, compte B ajouté (limite connue de Wazuh)
```
{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","eventID":"4720","channel":"Security","computer":"LAB-WIN11","severityValue":"AUDIT_SUCCESS","systemTime":"2026-03-10T08:20:00.000Z"},"eventdata":{"targetUserName":"intern01","targetSid":"S-1-5-21-1111111111-2222222222-3333333333-1006","subjectUserName":"administrator"}}}
{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","eventID":"4732","channel":"Security","computer":"LAB-WIN11","severityValue":"AUDIT_SUCCESS","systemTime":"2026-03-10T08:20:30.000Z"},"eventdata":{"targetUserName":"Administrators","targetSid":"S-1-5-32-544","memberName":"-","memberSid":"S-1-5-21-1111111111-2222222222-3333333333-1002","subjectUserName":"administrator"}}}
```

### Cas 9 — PowerShell encodé (100140)
```
{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1","channel":"Microsoft-Windows-Sysmon/Operational","computer":"LAB-WIN11","severityValue":"INFORMATION","systemTime":"2026-03-10T09:00:00.000Z"},"eventdata":{"image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","parentImage":"C:\\Windows\\System32\\cmd.exe","commandLine":"powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABoAGUAbABsAG8A","user":"LAB-WIN11\\mohamed"}}}
```

### Cas 10 — tâche planifiée 4698 (100150)
```
{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","eventID":"4698","channel":"Security","computer":"LAB-WIN11","severityValue":"AUDIT_SUCCESS","systemTime":"2026-03-10T09:01:00.000Z"},"eventdata":{"taskName":"\\Updater","subjectUserName":"mohamed"}}}
```

### Cas 11 — schtasks.exe /create (100151)
```
{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1","channel":"Microsoft-Windows-Sysmon/Operational","computer":"LAB-WIN11","severityValue":"INFORMATION","systemTime":"2026-03-10T09:01:01.000Z"},"eventdata":{"image":"C:\\Windows\\System32\\schtasks.exe","parentImage":"C:\\Windows\\System32\\cmd.exe","commandLine":"schtasks.exe /create /tn \"Updater\" /tr \"cmd.exe /c whoami\" /sc minute /mo 5","user":"LAB-WIN11\\mohamed"}}}
```

### Cas 12 — journal Security effacé (100160)
```
{"win":{"system":{"providerName":"Microsoft-Windows-Eventlog","eventID":"1102","channel":"Security","computer":"LAB-WIN11","severityValue":"INFORMATION","systemTime":"2026-03-10T09:02:00.000Z"},"eventdata":{"subjectUserName":"administrator"}}}
```

### Cas 13 — scan de ports (100170, 100171)
Coller les **15 lignes** du fichier (une connexion par ligne ; seul le port change). Exemple de ligne :
```
{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"3","channel":"Microsoft-Windows-Sysmon/Operational","computer":"LAB-WIN11","severityValue":"INFORMATION","systemTime":"2026-03-10T09:03:00.000Z"},"eventdata":{"image":"System","sourceIp":"203.0.113.90","destinationIp":"10.10.0.12","destinationPort":"21","protocol":"tcp"}}}
```

### Cas 14 — commande de désactivation de Defender (100180)
```
{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1","channel":"Microsoft-Windows-Sysmon/Operational","computer":"LAB-WIN11","severityValue":"INFORMATION","systemTime":"2026-03-10T09:04:00.000Z"},"eventdata":{"image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","parentImage":"C:\\Windows\\System32\\cmd.exe","commandLine":"powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true","user":"LAB-WIN11\\administrator"}}}
```

### Cas 15 — Defender 5001 (100181)
```
{"win":{"system":{"providerName":"Microsoft-Windows-Windows Defender","eventID":"5001","channel":"Microsoft-Windows-Windows Defender/Operational","computer":"LAB-WIN11","severityValue":"INFORMATION","systemTime":"2026-03-10T09:04:01.000Z"},"eventdata":{"productName":"Microsoft Defender Antivirus"}}}
```

### Cas 16 — Word lance cmd.exe (100200)
```
{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1","channel":"Microsoft-Windows-Sysmon/Operational","computer":"LAB-WIN11","severityValue":"INFORMATION","systemTime":"2026-03-10T09:06:00.000Z"},"eventdata":{"image":"C:\\Windows\\System32\\cmd.exe","parentImage":"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE","commandLine":"cmd.exe /c powershell -NoProfile -Command Write-Output lab","user":"LAB-WIN11\\mohamed"}}}
```

### Cas 17 — web shell (100190, 100191, 100192)
```
192.0.2.44 - - [10/Mar/2026:09:05:07 +0000] "POST /uploads/shell.php?cmd=whoami HTTP/1.1" 200 116 "-" "curl/7.88.1"
192.0.2.44 - - [10/Mar/2026:09:05:17 +0000] "GET /images/up.php?cmd=id HTTP/1.1" 200 89 "-" "curl/7.88.1"
192.0.2.44 - - [10/Mar/2026:09:05:29 +0000] "POST /wp-content/uploads/evil.php HTTP/1.1" 200 100 "-" "curl/7.88.1"
192.0.2.44 - - [10/Mar/2026:09:05:34 +0000] "GET /uploads/shell.php?cmd=Y2F0IC9ldGMvcGFzc3dk HTTP/1.1" 200 88 "-" "curl/7.88.1"
```

### Cas 18 — sosies bénins (négatif)
Coller les 10 lignes du fichier, par exemple :
```
10.10.0.5 - - [10/Mar/2026:08:25:00 +0000] "GET /search?q=evaluation HTTP/1.1" 200 1200 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
10.10.0.6 - - [10/Mar/2026:08:25:07 +0000] "GET /search?q=whoami+command+linux HTTP/1.1" 200 1201 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

---

## 3. Écarts connus entre les trois formats (à garder en tête pendant les tests)

| Détection | Moteur / Sigma | Wazuh |
|-----------|----------------|-------|
| Force brute RDP (02) | 8 échecs / 120 s | 60204 intégrée : 8 échecs / **240 s**, puis filtre 4625 type 3/10 |
| Succès après force brute (03, 12) | ≥ 8 échecs dans les 180 s qui précèdent le succès | succès dans les 180 s qui suivent l'alerte de force brute |
| Nouveau compte admin (04) | jointure 4720 `TargetSid` = 4732 `MemberSid` | corrélation par hôte (agent) seulement : limite du cas 8 |
| Scan de ports (08) | ports **distincts** | nombre de **connexions** |
