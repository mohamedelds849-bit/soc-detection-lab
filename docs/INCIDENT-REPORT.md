# Rapport d'incident — Compromission par force brute puis création d'un compte administrateur

> **AVERTISSEMENT — EXERCICE DE LAB.** Ce rapport est rédigé à partir de
> **données synthétiques** générées par `datasets/generate.py` (seed fixe). Les
> hôtes, comptes et adresses IP sont **fictifs** (plages RFC 5737 / RFC 1918).
> Aucun système réel n'est concerné. Le document suit volontairement le format
> d'un vrai rapport d'incident pour l'exercice.

- **Référence incident :** LAB-IR-2026-001
- **Analyste :** Mohamed Elansari (élève ingénieur, rôle d'analyste SOC tenu pour l'exercice)
- **Date de l'analyse :** 2026-03-10
- **Classification :** Lab / Confidentiel (exercice)
- **Gravité :** Élevée (compromission de compte + persistance + évasion de défense)

---

## 1. Résumé exécutif

Le 10 mars 2026, le moteur de détection du lab a identifié une **attaque par
force brute SSH réussie** sur l'hôte Linux `lab-web01`, suivie, sur l'hôte Windows
`LAB-WIN11`, de la **création d'un compte local ajouté au groupe Administrateurs**,
puis d'une série d'actions de **persistance** et d'**évasion de défense**
(tâche planifiée, PowerShell encodé, désactivation de Microsoft Defender,
effacement du journal de sécurité) et d'une **activité réseau de scan** et de
**web shell**. L'ensemble constitue un scénario cohérent d'intrusion allant de
l'accès initial à l'ancrage durable sur le parc.

**Impact (lab) :** accès non autorisé à un compte utilisateur, obtention de
privilèges administrateur, altération des journaux. **Aucune donnée réelle** n'est
en jeu (exercice).

---

## 2. Chronologie (UTC)

| Heure | Hôte | Évènement | Détection (ATT&CK) |
|-------|------|-----------|--------------------|
| 08:35:06 – 08:35:34 | lab-web01 | 14 échecs d'authentification SSH pour `mohamed` depuis `203.0.113.66` | SSH brute force (T1110) |
| 08:36:00 | lab-web01 | **Connexion SSH réussie** pour `mohamed` depuis `203.0.113.66` | Succès après échecs multiples (T1110) |
| 08:50:05 – 08:50:54 | LAB-WIN11 | 12 échecs de connexion RDP (`administrator`) depuis `198.51.100.77` | RDP brute force (T1110) |
| 08:50:59 | LAB-WIN11 | **Connexion RDP réussie** (4624, LogonType 10) pour `administrator` depuis `198.51.100.77` | **Aucune règle** — trouvé en investigation (voir §9) |
| 08:58:00 | LAB-WIN11 | Création du compte local `svc_helper` (4720) | Nouveau compte (T1136.001) |
| 08:58:08 | LAB-WIN11 | `svc_helper` ajouté au groupe **Administrators** (4732) | Compte admin créé (T1098) |
| 09:00:00 | LAB-WIN11 | PowerShell `-EncodedCommand` | PowerShell encodé (T1059.001) |
| 09:01:00 | LAB-WIN11 | Tâche planifiée `\Updater` créée (4698 + schtasks.exe) | Tâche planifiée (T1053.005) |
| 09:02:00 | LAB-WIN11 | **Journal de sécurité effacé** (1102) | Effacement de journaux (T1685.005, ex-T1070.001) |
| 09:03:00 – 09:03:10 | LAB-WIN11 | 21 ports distincts contactés depuis `203.0.113.90` | Scan de ports (T1046) |
| 09:04:00 | LAB-WIN11 | `Set-MpPreference -DisableRealtimeMonitoring $true` | Defender désactivé (T1685, ex-T1562.001) |
| 09:05:07 – 09:05:29 | lab-web01 | Requêtes web type web shell depuis `192.0.2.44` | Web shell (T1505.003) |
| 09:06:00 | LAB-WIN11 | WINWORD.EXE lance `cmd.exe` → PowerShell | Office lance un shell (T1204.002) |

---

## 3. Indicateurs de compromission (IOC)

> Fictifs, à des fins d'exercice uniquement.

**Adresses IP (plages de documentation RFC 5737 / privées)**
- `203.0.113.66` — source de la force brute SSH + connexion réussie
- `198.51.100.77` — source de la force brute RDP **puis connexion RDP réussie** sur `administrator`
- `203.0.113.90` — source du scan de ports
- `192.0.2.44` — source des requêtes web shell

**Comptes**
- `svc_helper` — compte local créé et élevé en administrateur (persistance)

**Artefacts hôte**
- Tâche planifiée : `\Updater` (`schtasks /create /tn "Updater" /tr "cmd.exe /c whoami" /sc minute /mo 5`)
- Commande : `powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABoAGUAbABsAG8A`
  (décodée : `Write-Output hello` — charge inoffensive de lab)
- Commande : `Set-MpPreference -DisableRealtimeMonitoring $true`
- EventID 1102 (journal de sécurité vidé) sur `LAB-WIN11`

**URL web shell**
- `POST /uploads/shell.php?cmd=whoami`
- `GET /images/up.php?cmd=id`
- `POST /wp-content/uploads/evil.php`

---

## 4. Portée (scope)

- **Hôtes concernés :** `lab-web01` (Linux, accès initial), `LAB-WIN11` (Windows,
  persistance + évasion).
- **Comptes concernés :** `mohamed` (compromis par force brute SSH),
  `administrator` (**compromis** : connexion RDP réussie à 08:50:59 après 12
  échecs — c'est ce compte qui crée `svc_helper` 7 minutes plus tard),
  `svc_helper` (créé par l'attaquant).
- **Vecteur d'entrée :** authentification par mot de passe exposée (SSH) sans
  limitation de débit / verrouillage, et RDP joignable.
- **Pas d'exfiltration observée** dans les données du lab ; l'activité se limite à
  l'accès, la persistance et l'évasion.

---

## 5. Confinement (containment)

Actions immédiates recommandées :
1. **Bloquer** les IP sources au pare-feu : `203.0.113.66`, `198.51.100.77`,
   `203.0.113.90`, `192.0.2.44`.
2. **Isoler** `LAB-WIN11` du réseau (persistance + Defender désactivé).
3. **Désactiver** immédiatement le compte `svc_helper` ; **réinitialiser** les
   mots de passe de `mohamed` et `administrator` (tous deux compromis).
4. **Préserver les preuves** avant éradication : export des journaux depuis
   Wazuh, image mémoire/disque de `LAB-WIN11` si possible.
5. **Couper** l'accès SSH/RDP depuis l'extérieur en attendant le durcissement.

---

## 6. Éradication (eradication)

1. **Supprimer** le compte `svc_helper` et le retirer du groupe Administrators.
2. **Supprimer** la tâche planifiée `\Updater`.
3. **Réactiver** Microsoft Defender (`Set-MpPreference -DisableRealtimeMonitoring $false`)
   et lancer une analyse complète.
4. **Rechercher** et supprimer tout fichier `.php` non autorisé dans la racine web
   (`shell.php`, `up.php`, `evil.php`, répertoire `/uploads/`).
5. **Vérifier** l'absence d'autres mécanismes de persistance (services, clés Run,
   autres tâches, comptes).

---

## 7. Récupération (recovery)

1. Réinitialiser les mots de passe des comptes concernés + comptes à privilèges.
2. Restaurer le contenu web à partir d'une sauvegarde saine.
3. Remettre `LAB-WIN11` en production seulement après validation (journaux propres,
   Defender actif, pas de persistance résiduelle).
4. Renforcer la surveillance (règles du lab déjà en place) pendant une période
   d'observation.

---

## 8. Leçons apprises & recommandations

- **Exposer le moins possible SSH/RDP :** restreindre par VPN / liste d'autorisation
  d'IP ; désactiver l'authentification par mot de passe SSH au profit de clés.
- **Verrouillage de compte / limitation de débit :** `fail2ban` côté Linux,
  stratégie de verrouillage + NLA côté RDP.
- **MFA** sur les accès distants et comptes à privilèges.
- **Protéger les journaux :** transfert immédiat vers le SIEM (les journaux locaux
  ont été effacés — la centralisation Wazuh aurait préservé la preuve).
- **Alerter sur la désactivation de l'EDR/AV :** une désactivation de Defender doit
  être une alerte critique (c'est déjà le cas, règle T1685 / ex-T1562.001). Vérifier
  aussi si la commande a réellement abouti (Defender EventID 5001,
  `Get-MpComputerStatus`) : avec Tamper Protection elle peut avoir été bloquée.
- **Combler l'angle mort « succès RDP après force brute » :** ajouter une règle
  séquence 4625×N → 4624 (LogonType 3/10) même IP, comme pour SSH.
- **Principe du moindre privilège :** surveiller toute création de compte admin
  (déjà couvert, T1098/T1136).

---

## 9. Couverture de détection

Les 11 détections du lab se sont déclenchées sur leur étape respective (voir
`reports/triage.html`). **Une étape clé n'est couverte par aucune règle :** la
connexion RDP réussie de `198.51.100.77` sur `administrator` (4624 LogonType 10,
08:50:59), juste après la force brute. C'est très probablement le vrai vecteur
d'accès à `LAB-WIN11` (la force brute SSH visait l'hôte Linux) ; elle a été
retrouvée en investigation en pivotant sur l'IP source de l'alerte RDP. La règle
« succès après échecs » n'existe aujourd'hui que pour SSH — c'est le premier
point d'amélioration de la couverture.

Remarque de méthode : l'ordre des évènements (Office → shell à 09:06, *après* la
désactivation de Defender) est celui du jeu de données synthétique ; dans un
scénario réel, un document piégé (T1204.002) serait plutôt un vecteur d'accès
initial et devrait être analysé comme une seconde chaîne possible.
