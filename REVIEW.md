# Security Review — SOC Detection Lab

**Reviewer role:** Security Reviewer (senior SOC / detection engineer + QA)
**Date:** 2026-10-03
**Scope:** `rules/wazuh/local_rules.xml`, `rules/sigma/*.yml`, `datasets/generate.py`,
`detector/`, `tests/`, `docs/SETUP.md`, `docs/INCIDENT-REPORT.md`,
`docs/ATTACK-SIMULATION.md`, `README.md`, `LEARN.md`.

## Verdict

| Item | Result |
|------|--------|
| TECHNICAL SCORE | **7/10** after fixes (about 5/10 as submitted) |
| EDUCATIONAL SCORE | **8/10** |
| SAFETY STATUS | **PASS** |
| CONSISTENCY STATUS | **PASS** (after the fixes below) |
| FINAL | **APPROVED**, with the remaining recommendations at the end |

This is a well-structured, honest student project. The offline engine is clean, the
docs are unusually thorough, and the safety framing is good. The original submission
had several real technical errors. The Sigma rules failed validation, the Wazuh regexes
would not have matched, the 4732 schema was wrong and two ATT&CK IDs were revoked. An
interviewer who knows Wazuh or Sigma would have found these quickly. They are fixed now.
The biggest remaining gap is that the Wazuh rules have never run on a real manager.

---

## 1. How it was verified

| Check | Method | Result |
|-------|--------|--------|
| Engine and tests | `python datasets/generate.py && python detector/run.py && python -m pytest -q` | 275 events, 14 alerts, 11/11 rules fire, 0 alerts on benign data. **31 passed** (30 plus 1 new regression test) |
| Determinism | Regenerated the dataset and checked `git diff` | Byte-identical (seed 1337) |
| Sigma | `sigma check` with sigma-cli 3.1 / pySigma, using the **live ATT&CK v19.2** data | Before: **11 errors** (non-UUID `id`). After the ID fix, 6 ATT&CK tag issues showed up. After all fixes: **0 errors, 0 condition errors, 0 issues** |
| Sigma conversion | `sigma convert -t splunk` and `-t eql` | Single-event, `event_count` and `value_count` rules convert to SPL. Splunk does not support `temporal_ordered`. The EQL output for the chained rule is malformed, which is a backend limitation |
| Wazuh | Compared parent SIDs and syntax with the **Wazuh v4.9.2 ruleset source** (0095, 0245, 0575, 0580, 0595, 0600, 0610, 0800) and checked XML well-formedness | Several issues, listed in §2.2. No live `wazuh-logtest` was available, so the rules are still unexecuted |
| Over-fitting | Fed 11 realistic variant events to the engine (scratch probe script) | See §2.4 |

---

## 2. Problems found

### 2.1 Sigma: invalid as submitted (FIXED)
1. **All 11 `id` values were not UUIDs** (for example `7a1e0c10-0009-4a00-9a09-defoff0000009`).
   `sigma check` rejected every rule.
2. **Deprecated aggregation syntax.** `selection | count() by src_ip >= 8` is the old
   Sigma v1 aggregation, which pySigma no longer supports. `failures | count() by src_ip >= 8 and success`
   was never valid Sigma. The README wrongly called this "modern correlation syntax".
   All four were rewritten as **Sigma v2 correlation rules**: `event_count` (SSH and RDP),
   `value_count` (port scan) and `temporal_ordered` (success-after-failures, chained on
   the SSH correlation).
3. **4732 used the wrong fields.** The rule used `GroupName: Administrators` and treated
   `TargetUserName` as the new user. In a real 4732 event, `TargetUserName`/`TargetSid`
   are the **group** and `MemberSid` is the account that was added. The rule now uses
   `TargetSid: S-1-5-32-544`, which also works on French Windows where the group is
   called "Administrateurs". It also gained a `temporal_ordered` correlation that joins
   4720 `TargetSid` with 4732 `MemberSid` through a correlation `alias`.
4. **Revoked ATT&CK IDs.** ATT&CK v19 (April 2026) revoked T1562.001 (now **T1685**) and
   T1070.001 (now **T1685.005**). It also split Defense Evasion into *Stealth* (TA0005)
   and *Defense Impairment* (TA0112). I confirmed both `revoked-by` relationships in the
   official STIX bundle.
5. Smaller fixes:
   - The scheduled-task rule mixed two log sources in one rule. It is now two documents.
   - `web_shell` looked for path patterns such as `shell.php` in `cs-uri-query`. Paths
     now use `cs-uri-stem`.
   - `port_scan` had a non-idiomatic logsource (`service: sysmon` together with `category`).
   - Dates were in `YYYY/MM/DD` format instead of ISO `YYYY-MM-DD`.

### 2.2 Wazuh: would not have worked as written (FIXED, not yet live-tested)
1. **PCRE syntax without `type="pcre2"`.** Wazuh's default regex engine (OSRegex) does
   not support `(?i)`, `?` or `(...)?`. As written, rules 100140, 100151, 100180, 100190
   and 100200 would not match as intended. `type="pcre2"` was added to every
   PCRE-style field, in the same style as Wazuh's own `0800-sysmon_id_1.xml`.
2. **`frequency="1"`** on 100111 and 100131 is not a valid correlation pattern. These
   rules now use `if_sid` + `if_matched_sid` + `timeframe` with no frequency, the same
   pattern as built-in rule 40112.
3. **Wrong SSH parent.** `5710` is "login attempt with a **non-existent** user". The
   dataset's `Failed password for mohamed` lines match **5760** (5716 → 5760), so 100110
   would never have counted them. The parent is now 5760.
4. **Generic parent `60000`.** Every Windows Security rule hung off the root rule.
   Wazuh first classifies these events under 60001 → 60103/60104 → specific rules, so
   the custom rules now attach to the specific built-in rule, checked in the 4.9.2
   source. That gives 60122 (4625), 60109 (4720), 60154 (Administrators group by SID),
   60228 (4698), and 60117 or 63103 (1102). 60154 also covers 4733 (member removed),
   so the `^4732$` filter stays.
5. Added **100181**, which matches Defender Operational **EventID 5001** under built-in
   rule 62152. It records that real-time protection actually turned off, while 100180
   only records the command-line attempt. With Tamper Protection on, the attempt is
   blocked and only 100180 fires.
6. ATT&CK IDs stay on T1562.001 / T1070.001 in Wazuh **on purpose**, because Wazuh's
   bundled MITRE database predates v19. This is documented.

### 2.3 Data and engine fidelity (FIXED)
- Dataset 4732 now follows the real schema (group in `Target*`, account in `MemberSid`),
  and 4720 now carries a `TargetSid`.
- Dataset 4625 had `Status: 0xC000006A`. It now has `Status 0xC000006D` and
  `SubStatus 0xC000006A`, which is the real wrong-password pair.
- The engine's scheduled-task rule matched any `schtasks.exe` run. It now requires
  `/create`, like the Sigma and Wazuh versions.
- PowerShell and Office rules now also cover `pwsh.exe`.

### 2.4 Over-fitting: an honest assessment
The headline result (11/11, 0 FP) is **real but partly self-fulfilling**:
- The benign baseline comes from the **same generator** as the attacks. It was written
  not to overlap with any rule: no software creating scheduled tasks, no admin
  encoded PowerShell, no vulnerability scanner. "0 FP" shows the rules are not
  trivially noisy. It does not show they are FP-free on real logs.
- Most tests only check "≥ 1 alert" or "0 alerts". They do not check entity, count or
  evidence.

Probe results against the engine:

| Probe | Result | Status |
|-------|--------|--------|
| `powershell -e <b64>` / `-ec` (the most common real forms) | **Missed** | **FIXED.** Regex is now `\s-(e\|ec\|en\|enc\|enco\|encodedcommand)\s` in all 3 formats, with a regression test that includes `-ExecutionPolicy` and `-Encoding` negatives |
| Benign installer `schtasks /create` | Fires | Expected for a medium-severity rule. Documented in the README |
| `/search?q=evaluation` | **Fires** (because the regex contains `eval`) | Open |
| Web shell names `up.php`, `evil.php` | Literal sample names from the dataset | **Over-fitted.** Open |
| 4720 for user A, then 4732 for an unrelated user B on the same host | **Fires** (engine groups by host) | Open. The Sigma rule now joins on SID |
| Slow brute force (30 failures, 1 every 20 s) / password spray (20 IPs × 1) | Missed | Open. A known limitation of simple thresholds |
| Office → `rundll32` | Missed | Open |
| RDP **success** after the brute force | No rule exists | Open. See §2.6 |

### 2.5 SETUP.md (FIXED)
- **systemd was only a footnote ("astuce"), shown after the install step.**
  `wazuh-install.sh` needs systemd, so the install fails without it. It is now a
  mandatory prerequisite with a `ps -p 1 -o comm=` check. The misleading
  "`service <name> start` without systemd" fallback was removed.
- `-i` was not explained. It skips the installer's hardware checks. Now documented.
- RAM: Wazuh's official sizing is 4 vCPU / 8 GB. `memory=5GB` is workable for a
  one-agent lab, but the doc now gives guidance for 8 GB and 16 GB hosts.
- Disk: about 9–11 GB is plausible for a **fresh** install. The doc now warns that
  indexes grow over time, that vulnerability detection (on by default since 4.8) can
  add several GB and can be disabled, and that `ext4.vhdx` does not shrink by itself.
  `wsl --manage … --set-sparse true` and `wsl --unregister` are given as remedies.
- Added the **Windows audit policy** section. **4698 is not logged by default**
  ("Other Object Access Events"). The commands use subcategory GUIDs because the
  names are translated on French Windows.
- Added a **Sysmon EID 3 caveat**: closed ports produce no EID 3, and the
  SwiftOnSecurity config filters EID 3.
- Added that the `.jsonl` files cannot be pasted into `wazuh-logtest`.
- Fixed the misleading "open Windows firewall 1514/1515" troubleshooting tip. The
  usual cause is that the WSL IP changed; `networkingMode=mirrored` is suggested.
- The uninstall steps were already correct: `wazuh-install.sh --uninstall`,
  `msiexec /x`, `Sysmon64 -u`, `wsl --unregister`.

### 2.6 Incident report (FIXED)
- **Analytical gap.** The dataset contains a **successful RDP logon** (4624, LogonType 10)
  from the brute-force IP 198.51.100.77 to `administrator` at 08:50:59. That same
  account creates `svc_helper` 7 minutes later. This is the likely entry point to
  LAB-WIN11, and the report left it out. The report also claimed the 11 detections
  "identified every step". It now includes this event, marks it as uncovered by any
  rule, adds `administrator` as a compromised account, and lists it as the first
  coverage gap to close.
- Added evidence preservation before eradication. Added a check that the Defender
  disable actually took effect (5001 / Tamper Protection). Added a note on how the
  Office → shell step is ordered in the timeline.
- Corrected two timeline times (RDP failures end at 08:50:54; the scan starts at 09:03:00).

### 2.7 ATTACK-SIMULATION.md: safety PASS (small fixes)
Every test is benign and targets only the author's own lab machine. Each one has
cleanup, macros are restricted to self-made documents, and there is no malware or
third-party target. Fixes:
- Removed `cmdkey /add`, which stored a credential and was never cleaned up.
- Added the French "Administrateurs" note.
- Corrected the 1102 test. Only clearing the **Security** log produces 1102; other logs
  produce System 104. The test now **exports the log first**.
- Added the Tamper Protection note, the NLA LogonType 3 note, the 4698 audit
  prerequisite, and the Sysmon EID 3 limitation for the scan test.

### 2.8 LEARN.md and CV line
The answers were correct overall. Added:
- The 4732 field semantics.
- The NLA failure-type trap and the 4625 Status/SubStatus codes.
- 1102 vs 104.
- The 4698 audit requirement.
- The ATT&CK v19 restructuring, which is likely to come up in a 2026 interview.
- An honest limitation in Q15.

CV line: it was mostly honest, because it already said "synthetic logs" and "Wazuh
deployment documented". It was tightened to "déclenchées" instead of "validées",
"base bénigne **synthétique**", `sigma check` validated, and 31 tests.

---

## 3. Fixes applied (complete list)

| File | Change |
|------|--------|
| `rules/sigma/*.yml` (all 11) | Real UUIDs; ISO dates; v2 correlation rules for SSH, RDP, port scan, success-after-failures and new-admin; 4732 by `TargetSid S-1-5-32-544` plus SID-alias correlation; scheduled task split into 2 rules; web shell split into `cs-uri-stem` / `cs-uri-query`; `pwsh.exe`; encoded-PS abbreviations; ATT&CK v19 tags (`attack.defense-impairment`, `t1685`, `t1685.005`); new Defender 5001 rule. Result: `sigma check` reports 0/0/0 |
| `rules/wazuh/local_rules.xml` | `type="pcre2"` on PCRE fields; SSH parent 5710 → 5760; removed `frequency="1"` (100111, 100131); Windows parents 60000 → 60122/60109/60154/60228/60117+63103; 4732 by SID; new 100181 (Defender 5001); `pwsh`; encoded-PS abbreviations; header documents the verified parent SIDs, built-in overlaps and ATT&CK version choice |
| `detector/rules/04,05,06,07,09,11` | 4732 by `TargetSid`; PowerShell image regex plus abbreviations; schtasks requires `/create`; v19 ATT&CK IDs with "ex-" notes; `pwsh` |
| `datasets/generate.py` (+ regenerated `windows_security.jsonl`) | Real 4732/4720 schema (TargetSid/MemberSid); 4625 Status/SubStatus; NLA note. Event counts unchanged |
| `tests/test_detector.py` | New `test_encoded_powershell_realistic_variants` (5 positives, 2 benign look-alikes) |
| `reports/alerts.json`, `reports/triage.html` | Regenerated (still 275 events / 14 alerts) |
| `README.md` | v19 ATT&CK IDs plus version note; 31 tests (EN and FR); rewrote the Wazuh/Sigma limitation bullets (they were inaccurate); added an honest note on the 0-FP methodology |
| `rules/README.md` | Table IDs and 100181; real `sigma check` / `sigma convert -t splunk` workflow (`-t wazuh` does not exist); multi-document and chaining notes; pcre2 and ATT&CK notes |
| `docs/SETUP.md` | systemd as a mandatory prerequisite; `-i` explained; RAM/disk realism; vhdx reclaim; audit policy (4698) with GUIDs; Defender channel; Sysmon EID 3 caveat; logtest guidance; agent troubleshooting; mirrored networking |
| `docs/ATTACK-SIMULATION.md` | Removed `cmdkey`; French group name; 1102 correctness plus backup; Tamper Protection; NLA; 4698 prerequisite; EID 3 limitation; v19 IDs |
| `docs/INCIDENT-REPORT.md` | Added the RDP-success event and the coverage gap; `administrator` marked as compromised; evidence preservation; Defender verification; timeline times; v19 IDs |
| `LEARN.md` | 4732 fields, NLA/LogonType, Status codes, 1102 vs 104, 4698 audit, ATT&CK v19, Q15 limitation, CV line |

---

## 4. Recommendations (remaining, not done by the reviewer)

1. **Deploy Wazuh and run every rule through `wazuh-logtest`.** This is the biggest
   credibility gap, because the Wazuh rules have never run. Capture screenshots of each
   alert in the dashboard and add them to the README. Watch for built-in siblings that
   win the match first, such as 92008 (Defender via PowerShell), 92047/92050 (Office
   parent) and 92057 (encoded PowerShell). If one wins, attach the custom rule as a
   child of that built-in rule.
2. **Add "RDP success after brute force":** 4625×8 → 4624 (LogonType 3/10), same IP,
   in all three formats. The incident report already depends on it.
3. **Remove the dataset-specific web-shell tokens** (`up.php`, `evil.php`) and the
   FP-prone `eval`. Replace them with behaviour: a POST to a `.php` file under upload
   paths, status 200, a rare user agent (`curl`, `python-requests`), or a first-seen URI.
4. **Port scan:** use a better data source (WFP 5156/5157, firewall logs, Zeek). The
   Wazuh rule counts *connections*, not *distinct ports*. Test Wazuh `<different_field>`
   in the installed version before adopting it.
5. **New local admin in the engine:** join on SID (4720 `TargetSid` = 4732 `MemberSid`),
   not on host. The current engine fires for unrelated accounts.
6. **Make the benign baseline realistic and measure an FP rate:** add installer
   scheduled tasks, SCCM/Intune encoded PowerShell, an authorised scanner, and users
   who mistype a password 3–5 times. Report precision/recall instead of 0/0.
7. **Strengthen the tests:** assert the alert entity (for example
   `src_ip=203.0.113.66`), the hit count and the time, not only "≥ 1 alert". Add
   boundary tests (7 vs 8 failures, 14 vs 15 ports) for every threshold rule.
8. **Broaden coverage:** password spraying (many users from one IP, or one user from
   many IPs), slow brute force (a longer window), Office → `rundll32/regsvr32/mshta`,
   PowerShell 4104 script-block rules.
9. **Sigma field mapping:** the SSH rules use a free-text `message` field and the
   non-standard `src_ip`. Add a small pySigma processing pipeline, or note the mapping
   that a real backend would need.

### Interview preparation
Be ready to explain:
- Why 4625 failures are LogonType 3 when NLA is on.
- Why 4698 needs an audit policy.
- The 4732 Target/Member field semantics.
- The ATT&CK v19 Defense Evasion split.
- Why "0 FP on my own synthetic baseline" is a weak claim, and how you would measure
  FP on real data. Saying this unprompted is a strong signal of seniority.

---

## Revision round 1 (2026-10-03) — answer to the Director audit

Scope: mandatory revisions 2 to 5 of `../DIRECTOR-AUDIT.md` (soc-detection-lab).
Revision 1 (deploy Wazuh, replay in `wazuh-logtest`, screenshots) is the
student's own work and was **not** attempted; it is now prepared by
`docs/WAZUH-VALIDATION.md`.

### What changed

| Revision | Change | Files |
|----------|--------|-------|
| 1 (prep only) | New per-rule checklist: line(s) to paste, expected rule id/level, masking risk, result and screenshot columns, 19 cases including negatives and the known 100131 limitation. New generator `tools/make_wazuh_samples.py` writes the replay lines in Wazuh eventchannel JSON (`datasets/wazuh_logtest/*.log`). Documents that Windows JSON does not reach rule 60000 in `wazuh-logtest` on a stock manager, and the temporary workaround used by Wazuh's own `runtests.py`. README now lists all 19 Wazuh rule IDs as untested | `docs/WAZUH-VALIDATION.md`, `tools/`, `datasets/wazuh_logtest/`, `README.md`, `docs/SETUP.md` |
| 2 | **Detection 12 "remote logon success after brute force"** (T1110 + T1078): 8+ 4625 (type 3/10) then 4624 type 10, or type 3 with NTLM, same source IP, 180 s. Engine YAML (sequence), Sigma (`temporal_ordered` chained on `lab_win_failed_logon_burst`, new UUIDs, `sigma check` clean), Wazuh 100122 / 100123 (children of 60106, `if_matched_sid 100121`, `same_field win.eventdata.ipAddress`, level 13). Incident report: the 08:50:59 RDP logon is now detected (timeline, §8, §9) | `detector/rules/12_*.yaml`, `rules/sigma/rdp_success_after_bruteforce.yml`, `rules/wazuh/local_rules.xml`, `docs/INCIDENT-REPORT.md` |
| 3 | Engine rule 04 now joins **4720 `TargetSid` = 4732 `MemberSid`** (new per-step `alias`, same idea as the Sigma correlation alias). Negative tests: unrelated account B added after A was created, other group (S-1-5-32-555), wrong order, 120 s vs 121 s | `detector/engine.py`, `detector/rules/04_new_local_admin.yaml`, tests |
| 4 | Web shell rule rewritten on **behaviour**: OS command (`whoami`, `id`, `uname`, `net user`, `cat /etc/passwd`, ...) as the value of a command-style parameter; PHP code-exec call (`eval(`, `system(`, `base64_decode(`) or long base64 value in a command parameter; successful POST (2xx) to `.php/.phtml/.phar` under an upload-type directory. `up.php`, `evil.php`, `shell.php` and bare `eval` removed. Same logic in Sigma and Wazuh (100190 / 100191 / 100192). `/search?q=evaluation` and 14 other look-alikes are negative tests, run against the engine, the Sigma regexes and the Wazuh regexes | `detector/rules/10_web_shell.yaml`, `rules/sigma/web_shell.yml`, `rules/wazuh/local_rules.xml`, tests |
| 5 | Tests: 31 -> **145**. Every alert on the attack dataset is checked for entity, number of alerts and hit count. Threshold edges with the thresholds read from the YAML (7 vs 8 SSH and RDP failures, 14 vs 15 distinct ports, 14 distinct + repeats), window edges (8th failure at 120 s vs 121 s, success at 180 s vs 181 s, port scan spread over 60 s), ordering (success before failures, 4732 before 4720, 3-step order), grouping (split IPs, other IP, other SID), NTLM vs Kerberos, logon type 2. Cross-format checks (Wazuh XML structure, Sigma UUIDs and chaining), determinism (build twice + compare with the committed dataset), replay files and checklist kept in sync | `tests/test_detector.py` |

### Engine changes needed for the above
- Match blocks accept nested `all`/`any` (needed for "type 10 OR (type 3 AND NTLM)").
- `sequence` is now evaluated by **look-back from the final event**: the earlier
  steps must be satisfied, in order, inside the window that ends at that event.
  The old forward implementation anchored the window on the first failure, so
  2 stale failures followed by a fresh burst + success could be missed (new test
  `test_ssh_success_after_failures_old_failures_do_not_block`).
- Threshold / distinct alerts now report every event of the triggering window
  (SSH 14, RDP 12, port scan 21 distinct ports) instead of always reporting
  exactly the threshold value.

### Dataset
- Still deterministic (seed 1337). New benign **near misses** with fixed
  timestamps and no RNG draw, so every pre-existing event is byte-identical: 7 SSH
  failures + success, 7 RDP failures + RDP logon, 3 failures + NTLM logon, an IT
  change (intern01 created, existing account sara added to Administrators), 9 web
  look-alikes. One attack request added (base64 command). 4624 events carry
  `AuthenticationPackageName`.
- Result: 307 events, 16 alerts, 12/12 detections, **0 FP on 246 benign events**.
  Honest note: the previous rules 04 and 10 raise **3 FPs** on the new near misses
  (host-based admin join; `eval` / `whoami` in a search parameter). The baseline is
  still written by the rule author, so this is a robustness check, not an FP rate.

### Wazuh findings from reading the 4.9.2 source (all still to be confirmed live)
1. **The original 100110 and 100121 would most likely never have fired.** Sibling
   rules are tried by descending level, then load order (`rules_list.c`,
   `_OS_AddRule`). Built-in 5763 (SSH, level 10, 8/120 s, same parent 5760) and
   60204 (Windows, level 10, 8/240 s, child of every `authentication_failed` rule)
   match on the same event and are loaded first. Both custom rules are now
   **children** of those built-ins (enrichment); the helper 100120 was removed.
2. 100111 (level 12) tied with built-in 40112 (level 12, also a child of 5715)
   and lost the tie; it is now level 13, like 100122/100123.
3. `frequency="8"` does fire on the 8th event (the loader subtracts 2), and
   correlation is per agent and uses reception time (`eventinfo.c`). The
   checklist tells the student to paste one case within the timeframe and to
   restart `wazuh-logtest` between cases.
4. Pasted eventchannel JSON is decoded as `json`, so rule 60000
   (`decoded_as windows_eventchannel`) does not match in `wazuh-logtest`; Wazuh's
   own `runtests.py` patches rule 60000 for its tests. This is why SETUP.md said
   the `.jsonl` files could not be pasted; the checklist now gives both the
   end-to-end method and the temporary patch (with backup and restore).
5. 100131 still cannot join on the SID in Wazuh (`same_field` compares one field
   name). It is documented as a known limitation and is checklist case 8.

### Verification
| Check | Result |
|-------|--------|
| `python datasets/generate.py && python tools/make_wazuh_samples.py && python detector/run.py` | 307 events, 16 alerts, 12/12 rules fire; benign build: 246 events, 0 alerts |
| `python -m pytest -q` | **145 passed** |
| `sigma check rules/sigma` (sigma-cli 3.1.0, pySigma 1.5.1) | 0 errors, 0 condition errors, 0 issues (21 documents); correlation references resolve |
| `local_rules.xml` | well-formed; 19 unique rule IDs; every `(?i)` field has `type="pcre2"` (tested) |
| Mutation check | old rule 04 fires on the unrelated-account test; old rule 10 fails 8 negatives and misses 3 positives; old engine fails 38 tests |

### Not done
- Revision 1 itself: no Wazuh deployment, no `wazuh-logtest` run, no screenshots
  (student's job; checklist ready).
- No pySigma processing pipeline for `src_ip` / `message` (optional revision).
- Password spraying, slow brute force, Office -> rundll32/regsvr32, 4104 rules
  (optional revisions).

---

## CI validation (2026-10-03) — correction of an earlier claim

The Wazuh rules are now executed on every relevant push by
`.github/workflows/wazuh-validation.yml`: real `wazuh/wazuh-manager:4.9.2` in
Docker, `local_rules.xml` validated with `wazuh-analysisd -t`, the 18 files of
`datasets/wazuh_logtest/` replayed with `lab/run_all.sh`, and
`lab/check_results.py` failing the build if the final rule id of any line differs
from `lab/expected.json`.

| Run | Result | Root cause | Fix |
|-----|--------|------------|-----|
| 1 | failed before testing | readiness-check bug in `lab/start.sh` | robust readiness check + diagnostics |
| 2 | SSH + web OK; every Windows event -> rule 1002; 100192 never fired | the rule 60000 test patch must also remove `<category>ossec</category>` (as `ruleset/testing/runtests.py` does); built-in 31108 (level 0) captured the POST without query string | runtests-style patch; 100192 `if_sid 31100,31108` |
| 3 | 15/18 (KO 03, 04, 13) | built-in 92653 captured the RDP success before 100122; 92652 the NTLM success before 100123; 2 of 15 Sysmon EID 3 ended on 92106 via 92105, so the 100170 counter reached 13 | 100122 `if_sid 60106, 92653`; 100123 `if_sid 60106, 92652`; 100170 `if_sid 61605, 92101…92110` |
| 4 | **18/18** | — | — |

**Correction.** The "Wazuh findings from reading the 4.9.2 source" above (point 1,
and the "Sibling order" note in `rules/README.md`) state that sibling child rules
are tried by descending level. In practice this did **not** hold: built-in
children loaded first, with a lower level, captured events before the custom
higher-level siblings (92653, 92652, 92106, 31108). Raising the level (100111,
100122, 100123 at 13) was not enough; the robust fix is to attach custom rules
under the built-in child rules that may capture the event. The text above is kept
as written for history; this section supersedes it.

Case 08 (unrelated account added to Administrators) fires 100131 as documented:
known limitation, expected behaviour.

**Still not done:** case 19, end to end with a real Windows agent + Sysmon and a
real RDP logon. The CI proves rule logic on synthetic lines replayed in
`wazuh-logtest` (with a CI-only patch of rule 60000), not live monitoring.

