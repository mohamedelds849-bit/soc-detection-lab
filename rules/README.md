# Rules — Wazuh (XML) + Sigma (YAML)

Each of the 11 lab detections exists in two deployable formats here, plus a third
form consumed by the offline engine (`detector/rules/*.yaml`).

| Detection | Wazuh rule id | Sigma file | ATT&CK |
|-----------|---------------|-----------|--------|
| SSH brute force | 100110 | ssh_bruteforce.yml | T1110 |
| SSH success after brute force | 100111 | success_after_failures.yml | T1110 |
| RDP/Windows brute force | 100121 | rdp_bruteforce.yml | T1110 |
| New local admin | 100131 | new_local_admin.yml | T1136.001 / T1098 |
| PowerShell encoded command | 100140 | encoded_powershell.yml | T1059.001 |
| Scheduled task | 100150 / 100151 | scheduled_task.yml | T1053.005 |
| Event log cleared | 100160 | event_log_cleared.yml | T1685.005 (ex-T1070.001) |
| Port scan | 100171 | port_scan.yml | T1046 |
| Defender disabled | 100180 (command) / 100181 (EventID 5001) | defender_disabled.yml | T1685 (ex-T1562.001) |
| Web shell request | 100190 | web_shell.yml | T1505.003 |
| Office spawns shell | 100200 | office_spawns_shell.yml | T1204.002 |

## Validate syntax

**Wazuh XML** (well-formedness):
```bash
xmllint --noout wazuh/local_rules.xml
```

**On the Wazuh manager** (semantic test against real log lines):
```bash
sudo cp wazuh/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-logtest     # paste a log line, see which rule matches
sudo systemctl restart wazuh-manager
```

**Sigma YAML** (spec validation + conversion, verified with sigma-cli 3.1):
```bash
python -m pip install sigma-cli
sigma check sigma/                          # -> 0 errors, 0 condition errors, 0 issues
sigma plugin install splunk
sigma convert -t splunk --without-pipeline sigma/rdp_bruteforce.yml
```
Several files contain more than one YAML document (a base rule plus a Sigma v2
**correlation rule** that references it by `name`). `success_after_failures.yml`
chains onto the correlation defined in `ssh_bruteforce.yml`, so check/convert the
whole directory. There is no official pySigma backend for Wazuh, which is why the
Wazuh rules are hand-written. The Splunk backend does not support
`temporal_ordered` correlations (success-after-failures, new local admin).

> Note: the Wazuh parent SIDs (sshd `5760/5715`, Windows `60122/60109/60154/60228/
> 60117/63103`, Sysmon `61603`/`61605`, Defender `62152`, web `31100`) were checked
> against the Wazuh v4.9.2 ruleset source, not against a running manager. They can
> vary by Wazuh version — always confirm with `wazuh-logtest` after deployment.
> Wazuh's default regex engine (OSRegex) does not understand `(?i)` and similar
> PCRE syntax, so those fields declare `type="pcre2"`.
>
> ATT&CK: Sigma/engine use ATT&CK v19 IDs (T1685, T1685.005); the Wazuh rules keep
> T1562.001 / T1070.001 because Wazuh's bundled MITRE database predates v19.
