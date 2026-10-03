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
| Event log cleared | 100160 | event_log_cleared.yml | T1070.001 |
| Port scan | 100171 | port_scan.yml | T1046 |
| Defender disabled | 100180 | defender_disabled.yml | T1562.001 |
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

**Sigma YAML** (parse + optional convert):
```bash
python -c "import glob,yaml; [yaml.safe_load(open(f,encoding='utf-8')) for f in glob.glob('sigma/*.yml')]; print('OK')"
# optional, with sigma-cli installed:
# sigma check sigma/
# sigma convert -t wazuh sigma/ssh_bruteforce.yml
```

> Note: the Wazuh rules reference standard decoder/parent SIDs (sshd `5710/5715`,
> Windows eventchannel `60000`, Sysmon `61603`/`61605`, web `31100`). These can
> vary by Wazuh version — always confirm with `wazuh-logtest` after deployment.
