#!/usr/bin/env python3
"""
Build the wazuh-logtest replay files used by docs/WAZUH-VALIDATION.md.

The lab datasets use a simplified flat JSON schema. Wazuh's Windows rules
expect the eventchannel JSON layout ({"win": {"system": {...}, "eventdata":
{...}}} with camelCase field names), so this script converts the relevant
attack events (and a few benign near misses) into that layout, one file per
test case, lines in the order they must be pasted.

Text logs (auth.log, apache_access.log) are copied as-is: the Wazuh sshd and
web-accesslog decoders read them directly.

Output: datasets/wazuh_logtest/*.log  (deterministic; re-run after
python datasets/generate.py). Lab data only: fictional hosts, RFC 5737 IPs.
"""
from __future__ import annotations

import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DS = os.path.join(ROOT, "datasets")
OUT = os.path.join(DS, "wazuh_logtest")

_SKIP = {"@timestamp", "host", "channel", "EventID", "Message"}


def _camel(name: str) -> str:
    return name[0].lower() + name[1:]


def to_wazuh(rec: dict) -> str:
    """Flat lab record -> Wazuh eventchannel JSON line."""
    eid = int(rec["EventID"])
    channel = rec["channel"]
    if channel == "Security":
        provider = "Microsoft-Windows-Eventlog" if eid == 1102 else "Microsoft-Windows-Security-Auditing"
        severity = "AUDIT_FAILURE" if eid == 4625 else ("INFORMATION" if eid == 1102 else "AUDIT_SUCCESS")
    elif channel.startswith("Microsoft-Windows-Sysmon"):
        provider, severity = "Microsoft-Windows-Sysmon", "INFORMATION"
    else:
        provider, severity = "Microsoft-Windows-Windows Defender", "INFORMATION"
    system = {
        "providerName": provider, "eventID": str(eid), "channel": channel,
        "computer": rec.get("host", "LAB-WIN11"), "severityValue": severity,
        "systemTime": rec["@timestamp"],
    }
    eventdata = {_camel(k): str(v) for k, v in rec.items() if k not in _SKIP}
    return json.dumps({"win": {"system": system, "eventdata": eventdata}}, separators=(",", ":"))


def _jsonl(name: str) -> list[dict]:
    with open(os.path.join(DS, name), encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _lines(name: str) -> list[str]:
    with open(os.path.join(DS, name), encoding="utf-8") as f:
        return [line.rstrip("\n") for line in f if line.strip()]


def build() -> dict[str, list[str]]:
    win = _jsonl("windows_security.jsonl")
    sysmon = _jsonl("sysmon.jsonl")
    auth = _lines("auth.log")
    web = _lines("apache_access.log")

    cases: dict[str, list[str]] = {}

    # --- SSH (text) ---------------------------------------------------------
    ssh_fail = [l for l in auth if "Failed password" in l and "203.0.113.66" in l]
    ssh_ok = [l for l in auth if "Accepted password" in l and "203.0.113.66" in l]
    cases["01_ssh_bruteforce_then_success"] = ssh_fail[:8] + ssh_ok[:1]
    near = [l for l in auth if "10.10.0.31" in l]          # benign: 7 failures + success
    cases["02_ssh_7_failures_then_success_NEGATIVE"] = near

    # --- RDP / Windows logons ---------------------------------------------------
    rdp_fail = [e for e in win if e["EventID"] == 4625 and e["IpAddress"] == "198.51.100.77"]
    rdp_ok = [e for e in win if e["EventID"] == 4624 and e["IpAddress"] == "198.51.100.77"]
    cases["03_rdp_bruteforce_then_rdp_success"] = [to_wazuh(e) for e in rdp_fail[:8] + rdp_ok[:1]]

    def variant(e, **changes):
        d = dict(e)
        d.update(changes)
        return d
    ntlm_fail = [variant(e, LogonType=3) for e in rdp_fail[:8]]
    ntlm_ok = variant(rdp_ok[0], LogonType=3, AuthenticationPackageName="NTLM")
    cases["04_network_bruteforce_then_ntlm_success"] = [to_wazuh(e) for e in ntlm_fail + [ntlm_ok]]
    kerb_ok = variant(rdp_ok[0], LogonType=3, AuthenticationPackageName="Kerberos")
    cases["05_network_bruteforce_then_kerberos_success_NEGATIVE"] = [to_wazuh(e) for e in ntlm_fail + [kerb_ok]]
    near = [e for e in win if e.get("IpAddress") == "10.10.0.30"]   # benign: 7 failures + RDP success
    cases["06_rdp_7_failures_then_success_NEGATIVE"] = [to_wazuh(e) for e in near]

    # --- account creation + Administrators -------------------------------------
    sid = "S-1-5-21-1111111111-2222222222-3333333333-1005"
    cases["07_new_account_added_to_admins"] = [
        to_wazuh(e) for e in win
        if (e["EventID"] == 4720 and e.get("TargetSid") == sid)
        or (e["EventID"] == 4732 and e.get("MemberSid") == sid)]
    cases["08_unrelated_account_added_to_admins_KNOWN_LIMITATION"] = [
        to_wazuh(e) for e in win
        if e["EventID"] in (4720, 4732) and e["@timestamp"].startswith("2026-03-10T08:20")]

    # --- single events ------------------------------------------------------------
    def first(events, pred):
        return next(e for e in events if pred(e))
    cases["09_encoded_powershell"] = [to_wazuh(first(sysmon, lambda e: "-EncodedCommand" in e.get("CommandLine", "")))]
    cases["10_scheduled_task_4698"] = [to_wazuh(first(win, lambda e: e["EventID"] == 4698))]
    cases["11_scheduled_task_schtasks"] = [to_wazuh(first(sysmon, lambda e: "schtasks" in e.get("CommandLine", "")))]
    cases["12_security_log_cleared"] = [to_wazuh(first(win, lambda e: e["EventID"] == 1102))]
    scan = [e for e in sysmon if e["EventID"] == 3 and e.get("SourceIp") == "203.0.113.90"]
    cases["13_port_scan_15_connections"] = [to_wazuh(e) for e in scan[:15]]
    cases["14_defender_disable_command"] = [to_wazuh(first(sysmon, lambda e: "DisableRealtimeMonitoring" in e.get("CommandLine", "")))]
    defender_5001 = {"@timestamp": "2026-03-10T09:04:01.000Z", "host": "LAB-WIN11",
                     "channel": "Microsoft-Windows-Windows Defender/Operational", "EventID": 5001,
                     "ProductName": "Microsoft Defender Antivirus"}
    cases["15_defender_5001"] = [to_wazuh(defender_5001)]
    cases["16_office_spawns_shell"] = [to_wazuh(first(sysmon, lambda e: "WINWORD" in e.get("ParentImage", "")))]

    # --- web (text) -----------------------------------------------------------------
    cases["17_web_shell_requests"] = [l for l in web if l.startswith("192.0.2.44 ")]
    cases["18_web_lookalikes_NEGATIVE"] = [l for l in web if "[10/Mar/2026:08:25:" in l]
    return cases


def main():
    os.makedirs(OUT, exist_ok=True)
    cases = build()
    for name, lines in cases.items():
        assert lines, f"empty case {name}"
        with open(os.path.join(OUT, name + ".log"), "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")
    print(f"{len(cases)} wazuh-logtest cases written to {OUT}")


if __name__ == "__main__":
    main()
