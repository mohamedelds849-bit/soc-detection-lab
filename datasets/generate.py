#!/usr/bin/env python3
"""
Synthetic log generator for the SOC Detection Lab.

Generates FICTIONAL, offline logs that contain benign noise plus the specific
attack patterns the detection rules are built to catch. Everything is
deterministic (fixed seed) so the dataset is reproducible and the pytest suite
is stable.

Outputs (written next to this script, in datasets/):
  - auth.log               Linux SSH/sudo auth log (text, syslog style)
  - windows_security.jsonl Windows Security channel events (JSON lines)
  - sysmon.jsonl           Sysmon operational events (JSON lines)
  - apache_access.log      Apache access log (combined-ish text)

IPs use RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) and RFC 1918 private ranges. Hosts/users are fictional.
NO real infrastructure is referenced. This is a defensive lab dataset only.
"""
from __future__ import annotations

import json
import os
import random
from datetime import datetime, timedelta, timezone

SEED = 1337
rng = random.Random(SEED)

HERE = os.path.dirname(os.path.abspath(__file__))

# Lab is anchored to a fixed date so timestamps are reproducible.
BASE = datetime(2026, 3, 10, 8, 0, 0, tzinfo=timezone.utc)

# --- Fictional environment -------------------------------------------------
LINUX_HOST = "lab-web01"
WIN_HOST = "LAB-WIN11"
BENIGN_USERS = ["mohamed", "sara", "yassine", "backup", "svc_report"]
# RFC 1918 internal clients (benign)
INTERNAL_IPS = ["10.10.0.5", "10.10.0.6", "10.10.0.12", "192.168.56.20"]
# RFC 5737 documentation ranges used as "external" actors
ATTACKER_SSH_IP = "203.0.113.66"     # SSH brute force source
ATTACKER_RDP_IP = "198.51.100.77"    # RDP brute force source
ATTACKER_SCAN_IP = "203.0.113.90"    # port scanner
ATTACKER_WEB_IP = "192.0.2.44"       # web shell probing
BENIGN_EXT_IPS = ["203.0.113.10", "198.51.100.25", "192.0.2.5"]

linux_lines: list[tuple[datetime, str]] = []
win_events: list[dict] = []
sysmon_events: list[dict] = []
apache_lines: list[tuple[datetime, str]] = []


def syslog_ts(dt: datetime) -> str:
    # e.g. "Mar 10 08:00:01"
    return dt.strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1) if dt.day < 10 else dt.strftime("%b %d %H:%M:%S")


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ---------------------------------------------------------------------------
# Benign baseline noise
# ---------------------------------------------------------------------------
def gen_benign_linux():
    """Normal SSH logins and sudo over the morning."""
    t = BASE
    for _ in range(40):
        t += timedelta(seconds=rng.randint(30, 240))
        user = rng.choice(BENIGN_USERS)
        ip = rng.choice(INTERNAL_IPS + BENIGN_EXT_IPS)
        port = rng.randint(40000, 60000)
        if rng.random() < 0.15:
            # occasional single failed password (fat finger) - must NOT trigger brute force
            linux_lines.append((t, f"{syslog_ts(t)} {LINUX_HOST} sshd[{rng.randint(1000,9999)}]: "
                                   f"Failed password for {user} from {ip} port {port} ssh2"))
        else:
            linux_lines.append((t, f"{syslog_ts(t)} {LINUX_HOST} sshd[{rng.randint(1000,9999)}]: "
                                   f"Accepted password for {user} from {ip} port {port} ssh2"))
            if rng.random() < 0.3:
                linux_lines.append((t + timedelta(seconds=2),
                                    f"{syslog_ts(t)} {LINUX_HOST} sudo: {user} : TTY=pts/0 ; "
                                    f"PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/apt update"))


def gen_benign_windows():
    """Normal interactive/network logons on the Windows host."""
    t = BASE
    for _ in range(35):
        t += timedelta(seconds=rng.randint(30, 300))
        user = rng.choice(BENIGN_USERS)
        ip = rng.choice(INTERNAL_IPS)
        logon_type = rng.choice([2, 3, 7])
        win_events.append({
            "@timestamp": iso(t), "host": WIN_HOST, "channel": "Security",
            "EventID": 4624, "TargetUserName": user, "LogonType": logon_type,
            "IpAddress": ip, "WorkstationName": WIN_HOST,
            # workgroup lab host: network logons are NTLM, interactive ones Negotiate
            "AuthenticationPackageName": "NTLM" if logon_type == 3 else "Negotiate",
        })
        if rng.random() < 0.1:
            # rare single failed logon - benign
            win_events.append({
                "@timestamp": iso(t + timedelta(seconds=5)), "host": WIN_HOST, "channel": "Security",
                "EventID": 4625, "TargetUserName": user, "LogonType": logon_type,
                "IpAddress": ip, "Status": "0xC000006D", "SubStatus": "0xC000006A",
            })


def gen_benign_sysmon():
    """Normal process creation + network connections."""
    t = BASE
    benign_cmds = [
        ("C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\explorer.exe", "cmd.exe /c dir"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "C:\\Windows\\explorer.exe", "powershell.exe Get-Process"),
        ("C:\\Program Files\\Git\\bin\\git.exe", "C:\\Windows\\explorer.exe", "git status"),
        ("C:\\Windows\\System32\\notepad.exe", "C:\\Windows\\explorer.exe", "notepad.exe notes.txt"),
    ]
    for _ in range(45):
        t += timedelta(seconds=rng.randint(20, 180))
        image, parent, cmd = rng.choice(benign_cmds)
        sysmon_events.append({
            "@timestamp": iso(t), "host": WIN_HOST, "channel": "Microsoft-Windows-Sysmon/Operational",
            "EventID": 1, "Image": image, "ParentImage": parent,
            "CommandLine": cmd, "User": f"{WIN_HOST}\\{rng.choice(BENIGN_USERS)}",
        })
    # benign outbound network connections (few distinct ports)
    for _ in range(20):
        t += timedelta(seconds=rng.randint(10, 120))
        sysmon_events.append({
            "@timestamp": iso(t), "host": WIN_HOST, "channel": "Microsoft-Windows-Sysmon/Operational",
            "EventID": 3, "Image": "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
            "SourceIp": rng.choice(INTERNAL_IPS), "DestinationIp": rng.choice(BENIGN_EXT_IPS),
            "DestinationPort": rng.choice([80, 443, 443, 443]), "Protocol": "tcp",
        })


def gen_benign_apache():
    """Normal web traffic to a small site."""
    t = BASE
    paths = ["/", "/index.html", "/about", "/blog/recipe-1", "/static/app.css",
             "/static/app.js", "/favicon.ico", "/contact"]
    uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    ]
    for _ in range(60):
        t += timedelta(seconds=rng.randint(5, 90))
        ip = rng.choice(INTERNAL_IPS + BENIGN_EXT_IPS)
        path = rng.choice(paths)
        status = rng.choice([200, 200, 200, 304, 404])
        size = rng.randint(200, 5000)
        apache_lines.append((t, f'{ip} - - [{t.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
                                f'"GET {path} HTTP/1.1" {status} {size} "-" "{rng.choice(uas)}"'))


def gen_benign_hard_negatives():
    """Benign look-alikes placed just UNDER or beside the detection logic, so the
    0-false-positive claim is tested against near misses, not only easy noise.
    Fixed timestamps and no rng draws: the rest of the dataset is unchanged."""
    def at(minutes, seconds=0):
        return BASE + timedelta(minutes=minutes, seconds=seconds)

    # SSH: 7 failures then a success (one below the threshold of 8)
    for i in range(7):
        t = at(10, i * 5)
        linux_lines.append((t, f"{syslog_ts(t)} {LINUX_HOST} sshd[4242]: "
                               f"Failed password for backup from 10.10.0.31 port {50100 + i} ssh2"))
    t = at(10, 40)
    linux_lines.append((t, f"{syslog_ts(t)} {LINUX_HOST} sshd[4243]: "
                           f"Accepted password for backup from 10.10.0.31 port 50110 ssh2"))

    # RDP: caps-lock user, 7 failures then a successful RDP logon (below 8)
    for i in range(7):
        win_events.append({
            "@timestamp": iso(at(12, i * 5)), "host": WIN_HOST, "channel": "Security",
            "EventID": 4625, "TargetUserName": "yassine", "LogonType": 10,
            "IpAddress": "10.10.0.30", "Status": "0xC000006D", "SubStatus": "0xC000006A",
        })
    win_events.append({
        "@timestamp": iso(at(12, 40)), "host": WIN_HOST, "channel": "Security",
        "EventID": 4624, "TargetUserName": "yassine", "LogonType": 10,
        "IpAddress": "10.10.0.30", "AuthenticationPackageName": "Negotiate",
    })
    # Network share: 3 failures then an NTLM type-3 success
    for i in range(3):
        win_events.append({
            "@timestamp": iso(at(14, i * 4)), "host": WIN_HOST, "channel": "Security",
            "EventID": 4625, "TargetUserName": "sara", "LogonType": 3,
            "IpAddress": "10.10.0.32", "Status": "0xC000006D", "SubStatus": "0xC000006A",
        })
    win_events.append({
        "@timestamp": iso(at(14, 20)), "host": WIN_HOST, "channel": "Security",
        "EventID": 4624, "TargetUserName": "sara", "LogonType": 3,
        "IpAddress": "10.10.0.32", "AuthenticationPackageName": "NTLM",
    })

    # IT change on the same host within 30s: create intern01 (NOT made admin)
    # and add the EXISTING account sara to Administrators. A host-based join
    # would wrongly call this "new account added to admins".
    win_events.append({
        "@timestamp": iso(at(20)), "host": WIN_HOST, "channel": "Security",
        "EventID": 4720, "TargetUserName": "intern01",
        "TargetSid": "S-1-5-21-1111111111-2222222222-3333333333-1006",
        "SubjectUserName": "administrator",
    })
    win_events.append({
        "@timestamp": iso(at(20, 30)), "host": WIN_HOST, "channel": "Security",
        "EventID": 4732, "TargetUserName": "Administrators", "TargetSid": "S-1-5-32-544",
        "MemberName": "-", "MemberSid": "S-1-5-21-1111111111-2222222222-3333333333-1002",
        "SubjectUserName": "administrator",
    })

    # Web: words and parameters that look like web shell tokens but are not
    benign_web = [
        ("10.10.0.5", "GET /search?q=evaluation HTTP/1.1", 200),
        ("10.10.0.6", "GET /search?q=whoami+command+linux HTTP/1.1", 200),
        ("10.10.0.12", "GET /blog/recipe-1?c=dark-mode HTTP/1.1", 200),
        ("192.168.56.20", "GET /product?id=42 HTTP/1.1", 200),
        ("10.10.0.5", "GET /docs/shell-scripting-basics HTTP/1.1", 200),
        ("10.10.0.6", "POST /contact HTTP/1.1", 200),
        ("10.10.0.12", "POST /wp-admin/async-upload.php HTTP/1.1", 200),
        ("192.168.56.20", "GET /wp-content/uploads/2026/03/photo.jpg HTTP/1.1", 200),
        ("10.10.0.5", "POST /uploads/avatar.png HTTP/1.1", 201),
    ]
    for i, (ip, req, status) in enumerate(benign_web):
        t = at(25, i * 7)
        apache_lines.append((t, f'{ip} - - [{t.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
                                f'"{req}" {status} {1200 + i} "-" '
                                f'"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"'))


# ---------------------------------------------------------------------------
# Attack patterns (each maps to one or more rules)
# ---------------------------------------------------------------------------
def atk_ssh_bruteforce():
    """T1110: SSH brute force, then a successful login (credential found)."""
    t = BASE + timedelta(minutes=35)
    victim = "mohamed"
    for i in range(14):
        t += timedelta(seconds=rng.randint(2, 6))
        port = rng.randint(40000, 60000)
        linux_lines.append((t, f"{syslog_ts(t)} {LINUX_HOST} sshd[{rng.randint(1000,9999)}]: "
                               f"Failed password for {victim} from {ATTACKER_SSH_IP} port {port} ssh2"))
    # successful login after the burst -> "success after many failures"
    t += timedelta(seconds=4)
    linux_lines.append((t, f"{syslog_ts(t)} {LINUX_HOST} sshd[{rng.randint(1000,9999)}]: "
                           f"Accepted password for {victim} from {ATTACKER_SSH_IP} port {rng.randint(40000,60000)} ssh2"))


def atk_rdp_bruteforce():
    """T1110: RDP brute force (Windows 4625, LogonType 10).

    Note: with NLA (Windows default) real failed RDP attempts are logged as
    LogonType 3, not 10 - the rules accept both."""
    t = BASE + timedelta(minutes=50)
    victim = "administrator"
    for i in range(12):
        t += timedelta(seconds=rng.randint(2, 7))
        win_events.append({
            "@timestamp": iso(t), "host": WIN_HOST, "channel": "Security",
            "EventID": 4625, "TargetUserName": victim, "LogonType": 10,
            "IpAddress": ATTACKER_RDP_IP, "Status": "0xC000006D", "SubStatus": "0xC000006A",
        })
    # successful RDP logon after the burst -> rule 12 rdp_success_after_bruteforce
    t += timedelta(seconds=5)
    win_events.append({
        "@timestamp": iso(t), "host": WIN_HOST, "channel": "Security",
        "EventID": 4624, "TargetUserName": victim, "LogonType": 10,
        "IpAddress": ATTACKER_RDP_IP, "AuthenticationPackageName": "Negotiate",
    })


def atk_new_local_admin():
    """T1136/T1098: create a local user then add it to Administrators."""
    t = BASE + timedelta(minutes=58)
    new_user = "svc_helper"
    new_sid = "S-1-5-21-1111111111-2222222222-3333333333-1005"   # fictional SID
    win_events.append({
        "@timestamp": iso(t), "host": WIN_HOST, "channel": "Security",
        "EventID": 4720, "TargetUserName": new_user, "TargetSid": new_sid,
        "SubjectUserName": "administrator",
    })
    t += timedelta(seconds=8)
    win_events.append({
        "@timestamp": iso(t), "host": WIN_HOST, "channel": "Security",
        # Real 4732 schema: TargetUserName/TargetSid = the GROUP, MemberSid = account added
        # (MemberName is "-" for local accounts).
        "EventID": 4732, "TargetUserName": "Administrators", "TargetSid": "S-1-5-32-544",
        "MemberName": "-", "MemberSid": new_sid, "SubjectUserName": "administrator",
    })


def atk_encoded_powershell():
    """T1059.001: PowerShell with -EncodedCommand."""
    t = BASE + timedelta(minutes=60)
    # harmless base64 of "Write-Output hello" (lab/defensive sample)
    b64 = "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABoAGUAbABsAG8A"
    sysmon_events.append({
        "@timestamp": iso(t), "host": WIN_HOST, "channel": "Microsoft-Windows-Sysmon/Operational",
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": f"powershell.exe -NoProfile -EncodedCommand {b64}",
        "User": f"{WIN_HOST}\\mohamed",
    })


def atk_scheduled_task():
    """T1053.005: scheduled task creation (Security 4698 + sysmon schtasks)."""
    t = BASE + timedelta(minutes=61)
    win_events.append({
        "@timestamp": iso(t), "host": WIN_HOST, "channel": "Security",
        "EventID": 4698, "TaskName": "\\Updater", "SubjectUserName": "mohamed",
    })
    sysmon_events.append({
        "@timestamp": iso(t + timedelta(seconds=1)), "host": WIN_HOST,
        "channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1,
        "Image": "C:\\Windows\\System32\\schtasks.exe",
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": 'schtasks.exe /create /tn "Updater" /tr "cmd.exe /c whoami" /sc minute /mo 5',
        "User": f"{WIN_HOST}\\mohamed",
    })


def atk_clear_event_log():
    """T1685.005 (ex-T1070.001): Windows event log cleared (Security 1102)."""
    t = BASE + timedelta(minutes=62)
    win_events.append({
        "@timestamp": iso(t), "host": WIN_HOST, "channel": "Security",
        "EventID": 1102, "SubjectUserName": "administrator",
        "Message": "The audit log was cleared.",
    })


def atk_port_scan():
    """T1046: port scan from a single source (many distinct dest ports)."""
    t = BASE + timedelta(minutes=63)
    for port in [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443]:
        t += timedelta(milliseconds=rng.randint(100, 800))
        sysmon_events.append({
            "@timestamp": iso(t), "host": WIN_HOST,
            "channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 3,
            "Image": "System", "SourceIp": ATTACKER_SCAN_IP,
            "DestinationIp": "10.10.0.12", "DestinationPort": port, "Protocol": "tcp",
        })


def atk_defender_disabled():
    """T1685 (ex-T1562.001): disable Microsoft Defender real-time monitoring."""
    t = BASE + timedelta(minutes=64)
    sysmon_events.append({
        "@timestamp": iso(t), "host": WIN_HOST,
        "channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1,
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true",
        "User": f"{WIN_HOST}\\administrator",
    })


def atk_web_shell():
    """T1505.003: web shell-like requests in the Apache log."""
    t = BASE + timedelta(minutes=65)
    reqs = [
        'POST /uploads/shell.php?cmd=whoami HTTP/1.1',
        'GET /images/up.php?cmd=id HTTP/1.1',
        'POST /wp-content/uploads/evil.php HTTP/1.1',
        # base64 command in a cmd= parameter ("cat /etc/passwd" - harmless lab string)
        'GET /uploads/shell.php?cmd=Y2F0IC9ldGMvcGFzc3dk HTTP/1.1',
    ]
    for r in reqs:
        t += timedelta(seconds=rng.randint(3, 12))
        status = 200
        apache_lines.append((t, f'{ATTACKER_WEB_IP} - - [{t.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
                                f'"{r}" {status} {rng.randint(10,120)} "-" "curl/7.88.1"'))


def atk_office_spawns_shell():
    """T1204: Office application spawning a command shell."""
    t = BASE + timedelta(minutes=66)
    sysmon_events.append({
        "@timestamp": iso(t), "host": WIN_HOST,
        "channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1,
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "CommandLine": "cmd.exe /c powershell -NoProfile -Command Write-Output lab",
        "User": f"{WIN_HOST}\\mohamed",
    })


# ---------------------------------------------------------------------------
def build(outdir: str, include_attacks: bool = True):
    """(Re)build the dataset into outdir. Used by main() and by the test suite
    (with include_attacks=False to produce a benign-only baseline)."""
    global rng, linux_lines, win_events, sysmon_events, apache_lines
    rng = random.Random(SEED)
    linux_lines = []
    win_events = []
    sysmon_events = []
    apache_lines = []

    gen_benign_linux()
    gen_benign_windows()
    gen_benign_sysmon()
    gen_benign_apache()
    gen_benign_hard_negatives()

    if include_attacks:
        atk_ssh_bruteforce()
        atk_rdp_bruteforce()
        atk_new_local_admin()
        atk_encoded_powershell()
        atk_scheduled_task()
        atk_clear_event_log()
        atk_port_scan()
        atk_defender_disabled()
        atk_web_shell()
        atk_office_spawns_shell()

    os.makedirs(outdir, exist_ok=True)
    _write_to(outdir)


def _write_to(outdir: str):
    linux_lines.sort(key=lambda x: x[0])
    apache_lines.sort(key=lambda x: x[0])
    win_events.sort(key=lambda e: e["@timestamp"])
    sysmon_events.sort(key=lambda e: e["@timestamp"])
    with open(os.path.join(outdir, "auth.log"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(line for _, line in linux_lines) + "\n")
    with open(os.path.join(outdir, "apache_access.log"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(line for _, line in apache_lines) + "\n")
    with open(os.path.join(outdir, "windows_security.jsonl"), "w", encoding="utf-8", newline="\n") as f:
        for e in win_events:
            f.write(json.dumps(e) + "\n")
    with open(os.path.join(outdir, "sysmon.jsonl"), "w", encoding="utf-8", newline="\n") as f:
        for e in sysmon_events:
            f.write(json.dumps(e) + "\n")


def main():
    build(HERE, include_attacks=True)
    print(f"Dataset written to: {HERE}")
    print(f"auth.log               : {len(linux_lines)} lines")
    print(f"apache_access.log      : {len(apache_lines)} lines")
    print(f"windows_security.jsonl : {len(win_events)} events")
    print(f"sysmon.jsonl           : {len(sysmon_events)} events")


if __name__ == "__main__":
    main()
