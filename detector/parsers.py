#!/usr/bin/env python3
"""
Parsers that normalize the four synthetic log formats into a single flat event
dict. Every normalized event has at least:

  ts       : float epoch seconds (for time-window correlation)
  source   : one of linux_auth | win_security | sysmon | apache
  raw      : the original log line / record (for triage display)

plus source-specific fields (src_ip, user, event_id, command_line, ...).
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

# Linux syslog has no year; the lab is anchored to 2026.
_SYSLOG_YEAR = 2026

_SSH_FAIL = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_SSH_OK = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_SUDO = re.compile(r"sudo:\s+(?P<user>\S+)\s*:.*COMMAND=(?P<cmd>.+)$")
_SYSLOG_HEAD = re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<rest>.*)$")

_APACHE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"')

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def _epoch(dt: datetime) -> float:
    return dt.replace(tzinfo=timezone.utc).timestamp() if dt.tzinfo is None else dt.timestamp()


def parse_linux_auth(path: str) -> list[dict]:
    events: list[dict] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            head = _SYSLOG_HEAD.match(line)
            if not head:
                continue
            mon = _MONTHS.get(head.group("mon"), 1)
            day = int(head.group("day"))
            hh, mm, ss = (int(x) for x in head.group("time").split(":"))
            dt = datetime(_SYSLOG_YEAR, mon, day, hh, mm, ss, tzinfo=timezone.utc)
            ts = _epoch(dt)
            host = head.group("host")
            rest = head.group("rest")

            m = _SSH_FAIL.search(rest)
            if m:
                events.append({"ts": ts, "source": "linux_auth", "event_type": "ssh_auth_failure",
                               "user": m.group("user"), "src_ip": m.group("ip"),
                               "host": host, "raw": line})
                continue
            m = _SSH_OK.search(rest)
            if m:
                events.append({"ts": ts, "source": "linux_auth", "event_type": "ssh_auth_success",
                               "user": m.group("user"), "src_ip": m.group("ip"),
                               "host": host, "raw": line})
                continue
            m = _SUDO.search(rest)
            if m:
                events.append({"ts": ts, "source": "linux_auth", "event_type": "sudo_command",
                               "user": m.group("user"), "command_line": m.group("cmd"),
                               "host": host, "raw": line})
    return events


def _parse_jsonl(path: str, source: str) -> list[dict]:
    events: list[dict] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            dt = datetime.strptime(rec["@timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
            ev = dict(rec)
            ev["ts"] = _epoch(dt)
            ev["source"] = source
            ev["raw"] = line
            # normalize common field names (keep originals too)
            if "EventID" in rec:
                ev["event_id"] = rec["EventID"]
            if "IpAddress" in rec:
                ev["src_ip"] = rec["IpAddress"]
            if "SourceIp" in rec:
                ev["src_ip"] = rec["SourceIp"]
            if "TargetUserName" in rec:
                ev["user"] = rec["TargetUserName"]
            if "CommandLine" in rec:
                ev["command_line"] = rec["CommandLine"]
            if "Image" in rec:
                ev["image"] = rec["Image"]
            if "ParentImage" in rec:
                ev["parent_image"] = rec["ParentImage"]
            if "DestinationPort" in rec:
                ev["dest_port"] = rec["DestinationPort"]
            events.append(ev)
    return events


def parse_win_security(path: str) -> list[dict]:
    return _parse_jsonl(path, "win_security")


def parse_sysmon(path: str) -> list[dict]:
    return _parse_jsonl(path, "sysmon")


def parse_apache(path: str) -> list[dict]:
    events: list[dict] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            m = _APACHE.match(line)
            if not m:
                continue
            # 10/Mar/2026:08:00:05 +0000
            dt = datetime.strptime(m.group("ts"), "%d/%b/%Y:%H:%M:%S %z")
            events.append({
                "ts": _epoch(dt), "source": "apache", "event_type": "http_request",
                "src_ip": m.group("ip"), "method": m.group("method"),
                "url": m.group("path"), "status": int(m.group("status")),
                "user_agent": m.group("ua"), "raw": line,
            })
    return events


def load_all(datasets_dir: str) -> list[dict]:
    """Parse every dataset file in datasets_dir and return a time-sorted list."""
    import os
    events: list[dict] = []
    events += parse_linux_auth(os.path.join(datasets_dir, "auth.log"))
    events += parse_win_security(os.path.join(datasets_dir, "windows_security.jsonl"))
    events += parse_sysmon(os.path.join(datasets_dir, "sysmon.jsonl"))
    events += parse_apache(os.path.join(datasets_dir, "apache_access.log"))
    events.sort(key=lambda e: e["ts"])
    return events
