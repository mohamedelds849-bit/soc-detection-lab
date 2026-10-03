"""
pytest suite for the offline detection engine.

What is checked:
  1. Every rule fires on the attack dataset, with the expected ENTITY
     (source IP / account SID / host), alert count and hit count.
  2. No rule fires on the benign-only dataset, which includes near misses
     (7 failures then success, unrelated admin change, "evaluation" ...).
  3. Threshold edges with the rules' REAL thresholds, read from the YAML:
     7 vs 8 failures, 14 vs 15 distinct ports, window inclusive/expired.
  4. Sequence logic: ordering, min_count, window expiry, correlation key
     (source IP, account SID via aliases).
  5. Behaviour-based web shell rule: positives and benign look-alikes, run
     against the engine, the Sigma regexes and the Wazuh pcre2 regexes.
  6. Determinism of the generator and consistency of the shipped rules.
"""
import filecmp
import importlib.util
import os
import re
import sys
import tempfile
import xml.etree.ElementTree as ET

import pytest
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from detector import parsers, engine  # noqa: E402

# import the dataset generator module by path
_spec = importlib.util.spec_from_file_location(
    "gen", os.path.join(ROOT, "datasets", "generate.py"))
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

RULES_DIR = os.path.join(ROOT, "detector", "rules")
SIGMA_DIR = os.path.join(ROOT, "rules", "sigma")
WAZUH_XML = os.path.join(ROOT, "rules", "wazuh", "local_rules.xml")

# Rules expected to fire on the attack dataset (every shipped rule).
EXPECTED_RULES = {
    "ssh_bruteforce", "rdp_bruteforce", "success_after_failures",
    "new_local_admin", "encoded_powershell", "scheduled_task_creation",
    "event_log_cleared", "port_scan", "defender_disabled",
    "web_shell_request", "office_spawns_shell", "rdp_success_after_bruteforce",
}

SSH_IP = "203.0.113.66"
RDP_IP = "198.51.100.77"
SCAN_IP = "203.0.113.90"
WEB_IP = "192.0.2.44"
NEW_ADMIN_SID = "S-1-5-21-1111111111-2222222222-3333333333-1005"


@pytest.fixture(scope="module")
def attack_events():
    with tempfile.TemporaryDirectory() as d:
        gen.build(d, include_attacks=True)
        yield parsers.load_all(d)


@pytest.fixture(scope="module")
def benign_events():
    with tempfile.TemporaryDirectory() as d:
        gen.build(d, include_attacks=False)
        yield parsers.load_all(d)


@pytest.fixture(scope="module")
def rules():
    return engine.load_rules(RULES_DIR)


def _rule(rules, rule_id):
    return next(r for r in rules if r["id"] == rule_id)


def _fired_ids(rules, events):
    return {a.rule_id for a in engine.run_all(rules, events)}


# --- sanity ----------------------------------------------------------------
def test_all_rules_load(rules):
    assert len(rules) == 12
    ids = {r["id"] for r in rules}
    assert ids == EXPECTED_RULES
    for r in rules:
        assert r.get("attack"), f"{r['id']} missing ATT&CK id"
        assert r.get("type") in {"single", "threshold", "distinct", "sequence"}


def test_datasets_parse(attack_events):
    assert len(attack_events) > 200
    sources = {e["source"] for e in attack_events}
    assert sources == {"linux_auth", "win_security", "sysmon", "apache"}


# --- true positives: every rule fires on the attack dataset ---------------
@pytest.mark.parametrize("rule_id", sorted(EXPECTED_RULES))
def test_rule_fires_on_attack(rules, attack_events, rule_id):
    alerts = engine.run_rule(_rule(rules, rule_id), attack_events)
    assert len(alerts) >= 1, f"{rule_id} did not fire on the attack dataset"


# rule_id -> (number of alerts, entity of every alert, hit count of the first alert)
EXPECTED_ALERTS = {
    "ssh_bruteforce": (1, f"src_ip={SSH_IP}", 14),          # 14 failures in the burst
    "success_after_failures": (1, f"src_ip={SSH_IP}", 15),  # 14 failures + 1 success
    "rdp_bruteforce": (1, f"src_ip={RDP_IP}", 12),          # 12 failures
    "rdp_success_after_bruteforce": (1, f"src_ip={RDP_IP}", 13),  # 12 failures + 1 success
    "new_local_admin": (1, f"account_sid={NEW_ADMIN_SID}", 2),   # 4720 + 4732
    "port_scan": (1, f"src_ip={SCAN_IP}", 21),              # 21 distinct ports
    "web_shell_request": (4, WEB_IP, 1),                    # 4 malicious requests
    "scheduled_task_creation": (2, "LAB-WIN11", 1),         # 4698 + schtasks.exe
    "encoded_powershell": (1, "LAB-WIN11", 1),
    "event_log_cleared": (1, "LAB-WIN11", 1),
    "defender_disabled": (1, "LAB-WIN11", 1),
    "office_spawns_shell": (1, "LAB-WIN11", 1),
}


@pytest.mark.parametrize("rule_id", sorted(EXPECTED_ALERTS))
def test_alert_entity_and_counts(rules, attack_events, rule_id):
    n, entity, hits = EXPECTED_ALERTS[rule_id]
    alerts = engine.run_rule(_rule(rules, rule_id), attack_events)
    assert len(alerts) == n, [a.entity for a in alerts]
    assert all(a.entity == entity for a in alerts), [a.entity for a in alerts]
    assert alerts[0].count == hits


def test_rdp_success_alert_points_at_the_4624(rules, attack_events):
    (a,) = engine.run_rule(_rule(rules, "rdp_success_after_bruteforce"), attack_events)
    assert a.time_str == "2026-03-10 08:50:59Z"
    assert '"EventID": 4624' in a.evidence[-1]
    assert '"LogonType": 10' in a.evidence[-1]


# --- false positives: no rule fires on benign-only data -------------------
@pytest.mark.parametrize("rule_id", sorted(EXPECTED_RULES))
def test_rule_quiet_on_benign(rules, benign_events, rule_id):
    alerts = engine.run_rule(_rule(rules, rule_id), benign_events)
    assert len(alerts) == 0, f"{rule_id} raised a FALSE POSITIVE on benign noise"


def test_full_run_covers_all_rules(rules, attack_events):
    assert _fired_ids(rules, attack_events) == EXPECTED_RULES


def test_benign_run_is_silent(rules, benign_events):
    assert _fired_ids(rules, benign_events) == set()


def test_benign_baseline_contains_near_misses(benign_events):
    """The 0-FP claim is only meaningful if the baseline contains look-alikes."""
    ssh_fail = [e for e in benign_events if e.get("event_type") == "ssh_auth_failure"
                and e["src_ip"] == "10.10.0.31"]
    rdp_fail = [e for e in benign_events if e.get("event_id") == 4625 and e["src_ip"] == "10.10.0.30"]
    assert len(ssh_fail) == 7 and len(rdp_fail) == 7          # one below the threshold
    assert any(e.get("event_id") == 4624 and e["src_ip"] == "10.10.0.30" for e in benign_events)
    assert any(e.get("event_id") == 4720 for e in benign_events)
    assert any(e.get("event_id") == 4732 for e in benign_events)
    urls = {e.get("url") for e in benign_events if e["source"] == "apache"}
    assert "/search?q=evaluation" in urls


# --- helpers to build synthetic events -------------------------------------
def _ssh_fail(ts, ip="203.0.113.5", user="root"):
    return {"ts": float(ts), "source": "linux_auth", "event_type": "ssh_auth_failure",
            "src_ip": ip, "user": user, "host": "h", "raw": f"fail {ts}"}


def _ssh_ok(ts, ip="203.0.113.5", user="root"):
    return {"ts": float(ts), "source": "linux_auth", "event_type": "ssh_auth_success",
            "src_ip": ip, "user": user, "host": "h", "raw": f"ok {ts}"}


def _win(ts, event_id, ip="198.51.100.9", logon_type=10, **extra):
    e = {"ts": float(ts), "source": "win_security", "event_id": event_id, "EventID": event_id,
         "src_ip": ip, "IpAddress": ip, "LogonType": logon_type, "host": "WIN",
         "raw": f"{event_id} {ts}"}
    e.update(extra)
    return e


# --- threshold edges (real thresholds from the YAML) -----------------------
def test_shipped_thresholds_are_the_documented_ones(rules):
    assert (_rule(rules, "ssh_bruteforce")["count"], _rule(rules, "ssh_bruteforce")["window_seconds"]) == (8, 120)
    assert (_rule(rules, "rdp_bruteforce")["count"], _rule(rules, "rdp_bruteforce")["window_seconds"]) == (8, 120)
    assert (_rule(rules, "port_scan")["count"], _rule(rules, "port_scan")["window_seconds"]) == (15, 60)
    for rid in ("success_after_failures", "rdp_success_after_bruteforce"):
        r = _rule(rules, rid)
        assert r["steps"][0]["min_count"] == 8 and r["window_seconds"] == 180


def test_ssh_bruteforce_7_vs_8(rules):
    r = _rule(rules, "ssh_bruteforce")
    n = r["count"]
    assert engine.run_rule(r, [_ssh_fail(i) for i in range(n - 1)]) == []
    (a,) = engine.run_rule(r, [_ssh_fail(i) for i in range(n)])
    assert a.entity == "src_ip=203.0.113.5" and a.count == n and a.ts == float(n - 1)


def test_ssh_bruteforce_window_edges(rules):
    r = _rule(rules, "ssh_bruteforce")
    n, w = r["count"], r["window_seconds"]
    # 8th failure exactly at window end -> inside (inclusive)
    inside = [_ssh_fail(i) for i in range(n - 1)] + [_ssh_fail(w)]
    assert len(engine.run_rule(r, inside)) == 1
    # 8th failure 1 s too late -> the first failure has expired
    late = [_ssh_fail(i) for i in range(n - 1)] + [_ssh_fail(w + 1)]
    assert engine.run_rule(r, late) == []


def test_ssh_bruteforce_groups_by_source_ip(rules):
    r = _rule(rules, "ssh_bruteforce")
    # 8 failures but split across two IPs -> no single source reaches the threshold
    evs = [_ssh_fail(i, ip="203.0.113.5") for i in range(4)] + \
          [_ssh_fail(i, ip="203.0.113.6") for i in range(4)]
    assert engine.run_rule(r, evs) == []


def test_rdp_bruteforce_7_vs_8_and_logon_type(rules):
    r = _rule(rules, "rdp_bruteforce")
    n = r["count"]
    assert engine.run_rule(r, [_win(i, 4625) for i in range(n - 1)]) == []
    (a,) = engine.run_rule(r, [_win(i, 4625) for i in range(n)])
    assert a.entity == "src_ip=198.51.100.9" and a.count == n
    # NLA: network logon type 3 counts too
    assert len(engine.run_rule(r, [_win(i, 4625, logon_type=3) for i in range(n)])) == 1
    # interactive console failures (type 2) are not remote brute force
    assert engine.run_rule(r, [_win(i, 4625, logon_type=2) for i in range(n)]) == []


def _conn(ts, port, ip="203.0.113.200"):
    return {"ts": float(ts), "source": "sysmon", "event_id": 3, "src_ip": ip,
            "dest_port": port, "host": "WIN", "raw": f"conn {port}"}


def test_port_scan_14_vs_15_distinct(rules):
    r = _rule(rules, "port_scan")
    n = r["count"]
    assert engine.run_rule(r, [_conn(i, 1000 + i) for i in range(n - 1)]) == []
    # 14 distinct ports + repeats of one of them -> still 14 distinct
    repeats = [_conn(i, 1000 + i) for i in range(n - 1)] + [_conn(20 + i, 1000) for i in range(5)]
    assert engine.run_rule(r, repeats) == []
    (a,) = engine.run_rule(r, [_conn(i, 1000 + i) for i in range(n)])
    assert a.entity == "src_ip=203.0.113.200" and a.count == n


def test_port_scan_window_expiry(rules):
    r = _rule(rules, "port_scan")
    n, w = r["count"], r["window_seconds"]
    slow = [_conn(i * (w / (n - 1)) + 0.5 * i, 2000 + i) for i in range(n)]  # spread just over 60 s
    assert slow[-1]["ts"] - slow[0]["ts"] > w
    assert engine.run_rule(r, slow) == []


# --- sequence: success after failures (SSH and RDP) ------------------------
def test_ssh_success_after_failures_edges(rules):
    r = _rule(rules, "success_after_failures")
    n, w = r["steps"][0]["min_count"], r["window_seconds"]
    # 7 failures then success -> no
    assert engine.run_rule(r, [_ssh_fail(i) for i in range(n - 1)] + [_ssh_ok(30)]) == []
    # 8 failures then success -> yes, count = 8 + 1
    (a,) = engine.run_rule(r, [_ssh_fail(i) for i in range(n)] + [_ssh_ok(30)])
    assert a.entity == "src_ip=203.0.113.5" and a.count == n + 1 and a.ts == 30.0
    # ordering: success BEFORE the failures -> no
    assert engine.run_rule(r, [_ssh_ok(0)] + [_ssh_fail(1 + i) for i in range(n)]) == []
    # success from another IP -> no
    assert engine.run_rule(r, [_ssh_fail(i) for i in range(n)] + [_ssh_ok(30, ip="10.0.0.9")]) == []
    # window: success exactly 180 s after the first failure -> yes; 1 s later -> expired
    fails = [_ssh_fail(i) for i in range(n)]
    assert len(engine.run_rule(r, fails + [_ssh_ok(w)])) == 1
    assert engine.run_rule(r, fails + [_ssh_ok(w + 1)]) == []


def test_ssh_success_after_failures_old_failures_do_not_block(rules):
    """2 old failures followed later by a fresh burst of 8 + success must fire
    (the window is measured back from the success, not from the first failure)."""
    r = _rule(rules, "success_after_failures")
    evs = [_ssh_fail(0), _ssh_fail(1)] + [_ssh_fail(150 + i) for i in range(8)] + [_ssh_ok(190)]
    (a,) = engine.run_rule(r, evs)
    assert a.count == 9  # the 2 failures at t=0/1 are outside [10, 190]


def test_rdp_success_after_bruteforce_positive_variants(rules):
    r = _rule(rules, "rdp_success_after_bruteforce")
    fails = [_win(i * 3, 4625) for i in range(8)]
    # RDP logon type 10
    (a,) = engine.run_rule(r, fails + [_win(40, 4624, logon_type=10, AuthenticationPackageName="Negotiate")])
    assert a.entity == "src_ip=198.51.100.9" and a.count == 9
    # NLA / SMB: network logon type 3 with NTLM
    assert len(engine.run_rule(r, fails + [_win(40, 4624, logon_type=3, AuthenticationPackageName="NTLM")])) == 1
    # failures were type 3 (NLA), success type 10
    fails3 = [_win(i * 3, 4625, logon_type=3) for i in range(8)]
    assert len(engine.run_rule(r, fails3 + [_win(40, 4624, logon_type=10)])) == 1
    # spraying: the account that logs on differs from the one that failed -> still fires
    assert len(engine.run_rule(r, fails + [_win(40, 4624, TargetUserName="other")])) == 1


def test_rdp_success_after_bruteforce_negatives(rules):
    r = _rule(rules, "rdp_success_after_bruteforce")
    fails = [_win(i * 3, 4625) for i in range(8)]
    # 7 failures then success
    assert engine.run_rule(r, fails[:7] + [_win(40, 4624)]) == []
    # success BEFORE the failures
    assert engine.run_rule(r, [_win(0, 4624)] + [_win(5 + i, 4625) for i in range(8)]) == []
    # success from a different IP
    assert engine.run_rule(r, fails + [_win(40, 4624, ip="10.10.0.5")]) == []
    # Kerberos network logon (normal domain traffic) is not counted as the success
    assert engine.run_rule(r, fails + [_win(40, 4624, logon_type=3, AuthenticationPackageName="Kerberos")]) == []
    # interactive console logon (type 2) is not a remote logon
    assert engine.run_rule(r, fails + [_win(40, 4624, logon_type=2)]) == []
    # failures of logon type 2 do not count toward the brute force
    assert engine.run_rule(r, [_win(i, 4625, logon_type=2) for i in range(8)] + [_win(40, 4624)]) == []
    # window expiry: 8 failures at t=0..21, success 181 s after the first one
    assert len(engine.run_rule(r, fails + [_win(180, 4624)])) == 1
    assert engine.run_rule(r, fails + [_win(181, 4624)]) == []


# --- new local admin: correlation by SID, not by host ----------------------
SID_A = "S-1-5-21-1-2-3-1101"
SID_B = "S-1-5-21-1-2-3-1102"


def _4720(ts, sid, host="WIN"):
    return {"ts": float(ts), "source": "win_security", "event_id": 4720, "host": host,
            "TargetUserName": "u", "TargetSid": sid, "raw": f"4720 {sid}"}


def _4732(ts, member_sid, group_sid="S-1-5-32-544", host="WIN"):
    return {"ts": float(ts), "source": "win_security", "event_id": 4732, "host": host,
            "TargetUserName": "Administrators", "TargetSid": group_sid,
            "MemberSid": member_sid, "raw": f"4732 {member_sid}"}


def test_new_local_admin_joins_on_sid(rules):
    r = _rule(rules, "new_local_admin")
    (a,) = engine.run_rule(r, [_4720(0, SID_A), _4732(10, SID_A)])
    assert a.entity == f"account_sid={SID_A}" and a.count == 2


def test_new_local_admin_unrelated_account_does_not_fire(rules):
    """Account A is created, then an unrelated account B is added to
    Administrators on the SAME host: no correlated alert."""
    r = _rule(rules, "new_local_admin")
    assert engine.run_rule(r, [_4720(0, SID_A), _4732(10, SID_B)]) == []
    # ...but if A is also added later, only A is reported
    alerts = engine.run_rule(r, [_4720(0, SID_A), _4732(10, SID_B), _4732(20, SID_A)])
    assert [a.entity for a in alerts] == [f"account_sid={SID_A}"]


def test_new_local_admin_other_group_order_and_window(rules):
    r = _rule(rules, "new_local_admin")
    w = r["window_seconds"]
    # added to Remote Desktop Users (S-1-5-32-555), not Administrators
    assert engine.run_rule(r, [_4720(0, SID_A), _4732(10, SID_A, group_sid="S-1-5-32-555")]) == []
    # added to Administrators BEFORE being created (impossible order) -> no
    assert engine.run_rule(r, [_4732(0, SID_A), _4720(10, SID_A)]) == []
    # window: exactly 120 s -> yes; 121 s -> no
    assert len(engine.run_rule(r, [_4720(0, SID_A), _4732(w, SID_A)])) == 1
    assert engine.run_rule(r, [_4720(0, SID_A), _4732(w + 1, SID_A)]) == []


# --- engine primitives -----------------------------------------------------
def test_threshold_window_boundary():
    """Events spread beyond the window must NOT reach the threshold."""
    rule = {"id": "t", "name": "t", "attack": "T0", "type": "threshold",
            "group_by": ["src_ip"], "count": 3, "window_seconds": 10,
            "match": {"all": [{"field": "event_type", "equals": "x"}]}}
    evs = [{"ts": float(t), "src_ip": "a", "event_type": "x"} for t in (0, 20, 40)]
    assert engine.run_rule(rule, evs) == []
    evs2 = [{"ts": float(t), "src_ip": "a", "event_type": "x"} for t in (0, 4, 8)]
    assert len(engine.run_rule(rule, evs2)) == 1


def test_distinct_counts_unique_only():
    rule = {"id": "d", "name": "d", "attack": "T0", "type": "distinct",
            "group_by": ["src_ip"], "distinct_field": "dest_port", "count": 3,
            "window_seconds": 10, "match": {"all": [{"field": "k", "equals": 1}]}}
    evs = [{"ts": float(t), "src_ip": "a", "dest_port": 80, "k": 1} for t in range(5)]
    assert engine.run_rule(rule, evs) == []
    evs2 = [{"ts": float(i), "src_ip": "a", "dest_port": 80 + i, "k": 1} for i in range(3)]
    assert len(engine.run_rule(rule, evs2)) == 1


def test_sequence_requires_order_and_window():
    rule = {"id": "s", "name": "s", "attack": "T0", "type": "sequence",
            "group_by": ["host"], "window_seconds": 30,
            "steps": [
                {"match": {"all": [{"field": "e", "equals": "a"}]}, "min_count": 2},
                {"match": {"all": [{"field": "e", "equals": "b"}]}, "min_count": 1},
            ]}
    good = [{"ts": 0.0, "host": "h", "e": "a"}, {"ts": 1.0, "host": "h", "e": "a"},
            {"ts": 2.0, "host": "h", "e": "b"}]
    assert len(engine.run_rule(rule, good)) == 1
    bad = [{"ts": 0.0, "host": "h", "e": "a"}, {"ts": 2.0, "host": "h", "e": "b"}]
    assert engine.run_rule(rule, bad) == []
    # b before the a's
    rev = [{"ts": 0.0, "host": "h", "e": "b"}, {"ts": 1.0, "host": "h", "e": "a"},
           {"ts": 2.0, "host": "h", "e": "a"}]
    assert engine.run_rule(rule, rev) == []
    # a's in another group
    other = [{"ts": 0.0, "host": "x", "e": "a"}, {"ts": 1.0, "host": "x", "e": "a"},
             {"ts": 2.0, "host": "h", "e": "b"}]
    assert engine.run_rule(rule, other) == []


def test_three_step_sequence_order():
    rule = {"id": "s3", "name": "s3", "attack": "T0", "type": "sequence",
            "group_by": ["k"], "window_seconds": 100,
            "steps": [{"match": {"all": [{"field": "e", "equals": x}]}} for x in "abc"]}
    ev = lambda t, e: {"ts": float(t), "k": 1, "e": e}  # noqa: E731
    assert len(engine.run_rule(rule, [ev(0, "a"), ev(1, "b"), ev(2, "c")])) == 1
    assert engine.run_rule(rule, [ev(0, "b"), ev(1, "a"), ev(2, "c")]) == []


def test_match_operators_and_nested_blocks():
    e = {"command_line": "powershell -EncodedCommand ABC", "n": 5, "t": 3, "p": "NTLM"}
    assert engine.match_condition(e, {"field": "command_line", "icontains": "encodedcommand"})
    assert engine.match_condition(e, {"field": "command_line", "regex": "(?i)-enc"})
    assert engine.match_condition(e, {"field": "n", "in": [4, 5, 6]})
    assert not engine.match_condition(e, {"field": "n", "equals": 1})
    nested = {"any": [{"field": "t", "equals": 10},
                      {"all": [{"field": "t", "equals": 3}, {"field": "p", "equals": "NTLM"}]}]}
    assert engine.match_block(e, nested)
    assert not engine.match_block({**e, "p": "Kerberos"}, nested)


def test_encoded_powershell_realistic_variants(rules):
    """Guard against over-fitting to the single synthetic sample: PowerShell
    accepts abbreviations of -EncodedCommand, and -ExecutionPolicy must not match."""
    rule = _rule(rules, "encoded_powershell")
    ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    def ev(cmd, image=ps):
        return [{"ts": 0.0, "source": "sysmon", "event_id": 1, "host": "h",
                 "image": image, "command_line": cmd}]

    for cmd in ("powershell.exe -nop -w hidden -e SQBFAFgA",
                "powershell -ec SQBFAFgA",
                "powershell -enc SQBFAFgA",
                "powershell -EncodedCommand SQBFAFgA"):
        assert len(engine.run_rule(rule, ev(cmd))) == 1, cmd
    assert len(engine.run_rule(rule, ev(
        "pwsh -EncodedCommand SQBFAFgA", "C:\\Program Files\\PowerShell\\7\\pwsh.exe"))) == 1
    assert engine.run_rule(rule, ev("powershell -ExecutionPolicy Bypass -File backup.ps1")) == []
    assert engine.run_rule(rule, ev("powershell -Command Get-Content a.txt -Encoding UTF8")) == []


# --- web shell: behaviour, not names -- engine + Sigma + Wazuh -------------
# (method, url, status)
WEB_POSITIVES = [
    ("GET", "/uploads/shell.php?cmd=whoami", 200),
    ("GET", "/images/x.php?c=id", 200),
    ("GET", "/a.php?exec=uname+-a", 200),
    ("GET", "/a.php?command=net+user", 200),
    ("GET", "/a.php?cmd=cat%20%2Fetc%2Fpasswd", 200),
    ("GET", "/a.php?page=1&cmd=ls+-la", 200),
    ("GET", "/a.php?run=x%3Bwhoami", 200),
    ("GET", "/uploads/shell.php?cmd=Y2F0IC9ldGMvcGFzc3dk", 200),     # base64 payload
    ("GET", "/index.php?x=eval%28base64_decode%28%27aWQ%27%29%29", 200),  # eval(base64_decode(...))
    ("POST", "/wp-content/uploads/2026/03/img.php", 200),           # POST to script in uploads
    ("POST", "/files/tmp.phtml", 200),
]
WEB_NEGATIVES = [
    ("GET", "/search?q=evaluation", 200),            # the reported FP of the old 'eval' token
    ("GET", "/search?q=course+evaluation+form", 200),
    ("GET", "/search?q=whoami+command+linux", 200),  # command word, but in a search param
    ("GET", "/product?id=42", 200),                  # 'id' as a parameter NAME
    ("GET", "/blog/recipe-1?c=dark-mode", 200),      # c= with a benign value
    ("GET", "/a.php?cmd=identity", 200),             # 'id' prefix only
    ("GET", "/a.php?command=listAllProductsToday", 200),  # long value, no digit -> not base64
    ("GET", "/docs/shell-scripting-basics", 200),
    ("GET", "/uploads/shell.php", 200),              # GET without command (name alone is not behaviour)
    ("GET", "/up.php", 200),                         # dataset file names are no longer indicators
    ("GET", "/evil.php", 200),
    ("POST", "/wp-content/uploads/evil.php", 403),   # blocked POST (not 2xx)
    ("POST", "/wp-admin/async-upload.php", 200),     # legit uploader, not inside an upload dir
    ("POST", "/uploads/avatar.png", 201),            # upload of an image
    ("POST", "/contact", 200),
]


def _web_event(method, url, status):
    return {"ts": 0.0, "source": "apache", "event_type": "http_request", "src_ip": "192.0.2.99",
            "method": method, "url": url, "status": status, "user_agent": "x", "raw": url}


@pytest.mark.parametrize("method,url,status", WEB_POSITIVES)
def test_web_shell_engine_positive(rules, method, url, status):
    assert len(engine.run_rule(_rule(rules, "web_shell_request"), [_web_event(method, url, status)])) == 1


@pytest.mark.parametrize("method,url,status", WEB_NEGATIVES)
def test_web_shell_engine_negative(rules, method, url, status):
    assert engine.run_rule(_rule(rules, "web_shell_request"), [_web_event(method, url, status)]) == []


def _sigma_docs(name):
    with open(os.path.join(SIGMA_DIR, name), encoding="utf-8") as f:
        return [d for d in yaml.safe_load_all(f) if d]


def _sigma_web_match(method, url, status):
    """Evaluate the Sigma web_shell detection in Python (cs-uri-stem / cs-uri-query
    split like a W3C/IIS log)."""
    (doc,) = _sigma_docs("web_shell.yml")
    det = doc["detection"]
    stem, _, query = url.partition("?")
    fields = {"cs-method": method, "cs-uri-stem": stem, "cs-uri-query": query, "sc-status": status}

    def sel_match(sel):
        for key, val in sel.items():
            fname, _, mod = key.partition("|")
            v = fields[fname]
            if mod == "re":
                if not re.search(val, str(v)):
                    return False
            elif isinstance(val, list):
                if v not in val:
                    return False
            elif v != val:
                return False
        return True

    assert det["condition"] == "1 of selection_*"
    return any(sel_match(v) for k, v in det.items() if k.startswith("selection_"))


@pytest.mark.parametrize("method,url,status", WEB_POSITIVES)
def test_web_shell_sigma_positive(method, url, status):
    assert _sigma_web_match(method, url, status)


@pytest.mark.parametrize("method,url,status", WEB_NEGATIVES)
def test_web_shell_sigma_negative(method, url, status):
    assert not _sigma_web_match(method, url, status)


def _wazuh_rules():
    return {r.get("id"): r for r in ET.parse(WAZUH_XML).getroot().iter("rule")}


def _wazuh_web_match(method, url, status):
    """Evaluate Wazuh 100190-100192 with Python re (the patterns use only PCRE
    features that Python re shares: (?i), lookahead, \\b, classes)."""
    rs = _wazuh_rules()
    for rid in ("100190", "100191", "100192"):
        r = rs[rid]
        ok = re.search(r.find("url").text, url) is not None
        if r.find("protocol") is not None:
            ok = ok and method == r.find("protocol").text
        if r.find("id") is not None:
            ok = ok and re.search(r.find("id").text, str(status)) is not None
        if ok:
            return True
    return False


@pytest.mark.parametrize("method,url,status", WEB_POSITIVES)
def test_web_shell_wazuh_positive(method, url, status):
    assert _wazuh_web_match(method, url, status)


@pytest.mark.parametrize("method,url,status", WEB_NEGATIVES)
def test_web_shell_wazuh_negative(method, url, status):
    assert not _wazuh_web_match(method, url, status)


def test_no_dataset_specific_tokens_left():
    """up.php / evil.php / bare 'eval' must not be detection logic anywhere."""
    texts = [open(os.path.join(RULES_DIR, "10_web_shell.yaml"), encoding="utf-8").read(),
             open(os.path.join(SIGMA_DIR, "web_shell.yml"), encoding="utf-8").read()]
    rs = _wazuh_rules()
    texts += [ET.tostring(rs[i], encoding="unicode") for i in ("100190", "100191", "100192")]
    for t in texts:
        logic = "\n".join(l for l in t.splitlines() if "regex" in l or "|re" in l or "<url" in l)
        assert "up\\.php" not in logic and "evil" not in logic
        assert not re.search(r"\|eval\||\(eval\||\|eval\)", logic)


# --- shipped rule files: consistency ---------------------------------------
def test_wazuh_rules_well_formed_and_consistent():
    rs = _wazuh_rules()
    ids = [r.get("id") for r in ET.parse(WAZUH_XML).getroot().iter("rule")]
    assert len(ids) == len(set(ids))
    assert all(100000 <= int(i) <= 120000 for i in ids)
    # rule 12 in Wazuh form: 4624 children of 60106 chained on the RDP brute force
    for rid, ltype in (("100122", "^10$"), ("100123", "^3$")):
        r = rs[rid]
        assert r.find("if_sid").text == "60106"
        assert r.find("if_matched_sid").text == "100121"
        assert r.find("same_field").text == "win.eventdata.ipAddress"
        assert int(r.get("level")) > 12  # tried before built-in 40112 (level 12)
        fields = {f.get("name"): f.text for f in r.findall("field")}
        assert fields["win.system.eventID"] == "^4624$"
        assert fields["win.eventdata.logonType"] == ltype
    assert rs["100121"].find("if_sid").text == "60204"
    assert rs["100110"].find("if_sid").text == "5763"
    assert "100120" not in rs
    # every PCRE-style pattern declares pcre2
    for r in rs.values():
        for el in r:
            if el.text and "(?i)" in el.text:
                assert el.get("type") == "pcre2", (r.get("id"), el.tag)


def test_sigma_ids_are_unique_uuids_and_rule12_is_chained():
    uuid_re = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    ids, names = [], set()
    for fn in os.listdir(SIGMA_DIR):
        for d in _sigma_docs(fn):
            assert uuid_re.match(d["id"]), (fn, d["id"])
            ids.append(d["id"])
            if "name" in d:
                names.add(d["name"])
    assert len(ids) == len(set(ids))
    base, corr = _sigma_docs("rdp_success_after_bruteforce.yml")
    assert corr["correlation"]["type"] == "temporal_ordered"
    assert corr["correlation"]["rules"] == ["lab_win_failed_logon_burst", base["name"]]
    assert set(corr["correlation"]["rules"]) <= names
    assert corr["correlation"]["group-by"] == ["IpAddress"]
    assert {"attack.t1110", "attack.t1078"} <= set(corr["tags"])


# --- determinism -----------------------------------------------------------
def test_generator_is_deterministic_and_matches_committed_dataset():
    names = ["auth.log", "windows_security.jsonl", "sysmon.jsonl", "apache_access.log"]
    with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
        gen.build(d1, include_attacks=True)
        gen.build(d2, include_attacks=True)
        for n in names:
            assert filecmp.cmp(os.path.join(d1, n), os.path.join(d2, n), shallow=False), n
            with open(os.path.join(d1, n), "rb") as a, \
                    open(os.path.join(ROOT, "datasets", n), "rb") as b:
                assert a.read() == b.read().replace(b"\r\n", b"\n"), \
                    f"datasets/{n} is stale: run python datasets/generate.py"


# --- wazuh-logtest replay material ------------------------------------------
def test_wazuh_samples_are_current_and_documented():
    spec = importlib.util.spec_from_file_location(
        "mws", os.path.join(ROOT, "tools", "make_wazuh_samples.py"))
    mws = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mws)
    cases = mws.build()
    out = os.path.join(ROOT, "datasets", "wazuh_logtest")
    all_lines = set()
    for name, lines in cases.items():
        with open(os.path.join(out, name + ".log"), encoding="utf-8") as f:
            assert f.read().splitlines() == lines, f"{name}.log is stale: run tools/make_wazuh_samples.py"
        all_lines.update(lines)
    with open(os.path.join(ROOT, "docs", "WAZUH-VALIDATION.md"), encoding="utf-8") as f:
        doc = f.read()
    # every log line quoted in the checklist must be a real replay line
    quoted = [l for l in doc.splitlines() if l.startswith('{"win"') or " sshd[" in l or '] "' in l]
    assert len(quoted) >= 25
    for line in quoted:
        assert line in all_lines, line[:120]
    # every case file is referenced in the checklist
    for name in cases:
        assert name + ".log" in doc, name
