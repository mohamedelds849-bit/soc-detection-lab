"""
pytest suite for the offline detection engine.

Two guarantees per rule:
  1. True positive  : the rule fires on the full (attacks + noise) dataset.
  2. No false positive: the rule does NOT fire on a benign-only dataset.

Also validates the correlation primitives and that every shipped rule is
syntactically loadable.
"""
import importlib.util
import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from detector import parsers, engine  # noqa: E402

# import the dataset generator module by path
_spec = importlib.util.spec_from_file_location(
    "gen", os.path.join(ROOT, "datasets", "generate.py"))
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

RULES_DIR = os.path.join(ROOT, "detector", "rules")

# Rules expected to fire on the attack dataset (every shipped rule).
EXPECTED_RULES = {
    "ssh_bruteforce", "rdp_bruteforce", "success_after_failures",
    "new_local_admin", "encoded_powershell", "scheduled_task_creation",
    "event_log_cleared", "port_scan", "defender_disabled",
    "web_shell_request", "office_spawns_shell",
}


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


def _fired_ids(rules, events):
    return {a.rule_id for a in engine.run_all(rules, events)}


# --- sanity ----------------------------------------------------------------
def test_all_rules_load(rules):
    assert len(rules) == 11
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
    rule = next(r for r in rules if r["id"] == rule_id)
    alerts = engine.run_rule(rule, attack_events)
    assert len(alerts) >= 1, f"{rule_id} did not fire on the attack dataset"


# --- false positives: no rule fires on benign-only data -------------------
@pytest.mark.parametrize("rule_id", sorted(EXPECTED_RULES))
def test_rule_quiet_on_benign(rules, benign_events, rule_id):
    rule = next(r for r in rules if r["id"] == rule_id)
    alerts = engine.run_rule(rule, benign_events)
    assert len(alerts) == 0, f"{rule_id} raised a FALSE POSITIVE on benign noise"


def test_full_run_covers_all_rules(rules, attack_events):
    assert _fired_ids(rules, attack_events) == EXPECTED_RULES


def test_benign_run_is_silent(rules, benign_events):
    assert _fired_ids(rules, benign_events) == set()


# --- engine primitives -----------------------------------------------------
def test_threshold_window_boundary():
    """Events spread beyond the window must NOT reach the threshold."""
    rule = {"id": "t", "name": "t", "attack": "T0", "type": "threshold",
            "group_by": ["src_ip"], "count": 3, "window_seconds": 10,
            "match": {"all": [{"field": "event_type", "equals": "x"}]}}
    # 3 events but spread over 40s -> no window of 10s holds 3
    evs = [{"ts": float(t), "src_ip": "a", "event_type": "x"} for t in (0, 20, 40)]
    assert engine.run_rule(rule, evs) == []
    # 3 events inside 8s -> fires
    evs2 = [{"ts": float(t), "src_ip": "a", "event_type": "x"} for t in (0, 4, 8)]
    assert len(engine.run_rule(rule, evs2)) == 1


def test_distinct_counts_unique_only():
    rule = {"id": "d", "name": "d", "attack": "T0", "type": "distinct",
            "group_by": ["src_ip"], "distinct_field": "dest_port", "count": 3,
            "window_seconds": 10, "match": {"all": [{"field": "k", "equals": 1}]}}
    # same port repeated -> only 1 distinct -> no alert
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
    # 2x a then b within window -> fires
    good = [{"ts": 0.0, "host": "h", "e": "a"}, {"ts": 1.0, "host": "h", "e": "a"},
            {"ts": 2.0, "host": "h", "e": "b"}]
    assert len(engine.run_rule(rule, good)) == 1
    # only 1 a before b -> does not fire
    bad = [{"ts": 0.0, "host": "h", "e": "a"}, {"ts": 2.0, "host": "h", "e": "b"}]
    assert engine.run_rule(rule, bad) == []


def test_match_operators():
    e = {"command_line": "powershell -EncodedCommand ABC", "n": 5}
    assert engine.match_condition(e, {"field": "command_line", "icontains": "encodedcommand"})
    assert engine.match_condition(e, {"field": "command_line", "regex": "(?i)-enc"})
    assert engine.match_condition(e, {"field": "n", "in": [4, 5, 6]})
    assert not engine.match_condition(e, {"field": "n", "equals": 1})
