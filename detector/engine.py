#!/usr/bin/env python3
"""
Offline detection engine.

Loads simple YAML rules and runs them over a list of normalized events
(see detector/parsers.py). Supports four rule types:

  single     : fire once per event that matches `match`.
  threshold  : group matching events by `group_by`; if >= `count` fall inside
               a sliding window of `window_seconds`, fire one alert per group.
  distinct   : like threshold, but counts DISTINCT values of `distinct_field`
               (used for port scans: many distinct destination ports).
  sequence   : ordered `steps` (each with its own match + optional min_count),
               all within `window_seconds`, grouped by `group_by`
               (used for "success after many failures" and "new admin account").

Field matching operators (per condition):
  equals, not_equals, in, contains, icontains (case-insensitive contains),
  regex, startswith.

An Alert carries the ATT&CK id, severity, matched evidence and a triage note.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

import yaml


# ---------------------------------------------------------------------------
# Condition matching
# ---------------------------------------------------------------------------
def _get(event: dict, field_name: str):
    return event.get(field_name)


def match_condition(event: dict, cond: dict) -> bool:
    fname = cond["field"]
    val = _get(event, fname)
    if "equals" in cond:
        return val == cond["equals"]
    if "not_equals" in cond:
        return val != cond["not_equals"]
    if "in" in cond:
        return val in cond["in"]
    if "contains" in cond:
        return val is not None and str(cond["contains"]) in str(val)
    if "icontains" in cond:
        return val is not None and str(cond["icontains"]).lower() in str(val).lower()
    if "startswith" in cond:
        return val is not None and str(val).startswith(str(cond["startswith"]))
    if "regex" in cond:
        return val is not None and re.search(cond["regex"], str(val)) is not None
    if "exists" in cond:
        return (val is not None) == bool(cond["exists"])
    raise ValueError(f"Unknown operator in condition: {cond}")


def match_block(event: dict, block: dict) -> bool:
    """A match block is {all: [...]} and/or {any: [...]} of conditions."""
    if not block:
        return True
    ok = True
    if "all" in block:
        ok = ok and all(match_condition(event, c) for c in block["all"])
    if "any" in block:
        ok = ok and any(match_condition(event, c) for c in block["any"])
    # a bare list is treated as "all"
    if isinstance(block, list):
        ok = all(match_condition(event, c) for c in block)
    return ok


def _group_key(event: dict, keys: list[str]) -> tuple:
    return tuple(event.get(k) for k in keys)


# ---------------------------------------------------------------------------
# Alert
# ---------------------------------------------------------------------------
@dataclass
class Alert:
    rule_id: str
    name: str
    attack: str
    severity: str
    source: str
    ts: float
    entity: str
    count: int
    triage: str
    evidence: list = field(default_factory=list)

    @property
    def time_str(self) -> str:
        return datetime.fromtimestamp(self.ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["time"] = self.time_str
        return d


# ---------------------------------------------------------------------------
# Rule runners
# ---------------------------------------------------------------------------
def _entity_str(keys: list[str], key_vals: tuple) -> str:
    return ", ".join(f"{k}={v}" for k, v in zip(keys, key_vals)) if keys else "-"


def run_single(rule: dict, events: list[dict]) -> list[Alert]:
    alerts = []
    for e in events:
        if match_block(e, rule.get("match", {})):
            alerts.append(Alert(
                rule_id=rule["id"], name=rule["name"], attack=rule["attack"],
                severity=rule.get("severity", "medium"), source=e.get("source", "-"),
                ts=e["ts"], entity=e.get(rule.get("entity_field", "host"), "-"),
                count=1, triage=rule.get("triage", ""), evidence=[e.get("raw", "")],
            ))
    return alerts


def _sliding_window_hit(times: list[float], count: int, window: float):
    """Return (start_idx, end_idx) of the first window containing >= count events."""
    lo = 0
    for hi in range(len(times)):
        while times[hi] - times[lo] > window:
            lo += 1
        if hi - lo + 1 >= count:
            return lo, hi
    return None


def run_threshold(rule: dict, events: list[dict]) -> list[Alert]:
    keys = rule.get("group_by", [])
    window = float(rule.get("window_seconds", 60))
    count = int(rule["count"])
    groups: dict[tuple, list[dict]] = {}
    for e in events:
        if match_block(e, rule.get("match", {})):
            groups.setdefault(_group_key(e, keys), []).append(e)

    alerts = []
    for key, evs in groups.items():
        evs.sort(key=lambda x: x["ts"])
        times = [x["ts"] for x in evs]
        hit = _sliding_window_hit(times, count, window)
        if hit:
            lo, hi = hit
            window_evs = evs[lo:hi + 1]
            alerts.append(Alert(
                rule_id=rule["id"], name=rule["name"], attack=rule["attack"],
                severity=rule.get("severity", "medium"), source=evs[0].get("source", "-"),
                ts=window_evs[-1]["ts"], entity=_entity_str(keys, key),
                count=len(window_evs), triage=rule.get("triage", ""),
                evidence=[x.get("raw", "") for x in window_evs[:5]],
            ))
    return alerts


def run_distinct(rule: dict, events: list[dict]) -> list[Alert]:
    keys = rule.get("group_by", [])
    dfield = rule["distinct_field"]
    window = float(rule.get("window_seconds", 60))
    count = int(rule["count"])
    groups: dict[tuple, list[dict]] = {}
    for e in events:
        if match_block(e, rule.get("match", {})):
            groups.setdefault(_group_key(e, keys), []).append(e)

    alerts = []
    for key, evs in groups.items():
        evs.sort(key=lambda x: x["ts"])
        lo = 0
        for hi in range(len(evs)):
            while evs[hi]["ts"] - evs[lo]["ts"] > window:
                lo += 1
            distinct_vals = {evs[i].get(dfield) for i in range(lo, hi + 1)}
            if len(distinct_vals) >= count:
                alerts.append(Alert(
                    rule_id=rule["id"], name=rule["name"], attack=rule["attack"],
                    severity=rule.get("severity", "medium"), source=evs[0].get("source", "-"),
                    ts=evs[hi]["ts"], entity=_entity_str(keys, key),
                    count=len(distinct_vals), triage=rule.get("triage", ""),
                    evidence=[f"{dfield}={evs[i].get(dfield)}" for i in range(lo, hi + 1)][:12],
                ))
                break  # one alert per group is enough
    return alerts


def run_sequence(rule: dict, events: list[dict]) -> list[Alert]:
    """
    Ordered steps within a window, grouped by group_by. Each step:
      match     : condition block
      min_count : how many of this step must occur before moving on (default 1)
    The final step must occur after the earlier steps' min_counts are met,
    with the whole chain inside window_seconds.
    """
    keys = rule.get("group_by", [])
    window = float(rule.get("window_seconds", 300))
    steps = rule["steps"]
    # bucket events per group, preserving time order
    groups: dict[tuple, list[dict]] = {}
    for e in events:
        if any(match_block(e, s["match"]) for s in steps):
            groups.setdefault(_group_key(e, keys), []).append(e)

    alerts = []
    for key, evs in groups.items():
        evs.sort(key=lambda x: x["ts"])
        step_idx = 0
        seen = 0
        anchor_ts = None
        chain: list[dict] = []
        for e in evs:
            s = steps[step_idx]
            if match_block(e, s["match"]):
                if anchor_ts is None:
                    anchor_ts = e["ts"]
                # reset if window exceeded
                if e["ts"] - anchor_ts > window:
                    anchor_ts = e["ts"]
                    seen = 0
                    step_idx = 0
                    chain = []
                    s = steps[step_idx]
                    if not match_block(e, s["match"]):
                        continue
                seen += 1
                chain.append(e)
                if seen >= int(s.get("min_count", 1)):
                    step_idx += 1
                    seen = 0
                    if step_idx >= len(steps):
                        alerts.append(Alert(
                            rule_id=rule["id"], name=rule["name"], attack=rule["attack"],
                            severity=rule.get("severity", "medium"),
                            source=chain[-1].get("source", "-"),
                            ts=chain[-1]["ts"], entity=_entity_str(keys, key),
                            count=len(chain), triage=rule.get("triage", ""),
                            evidence=[x.get("raw", "") for x in chain[:6]],
                        ))
                        # reset to allow detecting a later repeat
                        step_idx = 0
                        seen = 0
                        anchor_ts = None
                        chain = []
    return alerts


_RUNNERS = {
    "single": run_single,
    "threshold": run_threshold,
    "distinct": run_distinct,
    "sequence": run_sequence,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def load_rules(rules_dir: str) -> list[dict]:
    rules = []
    for fn in sorted(os.listdir(rules_dir)):
        if fn.endswith((".yml", ".yaml")):
            with open(os.path.join(rules_dir, fn), encoding="utf-8") as f:
                rule = yaml.safe_load(f)
                rule["_file"] = fn
                rules.append(rule)
    return rules


def run_rule(rule: dict, events: list[dict]) -> list[Alert]:
    rtype = rule.get("type", "single")
    runner = _RUNNERS.get(rtype)
    if runner is None:
        raise ValueError(f"Unknown rule type: {rtype} in {rule.get('id')}")
    return runner(rule, events)


def run_all(rules: list[dict], events: list[dict]) -> list[Alert]:
    alerts: list[Alert] = []
    for rule in rules:
        alerts.extend(run_rule(rule, events))
    alerts.sort(key=lambda a: a.ts)
    return alerts
