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
               grouped by `group_by`. Evaluated by LOOK-BACK from every event
               that matches the final step: the earlier steps must have been
               satisfied, in order, inside the `window_seconds` that end at
               that event. Steps may declare `alias: {key: field}` so that
               the same correlation key is read from a different field in
               each step (like Sigma correlation aliases), e.g. the account
               SID is TargetSid in 4720 but MemberSid in 4732.

Field matching operators (per condition):
  equals, not_equals, in, contains, icontains (case-insensitive contains),
  regex, startswith, exists.

Match blocks are {all: [...]} and/or {any: [...]}. An item of a list can
itself be a nested block ({all: ...} / {any: ...}), which allows
"A and (B or (C and D))".

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


def _match_item(event: dict, item) -> bool:
    if isinstance(item, dict) and "field" in item:
        return match_condition(event, item)
    return match_block(event, item)


def match_block(event: dict, block) -> bool:
    """A match block is {all: [...]} and/or {any: [...]}. Items may be
    conditions or nested blocks. A bare list is treated as "all"."""
    if not block:
        return True
    if isinstance(block, list):
        return all(_match_item(event, c) for c in block)
    ok = True
    if "all" in block:
        ok = ok and all(_match_item(event, c) for c in block["all"])
    if "any" in block:
        ok = ok and any(_match_item(event, c) for c in block["any"])
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
            # The alert is raised when the threshold is crossed (evs[hi]); the
            # reported count is every matching event in the window that starts
            # at the first event of the triggering burst.
            end = hi
            while end + 1 < len(evs) and evs[end + 1]["ts"] - evs[lo]["ts"] <= window:
                end += 1
            window_evs = evs[lo:end + 1]
            alerts.append(Alert(
                rule_id=rule["id"], name=rule["name"], attack=rule["attack"],
                severity=rule.get("severity", "medium"), source=evs[0].get("source", "-"),
                ts=evs[hi]["ts"], entity=_entity_str(keys, key),
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
                # report every distinct value seen in the window anchored at lo
                end = hi
                while end + 1 < len(evs) and evs[end + 1]["ts"] - evs[lo]["ts"] <= window:
                    end += 1
                all_vals = [evs[i].get(dfield) for i in range(lo, end + 1)]
                alerts.append(Alert(
                    rule_id=rule["id"], name=rule["name"], attack=rule["attack"],
                    severity=rule.get("severity", "medium"), source=evs[0].get("source", "-"),
                    ts=evs[hi]["ts"], entity=_entity_str(keys, key),
                    count=len(set(all_vals)), triage=rule.get("triage", ""),
                    evidence=[f"{dfield}={v}" for v in all_vals][:12],
                ))
                break  # one alert per group is enough
    return alerts


def _step_key(event: dict, keys: list[str], step: dict) -> tuple:
    alias = step.get("alias", {}) or {}
    return tuple(event.get(alias.get(k, k)) for k in keys)


def run_sequence(rule: dict, events: list[dict]) -> list[Alert]:
    """
    Ordered steps, grouped by group_by. Each step:
      match     : condition block
      min_count : how many events of this step are required (default 1)
      alias     : optional {group_key: field_name} for this step

    For every event E that matches the LAST step, look back over the events
    in [E.ts - window_seconds, E.ts] that share E's correlation key. Walking
    backwards, the step before the last must be satisfied min_count times,
    then the step before it (strictly earlier), and so on. If every step is
    satisfied, one alert is raised at E. Consequences:
      - order matters: a success BEFORE the failures does not fire;
      - the window ends at the final event, so old failures expire;
      - every final-step event that completes the chain is its own alert.
    The reported count is every event in that window (same key) that matches
    one of the earlier steps, plus E itself.
    """
    keys = rule.get("group_by", [])
    window = float(rule.get("window_seconds", 300))
    steps = rule["steps"]
    final = len(steps) - 1

    # (event, step_index, key) for every (event, step) pair that matches
    tagged: list[tuple[dict, int, tuple]] = []
    for e in sorted(events, key=lambda x: x["ts"]):
        for i, s in enumerate(steps):
            if match_block(e, s["match"]):
                tagged.append((e, i, _step_key(e, keys, s)))

    alerts = []
    for pos, (e, si, key) in enumerate(tagged):
        if si != final:
            continue
        if keys and all(v is None for v in key):
            continue  # no correlation key -> cannot correlate
        start = e["ts"] - window
        prior = [(x, xi) for (x, xi, xk) in tagged[:pos]
                 if xk == key and xi < final and x is not e and start <= x["ts"] <= e["ts"]]
        need = final - 1  # index of the step we are trying to satisfy
        seen = 0
        for x, xi in reversed(prior):
            if need < 0:
                break
            if xi == need:
                seen += 1
                if seen >= int(steps[need].get("min_count", 1)):
                    need -= 1
                    seen = 0
        if need >= 0:
            continue
        chain = [x for x, _ in prior] + [e]
        evidence = [x.get("raw", "") for x in chain]
        if len(evidence) > 6:
            evidence = evidence[:5] + [evidence[-1]]
        alerts.append(Alert(
            rule_id=rule["id"], name=rule["name"], attack=rule["attack"],
            severity=rule.get("severity", "medium"), source=e.get("source", "-"),
            ts=e["ts"], entity=_entity_str(keys, key),
            count=len(chain), triage=rule.get("triage", ""),
            evidence=evidence,
        ))
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
