#!/usr/bin/env python3
"""
CLI entry point for the offline detection engine.

Usage:
    python -m detector.run                 # run from repo root
    python detector/run.py --html reports/triage.html

Loads YAML rules from detector/rules/, parses the synthetic datasets in
datasets/, runs every rule and prints a triage summary. Optionally writes an
HTML report.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from detector import parsers, engine, report  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(description="Offline SOC detection engine")
    ap.add_argument("--datasets", default=os.path.join(ROOT, "datasets"))
    ap.add_argument("--rules", default=os.path.join(HERE, "rules"))
    ap.add_argument("--html", default=os.path.join(ROOT, "reports", "triage.html"))
    ap.add_argument("--json", default=os.path.join(ROOT, "reports", "alerts.json"))
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    events = parsers.load_all(args.datasets)
    rules = engine.load_rules(args.rules)
    alerts = engine.run_all(rules, events)

    if not args.quiet:
        print(report.console_report(alerts, len(events)))

    os.makedirs(os.path.dirname(args.html), exist_ok=True)
    with open(args.html, "w", encoding="utf-8") as f:
        f.write(report.html_report(alerts, len(events)))
    with open(args.json, "w", encoding="utf-8") as f:
        json.dump([a.to_dict() for a in alerts], f, indent=2)

    if not args.quiet:
        print(f"HTML report : {args.html}")
        print(f"JSON alerts : {args.json}")
    return alerts


if __name__ == "__main__":
    main()
