"""Compare lab/results/*.txt (wazuh-logtest output) with lab/expected.json. Exit 1 on any mismatch."""
import json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
expected = {k: v for k, v in json.load(open(os.path.join(HERE, "expected.json"), encoding="utf-8")).items() if not k.startswith("_")}


def final_ids(text):
    """Final rule id of each event: the first `id:` after "**Phase 3:" (Phase 2 can also print a decoded `id` field, e.g. HTTP status)."""
    out = []
    for block in text.split("**Phase 1:")[1:]:
        phase3 = block.split("**Phase 3:", 1)
        ids = re.findall(r"\bid: '(\d+)'", phase3[1]) if len(phase3) == 2 else []
        out.append(ids[0] if ids else "-")
    return out


fails = 0
for name, exp in expected.items():
    path = os.path.join(HERE, "results", name + ".txt")
    got = final_ids(open(path, encoding="utf-8", errors="replace").read()) if os.path.exists(path) else []
    ok = len(got) == len(exp)
    for e, g in zip(exp, got):
        ok &= (not g.startswith(e[4:])) if e.startswith("not:") else (g == e)
    fails += not ok
    print(f"{'OK ' if ok else 'KO '} {name:58} {' '.join(got)}")
print(f"\n{len(expected) - fails}/{len(expected)} cases OK")
sys.exit(1 if fails else 0)
