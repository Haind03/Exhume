#!/usr/bin/env python3
"""Compare Exhume reports before/after planting PANIX persistence and print a coverage table.

Usage: evaluate.py expect.tsv installed.tsv baseline.json after.json [summary.md]
Exit 1 when a technique that PANIX installed successfully is not detected.
"""
import json
import sys

SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def load(path):
    return json.load(open(path))["findings"]


def text(f):
    return " ".join([f.get("title", ""), f.get("path") or "", " ".join(f.get("details", []))])


def main():
    expect_p, installed_p, base_p, after_p = sys.argv[1:5]
    summary = sys.argv[5] if len(sys.argv) > 5 else None
    installed = dict(l.rstrip("\n").split("\t") for l in open(installed_p) if "\t" in l)
    base = {(f["title"], f.get("path")) for f in load(base_p)}
    after = [f for f in load(after_p) if (f["title"], f.get("path")) not in base]
    rows, missed, planted = [], [], 0
    for line in open(expect_p):
        if line.startswith("#") or not line.strip():
            continue
        tech, min_sev, prefix, needle = line.rstrip("\n").split("\t")
        rc = installed.get(tech)
        if rc != "0":
            rows.append((tech, "not planted (PANIX rc=%s)" % rc, "-"))
            continue
        planted += 1
        hits = [f for f in after if f["title"].startswith(prefix) and needle in text(f)]
        best = max((SEV[f["severity"]] for f in hits), default=-1)
        if best >= SEV[min_sev]:
            top = max(hits, key=lambda f: SEV[f["severity"]])
            rows.append((tech, "detected", "%s: %s" % (top["severity"].upper(), top["title"])))
        else:
            missed.append(tech)
            got = "below %s" % min_sev if hits else "no finding"
            rows.append((tech, "MISSED", got))
    detected = planted - len(missed)
    out = ["| Technique | Result | Strongest finding |", "| --- | --- | --- |"]
    out += ["| %s | %s | %s |" % r for r in rows]
    out.append("")
    out.append("**%d of %d planted techniques detected.**" % (detected, planted))
    report = "\n".join(out)
    print(report)
    if summary:
        with open(summary, "a") as fh:
            fh.write("## PANIX persistence coverage\n\n" + report + "\n")
    sys.exit(1 if missed else 0)


if __name__ == "__main__":
    main()
