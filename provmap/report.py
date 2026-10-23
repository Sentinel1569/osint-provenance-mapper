"""Markdown and CSV renderings of an analysis."""

from __future__ import annotations

import csv
import io


def to_markdown(r: dict) -> str:
    s = r["summary"]
    sev = ", ".join(f"{v} {k}" for k, v in sorted(s["by_severity"].items(), key=lambda kv: kv[0])) or "none"
    out = [f"# Dependency provenance report: `{r['root']}`", "",
           f"_{r['ecosystem']} · {r['filename']} · generated {r['generated_at']} UTC_", "",
           f"**{s['packages']}** packages ({s['direct']} direct, max depth {s['max_depth']}) · **{s['advisories']}** advisories in "
           f"**{s['vulnerable_packages']}** packages ({sev}) · {s['install_scripts']} packages run install scripts", ""]
    if r["note"]:
        out += [f"> {r['note']}", ""]
    out += ["## Findings", "", "| Severity | Advisory | Package | Depth | Introduced via | Fix |", "|---|---|---|---:|---|---|"]
    for f in r["findings"]:
        out.append(f"| {f['vuln_severity']} {f['vuln_score'] or ''} | {f['vuln_id']} {f['vuln_cve']} | `{f['package']}`"
                   f"{' (dev)' if f['dev'] else ''} | {f['depth']} | {', '.join(x.split('@')[0] for x in f['introduced_via'])} | {f['fix'] or '—'} |")
    out += ["", "### Propagation paths", ""]
    for f in r["findings"]:
        out.append(f"**{f['vuln_id']}** in `{f['package']}`: {f['vuln_summary']}")
        out += [f"- {' → '.join(p)}" for p in f["paths"][:5]]
        if len(f["paths"]) > 5 or f["paths_truncated"]:
            out.append(f"- … {len(f['paths']) - 5}+ more")
        out += [f"- _Remedy:_ {f['remedy']}", ""]
    if r["blast_radius"]:
        out += ["## Direct dependencies by blast radius", "", "| Direct dependency | Vulnerable packages | Advisories | Worst | Transitive deps |",
                "|---|---:|---:|---|---:|"]
        out += [f"| `{b['direct']}` | {b['packages']} | {b['findings']} | {b['max_severity']} | {b['transitive_size']} |" for b in r["blast_radius"]]
    flagged = [n for n in r["nodes"] if n.get("signals")]
    if flagged:
        out += ["", "## Provenance signals", "", "_Signals are prompts for review, not defects._", "", "| Package | Signals |", "|---|---|"]
        for n in sorted(flagged, key=lambda n: -n["risk"]):
            out.append(f"| `{n['id']}` | {'; '.join(s['title'] for s in n['signals'])} |")
    out += ["", "## Sources", ""] + [f"- {s['source']} · {s['retrieved_at']} · sha256 `{s['sha256'][:16]}…`" for s in r["sources"]]
    if r["errors"]:
        out += ["", "## Collection gaps", ""] + [f"- {e}" for e in r["errors"]]
    return "\n".join(out) + "\n"


def findings_csv(r: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["advisory", "cve", "severity", "score", "package", "version", "direct", "dev", "depth", "introduced_via", "fix", "paths", "summary"])
    for f in r["findings"]:
        w.writerow([f["vuln_id"], f["vuln_cve"], f["vuln_severity"], f["vuln_score"], f["name"], f["version"], f["direct"], f["dev"],
                    f["depth"], " ".join(f["introduced_via"]), f["fix"], len(f["paths"]), f["vuln_summary"]])
    return buf.getvalue()
