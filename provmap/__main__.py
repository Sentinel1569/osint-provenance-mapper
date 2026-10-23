"""Command-line interface.

    python -m provmap scan package-lock.json [--provenance auto|direct|all|none] [--json | --markdown | --csv]
    python -m provmap scan poetry.lock / Cargo.lock / requirements.txt
    python -m provmap demo [--write samples/]
    python -m provmap serve

Exit status is 1 when findings at or above --fail-on are present, for CI use.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .demo import DemoProvider, lockfile
from .lockfiles import LockfileError, parse
from .mapper import SEV_RANK, analyze
from .report import findings_csv, to_markdown


def _summary(r: dict) -> None:
    s = r["summary"]
    print(f"\n  {r['root']} · {s['packages']} packages · {s['advisories']} advisories in {s['vulnerable_packages']} packages\n")
    for f in r["findings"]:
        print(f"  [{f['vuln_severity']:>8}] {f['vuln_id']:<18} {f['package']:<34} depth {f['depth']}  fix {f['fix'] or '—'}")
        for p in f["paths"][:3]:
            print(f"             {' → '.join(x.split('@')[0] for x in p)}")
    flagged = [n for n in r["nodes"] if n.get("signals")]
    if flagged:
        print("\n  Provenance signals:")
        for n in sorted(flagged, key=lambda n: -n["risk"])[:12]:
            print(f"   {n['id']:<34} {'; '.join(x['title'] for x in n['signals'])}")
    for e in r["errors"]:
        print(f"  ! {e}")
    print()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="provmap", description="Open-Source Software Provenance Mapper")
    sub = p.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan", help="analyse a lockfile")
    sc.add_argument("lockfile")
    sc.add_argument("--provenance", default="auto", choices=["auto", "direct", "all", "none"])
    sc.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], help="exit 1 if a finding is at least this severe")
    g = sc.add_mutually_exclusive_group()
    g.add_argument("--json", action="store_true")
    g.add_argument("--markdown", action="store_true")
    g.add_argument("--csv", action="store_true")
    d = sub.add_parser("demo", help="analyse the bundled fictional project")
    d.add_argument("--write", metavar="DIR")
    s = sub.add_parser("serve", help="start the web UI")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--reload", action="store_true")
    a = p.parse_args(argv)

    if a.cmd == "serve":
        import uvicorn
        uvicorn.run("provmap.app:app", host=a.host, port=a.port, reload=a.reload)
        return 0
    if a.cmd == "demo":
        if a.write:
            Path(a.write).mkdir(parents=True, exist_ok=True)
            (Path(a.write) / "package-lock.json").write_text(lockfile())
            print(f"wrote {a.write}/package-lock.json")
            return 0
        _summary(analyze(parse("package-lock.json", lockfile()), DemoProvider(), provenance="all"))
        return 0
    try:
        graph = parse(Path(a.lockfile).name, Path(a.lockfile).read_text(encoding="utf-8"))
    except (OSError, LockfileError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    r = analyze(graph, provenance=a.provenance)
    if a.json:
        json.dump(r, sys.stdout, indent=2)
    elif a.markdown:
        sys.stdout.write(to_markdown(r))
    elif a.csv:
        sys.stdout.write(findings_csv(r))
    else:
        _summary(r)
    if a.fail_on and any(SEV_RANK.get(f["vuln_severity"], 0) >= SEV_RANK[a.fail_on] for f in r["findings"]):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
