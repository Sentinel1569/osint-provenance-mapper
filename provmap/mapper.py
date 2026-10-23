"""Combine a dependency graph with vulnerability and provenance data.

Answers three questions for each finding:

1. **What is vulnerable?** (OSV advisory, severity, fixed versions)
2. **How does it get in?** (every path from the project root, its depth and
   the direct dependency responsible)
3. **Who stands behind it?** (maintainers, release recency, repository status
   and install scripts: provenance signals that are worth a second look but
   are not defects in themselves)
"""

from __future__ import annotations

from collections import defaultdict, deque

from .evidence import utcnow
from .http import FetchError
from .sources import _vkey, days_since, github_repo, osv_batch, osv_vuln, registry_meta, summarise_vuln

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0, "unknown": 0}
MAX_PATHS = 25


class LiveProvider:
    def batch(self, ecosystem, packages):
        return osv_batch(ecosystem, packages)

    def vuln(self, vid):
        return osv_vuln(vid)

    def registry(self, ecosystem, name, version):
        return registry_meta(ecosystem, name, version)

    def github(self, url):
        return github_repo(url)


def _adjacency(edges):
    out = defaultdict(list)
    for a, b in edges:
        out[a].append(b)
    return out


def depths(graph: dict) -> dict[str, int]:
    adj = _adjacency(graph["edges"])
    d = {graph["root"]: 0}
    q = deque([graph["root"]])
    while q:
        n = q.popleft()
        for c in adj[n]:
            if c not in d:
                d[c] = d[n] + 1
                q.append(c)
    return d


def paths_to(graph: dict, target: str, limit: int = MAX_PATHS) -> tuple[list[list[str]], bool]:
    """Shortest-first simple paths root → target (BFS over paths, cycle-safe, capped)."""
    adj = _adjacency(graph["edges"])
    out: list[list[str]] = []
    q = deque([[graph["root"]]])
    expansions = 0
    while q and len(out) < limit and expansions < 200_000:
        path = q.popleft()
        expansions += 1
        for c in adj[path[-1]]:
            if c in path:
                continue
            if c == target:
                out.append(path + [c])
            else:
                q.append(path + [c])
    return out, bool(q) and len(out) >= limit


def provenance_signals(meta: dict, repo: dict | None, node: dict) -> list[dict]:
    s = []

    def add(code, weight, title, why):
        s.append({"code": code, "weight": weight, "title": title, "explanation": why})
    if node.get("install_script"):
        add("install_script", 0.35, "Runs an install script", "Code executes automatically at `npm install` time.")
    if not meta:
        return s
    if meta.get("deprecated"):
        add("deprecated", 0.4, "Deprecated / yanked", str(meta["deprecated"])[:160])
    if len(meta.get("maintainers") or []) == 1:
        add("single_maintainer", 0.15, "Single maintainer", f"Only {meta['maintainers'][0]} can publish; one account compromise publishes to every dependent.")
    age = days_since(meta.get("published", ""))
    if age is not None and age <= 14:
        add("fresh_release", 0.3, "Very recent release", f"This version was published {age} day(s) ago. Malicious releases are usually caught within days.")
    latest_age = days_since(meta.get("latest_published", ""))
    if latest_age is not None and latest_age > 730:
        add("stale", 0.2, "No release in 2+ years", f"Latest release is {latest_age // 365} years old; fixes may never ship.")
    if meta.get("latest") and meta["latest"] != node["version"]:
        add("outdated", 0.05, "Not the latest version", f"Locked {node['version']}, latest is {meta['latest']}.")
    if not meta.get("repository"):
        add("no_repository", 0.2, "No source repository linked", "The published artefact cannot be traced to public source code.")
    if repo and repo.get("archived"):
        add("archived", 0.3, "Repository archived", f"{repo['full_name']} is archived: no maintenance expected.")
    return s


def analyze(graph: dict, provider=None, *, provenance: str = "auto", max_meta: int = 150) -> dict:
    provider = provider or LiveProvider()
    eco = graph["ecosystem"]
    nodes = graph["nodes"]
    pkgs = [(n["name"], n["version"]) for nid, n in nodes.items() if not n.get("root")]
    sources, errors = [], []
    try:
        hits, ev = provider.batch(eco, pkgs)
        sources.append(ev.to_dict())
    except FetchError as exc:
        hits = {}
        errors.append(f"OSV: {exc}")

    detail_cache: dict[str, dict] = {}
    for nid, n in nodes.items():
        n["vulns"] = []
        for vid in hits.get(nid, []):
            if vid not in detail_cache:
                try:
                    raw, ev = provider.vuln(vid)
                    detail_cache[vid] = raw
                except FetchError as exc:
                    errors.append(f"OSV {vid}: {exc}")
                    detail_cache[vid] = {"id": vid}
            v = summarise_vuln(detail_cache[vid], n["name"], eco)
            if not v["withdrawn"]:
                n["vulns"].append(v)

    dep = depths(graph)
    vulnerable = [nid for nid, n in nodes.items() if n["vulns"]]
    direct = [c for p, c in graph["edges"] if p == graph["root"]]

    # provenance metadata
    want = set()
    if provenance == "all" or (provenance == "auto" and len(nodes) <= max_meta):
        want = {nid for nid in nodes if not nodes[nid].get("root")}
    elif provenance in ("auto", "direct"):
        want = set(direct) | set(vulnerable)
    for nid in sorted(want, key=lambda x: dep.get(x, 99))[:max_meta]:
        n = nodes[nid]
        try:
            meta, ev = provider.registry(eco, n["name"], n["version"])
            n["meta"] = meta
            n["meta_source"] = ev.to_dict()
        except (FetchError, KeyError) as exc:
            n["meta"] = {}
            errors.append(f"registry {nid}: {exc}")
            continue
        gh = provider.github(meta.get("repository", "")) if meta.get("repository") else None
        n["repo"] = gh[0] if gh else None
    for nid, n in nodes.items():
        n["depth"] = dep.get(nid)
        n["signals"] = provenance_signals(n.get("meta") or {}, n.get("repo"), n) if not n.get("root") else []
        n["risk"] = round(1 - _prod(1 - s["weight"] for s in n["signals"]), 3)

    findings = []
    for nid in vulnerable:
        n = nodes[nid]
        ps, truncated = paths_to(graph, nid)
        via = sorted({p[1] for p in ps if len(p) > 1})
        for v in n["vulns"]:
            newer = [f for f in v["fixed"] if _vkey(f) > _vkey(n["version"])]
            fix = newer[0] if newer else (v["fixed"][-1] if v["fixed"] else "")
            if not fix:
                remedy = "No fixed version published. Consider replacing the package or mitigating."
            elif n.get("direct"):
                remedy = f"Upgrade {n['name']} to ≥ {fix}."
            else:
                remedy = (f"Transitive: needs {n['name']} ≥ {fix}. Upgrade {', '.join(nodes[x]['name'] for x in via[:3])} to a release that "
                          f"allows it, or pin it with an override/resolution.")
            findings.append({"package": nid, "name": n["name"], "version": n["version"], "direct": n.get("direct", False),
                             "dev": n.get("dev", False), "depth": n["depth"], "paths": ps, "paths_truncated": truncated,
                             "introduced_via": via, "fix": fix, "remedy": remedy, **{f"vuln_{k}": val for k, val in v.items()}})
    findings.sort(key=lambda f: (-SEV_RANK.get(f["vuln_severity"], 0), f["depth"] or 0, f["package"]))

    blast = []
    for d in direct:
        reach = _reachable(graph, d)
        vs = [f for f in findings if f["package"] in reach]
        if vs:
            blast.append({"direct": d, "findings": len(vs), "packages": len({f["package"] for f in vs}),
                          "max_severity": max((f["vuln_severity"] for f in vs), key=lambda s: SEV_RANK.get(s, 0)),
                          "transitive_size": len(reach) - 1})
    blast.sort(key=lambda b: (-SEV_RANK.get(b["max_severity"], 0), -b["findings"]))

    sev_counts = defaultdict(int)
    for f in findings:
        sev_counts[f["vuln_severity"]] += 1
    signals = defaultdict(int)
    for n in nodes.values():
        for s in n["signals"]:
            signals[s["code"]] += 1
    return {
        "generated_at": utcnow(), "ecosystem": eco, "format": graph.get("format"), "filename": graph.get("filename"),
        "root": graph["root"], "note": graph.get("note", ""), "unpinned": graph.get("unpinned", []),
        "nodes": list(nodes.values()), "edges": graph["edges"], "findings": findings, "blast_radius": blast,
        "summary": {"packages": len(nodes) - 1, "direct": len(direct), "max_depth": max(dep.values()) if dep else 0,
                    "vulnerable_packages": len(vulnerable), "advisories": len(findings), "by_severity": dict(sev_counts),
                    "signals": dict(signals), "install_scripts": sum(1 for n in nodes.values() if n.get("install_script"))},
        "sources": sources, "errors": errors,
    }


def _reachable(graph, start):
    adj = _adjacency(graph["edges"])
    seen, stack = {start}, [start]
    while stack:
        for c in adj[stack.pop()]:
            if c not in seen:
                seen.add(c)
                stack.append(c)
    return seen


def _prod(xs):
    p = 1.0
    for x in xs:
        p *= x
    return p
