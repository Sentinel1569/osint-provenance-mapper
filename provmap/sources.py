"""OSV vulnerability data, package registry metadata and GitHub repository facts."""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone

from .cvss import base_score, severity
from .evidence import Evidence
from .http import FetchError, fetch_json

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
REGISTRY = {
    "npm": "https://registry.npmjs.org/{name}",
    "PyPI": "https://pypi.org/pypi/{name}/json",
    "crates.io": "https://crates.io/api/v1/crates/{name}",
}


# --------------------------------------------------------------------------- OSV

def osv_batch(ecosystem: str, packages: list[tuple[str, str]]) -> tuple[dict[str, list[str]], Evidence]:
    """Return ``{"name@version": [vuln ids]}`` for a list of (name, version)."""
    out: dict[str, list[str]] = {}
    ev = None
    for i in range(0, len(packages), 500):
        chunk = packages[i:i + 500]
        body = {"queries": [{"package": {"name": n, "ecosystem": ecosystem}, "version": v} for n, v in chunk]}
        data, ev = fetch_json(OSV_BATCH, method="POST", json_body=body, source="OSV.dev", reliability="A", credibility=2, timeout=60)
        for (n, v), res in zip(chunk, data.get("results", [])):
            ids = [x["id"] for x in res.get("vulns", []) or []]
            if ids:
                out[f"{n}@{v}"] = ids
    return out, ev or Evidence(source="OSV.dev", note="no packages queried")


def osv_vuln(vid: str) -> tuple[dict, Evidence]:
    return fetch_json(OSV_VULN + vid, source="OSV.dev", reliability="A", credibility=2, ttl=86400)


def summarise_vuln(v: dict, name: str, ecosystem: str) -> dict:
    """Reduce an OSV record to what the mapper needs, including fixed versions for this package."""
    score = None
    for sev in v.get("severity", []) or []:
        if sev.get("type") == "CVSS_V3":
            score = base_score(sev.get("score", ""))
            if score is not None:
                break
    label = (v.get("database_specific") or {}).get("severity", "")
    label = {"moderate": "medium"}.get(label.lower(), label.lower()) if label else severity(score)
    fixed, introduced = set(), set()
    for aff in v.get("affected", []) or []:
        pkg = aff.get("package", {})
        if pkg.get("name", "").lower() != name.lower() or pkg.get("ecosystem", ecosystem) != ecosystem:
            continue
        for rng in aff.get("ranges", []) or []:
            for e in rng.get("events", []):
                if "fixed" in e:
                    fixed.add(e["fixed"])
                if "introduced" in e and e["introduced"] != "0":
                    introduced.add(e["introduced"])
    aliases = v.get("aliases", []) or []
    return {
        "id": v.get("id", ""), "aliases": aliases, "cve": next((a for a in aliases if a.startswith("CVE-")), ""),
        "summary": v.get("summary") or (v.get("details") or "")[:200], "details": (v.get("details") or "")[:1500],
        "published": (v.get("published") or "")[:10], "modified": (v.get("modified") or "")[:10],
        "score": score, "severity": label or "unknown", "fixed": sorted(fixed, key=_vkey), "introduced": sorted(introduced, key=_vkey),
        "references": [r.get("url") for r in v.get("references", []) or []][:6],
        "withdrawn": bool(v.get("withdrawn")),
    }


def _vkey(v: str):
    return [int(x) if x.isdigit() else x for x in re.split(r"[.\-+]", v)]


# --------------------------------------------------------------------------- registries

def _ts(s: str) -> str:
    return (s or "")[:10]


def parse_registry(ecosystem: str, name: str, version: str, data: dict) -> dict:
    """Normalise registry metadata to {maintainers, published, latest, repository, deprecated, versions}."""
    if ecosystem == "npm":
        times = data.get("time", {})
        vmeta = (data.get("versions") or {}).get(version, {})
        repo = vmeta.get("repository") or data.get("repository") or {}
        return {"maintainers": [m.get("name") or m.get("email", "") for m in data.get("maintainers", [])],
                "published": _ts(times.get(version, "")), "created": _ts(times.get("created", "")),
                "latest": (data.get("dist-tags") or {}).get("latest", ""), "latest_published": _ts(times.get((data.get("dist-tags") or {}).get("latest", ""), "")),
                "repository": repo.get("url", "") if isinstance(repo, dict) else str(repo),
                "deprecated": vmeta.get("deprecated", ""), "license": vmeta.get("license", "") or data.get("license", ""),
                "versions": len(data.get("versions") or {})}
    if ecosystem == "PyPI":
        info = data.get("info", {})
        rel = (data.get("releases") or {}).get(version) or data.get("urls") or []
        urls = info.get("project_urls") or {}
        repo = next((u for k, u in urls.items() if re.search(r"source|repo|code|github", k, re.I)), info.get("home_page") or "")
        latest = info.get("version", "")
        latest_rel = (data.get("releases") or {}).get(latest) or []
        maint = [x for x in (info.get("maintainer"), info.get("author")) if x]
        return {"maintainers": list(dict.fromkeys(maint)), "published": _ts(rel[0].get("upload_time_iso_8601", "") if rel else ""),
                "created": "", "latest": latest, "latest_published": _ts(latest_rel[0].get("upload_time_iso_8601", "") if latest_rel else ""),
                "repository": repo, "deprecated": "yanked" if any(r.get("yanked") for r in rel) else "",
                "license": info.get("license") or "", "versions": len(data.get("releases") or {})}
    if ecosystem == "crates.io":
        c = data.get("crate", {})
        vers = data.get("versions", [])
        this = next((v for v in vers if v.get("num") == version), {})
        return {"maintainers": [this.get("published_by", {}).get("login")] if this.get("published_by") else [],
                "published": _ts(this.get("created_at", "")), "created": _ts(c.get("created_at", "")),
                "latest": c.get("max_stable_version") or c.get("max_version", ""), "latest_published": _ts(c.get("updated_at", "")),
                "repository": c.get("repository") or "", "deprecated": "yanked" if this.get("yanked") else "",
                "license": this.get("license", ""), "versions": len(vers)}
    return {}


def registry_meta(ecosystem: str, name: str, version: str) -> tuple[dict, Evidence]:
    url = REGISTRY[ecosystem].format(name=name.replace("/", "%2f") if ecosystem == "npm" else name)
    data, ev = fetch_json(url, source=f"{ecosystem} registry", reliability="A", credibility=2, ttl=86400)
    return parse_registry(ecosystem, name, version, data), ev


GH_RE = re.compile(r"github\.com[/:]([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+?)(?:\.git)?(?:[/#].*)?$")


def github_repo(url: str) -> tuple[dict, Evidence] | None:
    m = GH_RE.search(url or "")
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    headers = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    try:
        data, ev = fetch_json(f"https://api.github.com/repos/{owner}/{repo}", headers=headers, source="GitHub API",
                              reliability="A", credibility=2, ttl=86400)
    except FetchError:
        return None
    return parse_github(data), ev


def parse_github(d: dict) -> dict:
    return {"full_name": d.get("full_name", ""), "archived": bool(d.get("archived")), "stars": d.get("stargazers_count", 0),
            "open_issues": d.get("open_issues_count", 0), "pushed_at": _ts(d.get("pushed_at", "")),
            "created_at": _ts(d.get("created_at", "")), "owner_type": (d.get("owner") or {}).get("type", ""),
            "default_branch": d.get("default_branch", "")}


def days_since(iso: str, now: datetime | None = None) -> int | None:
    if not iso:
        return None
    now = now or datetime.now(timezone.utc)
    try:
        d = datetime.fromisoformat(iso[:10]).replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return (now - d).days
