"""Fictional npm project plus OSV, registry and GitHub responses for it.

Every package name starts with ``demo-`` and every advisory ID with
``DEMO-`` so nothing here can be confused with a real package or advisory.
The lockfile exercises nested ``node_modules`` resolution: two versions of
``demo-tar-stream`` coexist and only the nested one is vulnerable.
"""

from __future__ import annotations

import json
from datetime import date, timedelta

from .evidence import Evidence, sha256_json
from .http import FetchError

TODAY = date.today()


def _d(days_ago: int) -> str:
    return (TODAY - timedelta(days=days_ago)).isoformat() + "T10:00:00.000Z"


# path -> (version, deps, extra)
_TREE = {
    "node_modules/demo-web-framework": ("4.18.2", ["demo-router", "demo-body-parser", "demo-cookie", "demo-debug"], {}),
    "node_modules/demo-router": ("1.3.0", ["demo-path-match", "demo-debug"], {}),
    "node_modules/demo-path-match": ("0.1.7", [], {}),
    "node_modules/demo-body-parser": ("1.20.1", ["demo-bytes", "demo-debug", "demo-qs"], {}),
    "node_modules/demo-bytes": ("3.1.2", [], {}),
    "node_modules/demo-qs": ("6.11.0", ["demo-side-channel"], {}),
    "node_modules/demo-side-channel": ("1.0.4", [], {}),
    "node_modules/demo-cookie": ("0.5.0", [], {}),
    "node_modules/demo-debug": ("2.6.9", ["demo-ms"], {}),
    "node_modules/demo-ms": ("2.0.0", [], {}),
    "node_modules/demo-http-client": ("0.21.1", ["demo-follow-redirects", "demo-form-data"], {}),
    "node_modules/demo-follow-redirects": ("1.15.2", [], {}),
    "node_modules/demo-form-data": ("4.0.0", ["demo-mime-types"], {}),
    "node_modules/demo-mime-types": ("2.1.35", [], {}),
    "node_modules/demo-config-loader": ("2.4.0", ["demo-yaml-parse", "demo-deep-merge"], {}),
    "node_modules/demo-yaml-parse": ("1.2.0", [], {}),
    "node_modules/demo-deep-merge": ("4.2.2", [], {}),
    "node_modules/demo-cli-kit": ("5.1.0", ["demo-yaml-parse", "demo-color-utils", "demo-left-trim"], {}),
    "node_modules/demo-color-utils": ("1.4.0", [], {}),
    "node_modules/demo-left-trim": ("1.0.3", [], {}),
    "node_modules/demo-archive": ("3.2.0", ["demo-tar-stream", "demo-zlib-lite"], {}),
    "node_modules/demo-archive/node_modules/demo-tar-stream": ("2.1.0", ["demo-bl"], {}),
    "node_modules/demo-tar-stream": ("3.0.1", ["demo-bl"], {}),
    "node_modules/demo-bl": ("4.1.0", [], {}),
    "node_modules/demo-zlib-lite": ("1.0.5", [], {}),
    "node_modules/demo-telemetry-helper": ("0.0.9", [], {"hasInstallScript": True}),
    "node_modules/demo-image-resize": ("0.32.6", ["demo-telemetry-helper"], {"hasInstallScript": True}),
    "node_modules/demo-markdown": ("4.0.0", ["demo-entities"], {"dev": True}),
    "node_modules/demo-entities": ("2.1.0", [], {"dev": True}),
    "node_modules/demo-test-runner": ("29.7.0", ["demo-markdown", "demo-debug"], {"dev": True}),
}
_DIRECT = ["demo-web-framework", "demo-http-client", "demo-config-loader", "demo-cli-kit", "demo-archive", "demo-tar-stream",
           "demo-image-resize"]
_DEV = ["demo-test-runner", "demo-markdown"]


def lockfile() -> str:
    pkgs = {"": {"name": "demo-storefront", "version": "1.0.0",
                 "dependencies": {d: "*" for d in _DIRECT}, "devDependencies": {d: "*" for d in _DEV}}}
    for path, (ver, deps, extra) in _TREE.items():
        name = path.rsplit("node_modules/", 1)[-1]
        pkgs[path] = {"version": ver, "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{ver}.tgz",
                      "integrity": "sha512-" + sha256_json([name, ver])[:40], "license": "MIT",
                      **({"dependencies": {d: "*" for d in deps}} if deps else {}), **extra}
    return json.dumps({"name": "demo-storefront", "version": "1.0.0", "lockfileVersion": 3, "requires": True, "packages": pkgs},
                      indent=2)


_VULNS = {
    "DEMO-2026-yaml-1": {
        "pkg": "demo-yaml-parse", "summary": "Prototype pollution via crafted YAML anchors allows remote code execution",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "introduced": "1.0.0", "fixed": "1.2.4", "published": 120},
    "DEMO-2026-http-1": {
        "pkg": "demo-http-client", "summary": "Server-side request forgery when following protocol-relative redirects",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "introduced": "0.8.1", "fixed": "0.21.3", "published": 60,
        "dbsev": "HIGH"},
    "DEMO-2025-tar-1": {
        "pkg": "demo-tar-stream", "summary": "Path traversal when extracting archives with symlink entries",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", "introduced": "0", "fixed": "2.2.0", "published": 400},
    "DEMO-2025-md-1": {
        "pkg": "demo-markdown", "summary": "Cross-site scripting through unsanitised link titles",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "introduced": "3.0.0", "fixed": "4.0.1", "published": 300},
    "DEMO-2024-qs-1": {
        "pkg": "demo-qs", "summary": "Denial of service through deeply nested query strings",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "introduced": "6.0.0", "fixed": "6.11.3", "published": 700},
}
_AFFECTED = {  # name@version -> advisory ids
    "demo-yaml-parse@1.2.0": ["DEMO-2026-yaml-1"], "demo-http-client@0.21.1": ["DEMO-2026-http-1"],
    "demo-tar-stream@2.1.0": ["DEMO-2025-tar-1"], "demo-markdown@4.0.0": ["DEMO-2025-md-1"], "demo-qs@6.11.0": ["DEMO-2024-qs-1"],
}

_META = {  # name -> (maintainers, days since this version, days since latest, latest, repo, deprecated)
    "demo-left-trim": (["solo-dev"], 2900, 2900, "1.0.3", "https://github.com/demo-org/left-trim", ""),
    "demo-telemetry-helper": (["new-account-2026"], 6, 6, "0.0.9", "", ""),
    "demo-color-utils": (["alice", "bob"], 1500, 1500, "1.4.0", "https://github.com/demo-org/color-utils", ""),
    "demo-deep-merge": (["carol"], 1100, 1100, "4.2.2", "https://github.com/demo-org/deep-merge", "Use structuredClone instead"),
    "demo-yaml-parse": (["dan", "erin"], 400, 30, "1.2.5", "https://github.com/demo-org/yaml-parse", ""),
}
_ARCHIVED = {"demo-org/color-utils"}


def _ev(source, payload, rel="A", cred=2) -> Evidence:
    return Evidence(source=f"{source} [demo]", sha256=sha256_json(payload), method="demo", reliability=rel, credibility=cred,
                    note="Synthetic demo data")


class DemoProvider:
    def batch(self, ecosystem, packages):
        res = {"results": [{"vulns": [{"id": i, "modified": _d(5)} for i in _AFFECTED.get(f"{n}@{v}", [])]} for n, v in packages]}
        return {f"{n}@{v}": _AFFECTED[f"{n}@{v}"] for n, v in packages if f"{n}@{v}" in _AFFECTED}, _ev("OSV.dev", res)

    def vuln(self, vid):
        v = _VULNS.get(vid)
        if not v:
            raise FetchError(f"unknown demo advisory {vid}")
        raw = {"id": vid, "summary": v["summary"], "details": v["summary"] + ". (Synthetic advisory for the demo.)",
               "aliases": [], "published": _d(v["published"]), "modified": _d(5),
               "severity": [{"type": "CVSS_V3", "score": v["vector"]}],
               "database_specific": {"severity": v.get("dbsev", "")} if v.get("dbsev") else {},
               "affected": [{"package": {"ecosystem": "npm", "name": v["pkg"]},
                             "ranges": [{"type": "SEMVER", "events": [{"introduced": v["introduced"]}, {"fixed": v["fixed"]}]}]}],
               "references": [{"type": "ADVISORY", "url": f"https://advisories.example/{vid}"}]}
        return raw, _ev("OSV.dev", raw)

    def registry(self, ecosystem, name, version):
        m, age, latest_age, latest, repo, dep = _META.get(name, (["maintainer-a", "maintainer-b"], 200, 90, version,
                                                                 f"https://github.com/demo-org/{name.removeprefix('demo-')}", ""))
        raw = {"name": name, "maintainers": [{"name": x} for x in m], "dist-tags": {"latest": latest},
               "time": {"created": _d(3000), version: _d(age), latest: _d(latest_age)},
               "versions": {version: {"repository": {"type": "git", "url": f"git+{repo}.git"} if repo else None,
                                      "deprecated": dep, "license": "MIT"}}}
        from .sources import parse_registry
        return parse_registry("npm", name, version, raw), _ev("npm registry", raw)

    def github(self, url):
        from .sources import GH_RE, parse_github
        m = GH_RE.search(url or "")
        if not m:
            return None
        full = f"{m.group(1)}/{m.group(2)}"
        raw = {"full_name": full, "archived": full in _ARCHIVED, "stargazers_count": 1200, "open_issues_count": 14,
               "pushed_at": _d(1500 if full in _ARCHIVED else 20), "created_at": _d(3000), "owner": {"type": "Organization"}}
        return parse_github(raw), _ev("GitHub API", raw)
