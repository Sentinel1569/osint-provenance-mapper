"""Lockfile parsers → a normalised dependency graph.

Supported formats:

* ``package-lock.json`` (npm lockfile v1, v2 and v3, including nested
  ``node_modules`` resolution)
* ``poetry.lock`` and ``Cargo.lock`` (TOML ``[[package]]`` tables)
* ``requirements.txt`` (pinned ``==`` lines, flat, since the file has no edges)

Graph shape::

    {"ecosystem": "npm", "root": "app@1.0.0",
     "nodes": {"pkg@ver": {"name", "version", "direct", "dev", "install_script", ...}},
     "edges": [["parent@ver", "child@ver"], ...]}
"""

from __future__ import annotations

import json
import re

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]


class LockfileError(ValueError):
    pass


def _node(name, version, **extra) -> dict:
    return {"id": f"{name}@{version}", "name": name, "version": version, "direct": False, "dev": False,
            "install_script": False, **extra}


def detect_format(filename: str, text: str) -> str:
    f = filename.lower()
    if f.endswith("package-lock.json") or f.endswith("npm-shrinkwrap.json"):
        return "npm"
    if f.endswith("poetry.lock"):
        return "poetry"
    if f.endswith("cargo.lock"):
        return "cargo"
    if f.endswith(".txt") or "requirements" in f:
        return "requirements"
    s = text.lstrip()
    if s.startswith("{") and '"lockfileVersion"' in s:
        return "npm"
    if "[[package]]" in s:
        return "cargo" if "checksum" in s and "source = \"registry+" in s else "poetry"
    if re.search(r"^[A-Za-z0-9_.\-\[\]]+==", s, re.M):
        return "requirements"
    raise LockfileError(f"cannot recognise lockfile format of {filename!r}")


# --------------------------------------------------------------------------- npm

def parse_npm(text: str) -> dict:
    try:
        lock = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LockfileError(f"invalid JSON: {exc}") from exc
    root_name = lock.get("name") or "root"
    root_ver = lock.get("version") or "0.0.0"
    root_id = f"{root_name}@{root_ver}"
    nodes = {root_id: {**_node(root_name, root_ver), "root": True}}
    edges: list[list[str]] = []

    if "packages" in lock:  # v2 / v3
        pkgs = lock["packages"]
        path_to_id: dict[str, str] = {}
        for path, meta in pkgs.items():
            if not path:
                continue
            name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
            ver = meta.get("version", "0.0.0")
            if meta.get("link"):
                continue
            nid = f"{name}@{ver}"
            path_to_id[path] = nid
            n = nodes.setdefault(nid, _node(name, ver, resolved=meta.get("resolved", ""), integrity=meta.get("integrity", ""),
                                            license=meta.get("license", ""), paths=[]))
            n["dev"] = n["dev"] or bool(meta.get("dev") or meta.get("devOptional"))
            n["install_script"] = n["install_script"] or bool(meta.get("hasInstallScript"))
            n.setdefault("paths", []).append(path)

        def resolve(from_path: str, dep: str) -> str | None:
            base = from_path
            while True:
                cand = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
                if cand in path_to_id:
                    return path_to_id[cand]
                if not base:
                    return None
                idx = base.rfind("/node_modules/")
                base = base[:idx] if idx >= 0 else ""

        root_meta = pkgs.get("", {})
        for kind in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            for dep in root_meta.get(kind, {}) or {}:
                cid = resolve("", dep)
                if cid:
                    edges.append([root_id, cid])
                    nodes[cid]["direct"] = True
        for path, meta in pkgs.items():
            if not path or path not in path_to_id:
                continue
            for kind in ("dependencies", "optionalDependencies", "peerDependencies"):
                for dep in meta.get(kind, {}) or {}:
                    cid = resolve(path, dep)
                    if cid:
                        edges.append([path_to_id[path], cid])
    elif "dependencies" in lock:  # v1: nested tree with "requires"
        def walk(deps: dict, parent_id: str, scope: list[dict]):
            for name, meta in deps.items():
                nid = f"{name}@{meta.get('version', '0.0.0')}"
                n = nodes.setdefault(nid, _node(name, meta.get("version", "0.0.0"), resolved=meta.get("resolved", "")))
                n["dev"] = n["dev"] or bool(meta.get("dev"))
                if parent_id == root_id:
                    n["direct"] = True
                    edges.append([root_id, nid])
            for name, meta in deps.items():
                nid = f"{name}@{meta.get('version', '0.0.0')}"
                local = [meta.get("dependencies", {})] + scope
                for req in meta.get("requires", {}) or {}:
                    target = next((d[req] for d in local if req in d), None)
                    if target:
                        edges.append([nid, f"{req}@{target.get('version', '0.0.0')}"])
                if meta.get("dependencies"):
                    walk(meta["dependencies"], nid, local)
        walk(lock["dependencies"], root_id, [lock["dependencies"]])
        # in v1 every top-level entry is hoisted; only the ones in package.json are truly direct, unknown here
    else:
        raise LockfileError("package-lock.json has neither 'packages' nor 'dependencies'")
    return {"ecosystem": "npm", "root": root_id, "nodes": nodes, "edges": _dedupe(edges)}


# --------------------------------------------------------------------------- TOML locks

def _toml_graph(text: str, ecosystem: str, root_name: str) -> dict:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise LockfileError(f"invalid TOML: {exc}") from exc
    pkgs = data.get("package", [])
    by_name: dict[str, list[dict]] = {}
    for p in pkgs:
        by_name.setdefault(p["name"].lower(), []).append(p)
    root_id = f"{root_name}@0.0.0"
    nodes = {root_id: {**_node(root_name, "0.0.0"), "root": True}}
    edges: list[list[str]] = []
    for p in pkgs:
        nid = f"{p['name']}@{p['version']}"
        nodes[nid] = _node(p["name"], p["version"], dev=p.get("category") == "dev" or "dev" in (p.get("groups") or []))
    for p in pkgs:
        nid = f"{p['name']}@{p['version']}"
        deps = p.get("dependencies", {})
        items = deps.items() if isinstance(deps, dict) else [(d.split()[0], d.split()[1] if len(d.split()) > 1 else None) for d in deps]
        for dname, spec in items:
            cands = by_name.get(dname.lower().replace("_", "-")) or by_name.get(dname.lower()) or []
            if not cands:
                continue
            version = spec if isinstance(spec, str) and cands and any(c["version"] == spec for c in cands) else cands[0]["version"]
            edges.append([nid, f"{cands[0]['name']}@{version}"])
    targets = {c for _, c in edges}
    for nid, n in nodes.items():
        if nid != root_id and nid not in targets:
            n["direct"] = True
            edges.append([root_id, nid])
    return {"ecosystem": ecosystem, "root": root_id, "nodes": nodes, "edges": _dedupe(edges)}


def parse_poetry(text: str) -> dict:
    g = _toml_graph(text, "PyPI", "project")
    g["note"] = "poetry.lock does not record which packages are direct; packages nothing else depends on are treated as direct."
    return g


def parse_cargo(text: str) -> dict:
    g = _toml_graph(text, "crates.io", "crate")
    # In Cargo.lock the workspace crate itself has no `source`; make it the root.
    data = tomllib.loads(text)
    local = [p for p in data.get("package", []) if "source" not in p]
    if local:
        rid = f"{local[0]['name']}@{local[0]['version']}"
        g["nodes"].pop(g["root"], None)
        g["edges"] = [e for e in g["edges"] if e[0] != g["root"]]
        g["root"] = rid
        g["nodes"][rid]["root"] = True
        g["nodes"][rid]["direct"] = False
        for _, c in [e for e in g["edges"] if e[0] == rid]:
            g["nodes"][c]["direct"] = True
        targets = {c for _, c in g["edges"]}
        for nid, n in g["nodes"].items():
            if nid != rid and nid not in targets:
                n["direct"] = True
                g["edges"].append([rid, nid])
    return g


# --------------------------------------------------------------------------- requirements

REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)(\[[^\]]*\])?\s*==\s*([A-Za-z0-9.!+_\-]+)")


def parse_requirements(text: str) -> dict:
    root_id = "requirements@0.0.0"
    nodes = {root_id: {**_node("requirements", "0.0.0"), "root": True}}
    edges, unpinned = [], []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "--")):
            continue
        m = REQ_RE.match(line)
        if not m:
            unpinned.append(line)
            continue
        name, ver = m.group(1), m.group(3)
        nid = f"{name}@{ver}"
        nodes[nid] = _node(name, ver, direct=True)
        edges.append([root_id, nid])
    return {"ecosystem": "PyPI", "root": root_id, "nodes": nodes, "edges": edges, "unpinned": unpinned,
            "note": "requirements.txt is flat: transitive structure is unknown unless generated with pip-compile."}


def parse(filename: str, text: str) -> dict:
    fmt = detect_format(filename, text)
    g = {"npm": parse_npm, "poetry": parse_poetry, "cargo": parse_cargo, "requirements": parse_requirements}[fmt](text)
    g["format"] = fmt
    g["filename"] = filename
    return g


def _dedupe(edges):
    seen, out = set(), []
    for e in edges:
        t = tuple(e)
        if t not in seen and e[0] != e[1]:
            seen.add(t)
            out.append(e)
    return out
