import json

import pytest
from fastapi.testclient import TestClient

from provmap.app import app
from provmap.cvss import base_score, severity
from provmap.demo import DemoProvider, lockfile
from provmap.lockfiles import LockfileError, detect_format, parse
from provmap.mapper import analyze, paths_to
from provmap.report import findings_csv, to_markdown
from provmap.sources import parse_github, parse_registry, summarise_vuln


@pytest.mark.parametrize("vector,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
    ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
])
def test_cvss(vector, score):
    assert base_score(vector) == score


def test_cvss_bad_input():
    assert base_score("garbage") is None and base_score("CVSS:3.1/AV:X") is None
    assert severity(9.8) == "critical" and severity(None) == "unknown"


def test_npm_v3_nested_resolution():
    g = parse("package-lock.json", lockfile())
    assert g["format"] == "npm" and g["root"] == "demo-storefront@1.0.0"
    edges = {tuple(e) for e in g["edges"]}
    assert ("demo-archive@3.2.0", "demo-tar-stream@2.1.0") in edges        # nested copy wins for demo-archive
    assert ("demo-storefront@1.0.0", "demo-tar-stream@3.0.1") in edges      # root gets the hoisted copy
    assert g["nodes"]["demo-telemetry-helper@0.0.9"]["install_script"]
    assert g["nodes"]["demo-markdown@4.0.0"]["dev"]


def test_npm_v1():
    lock = {"name": "app", "version": "1.0.0", "lockfileVersion": 1, "dependencies": {
        "a": {"version": "1.0.0", "requires": {"b": "^2"}},
        "b": {"version": "2.0.0"},
        "c": {"version": "1.0.0", "requires": {"b": "^1"}, "dependencies": {"b": {"version": "1.5.0"}}}}}
    g = parse("package-lock.json", json.dumps(lock))
    edges = {tuple(e) for e in g["edges"]}
    assert ("a@1.0.0", "b@2.0.0") in edges and ("c@1.0.0", "b@1.5.0") in edges


def test_poetry_and_cargo_and_requirements():
    poetry = '''
[[package]]
name = "requests"
version = "2.31.0"
[package.dependencies]
urllib3 = ">=1.21.1,<3"
idna = "*"

[[package]]
name = "urllib3"
version = "2.0.7"

[[package]]
name = "idna"
version = "3.6"
'''
    g = parse("poetry.lock", poetry)
    assert g["ecosystem"] == "PyPI"
    assert {tuple(e) for e in g["edges"]} >= {("requests@2.31.0", "urllib3@2.0.7"), ("project@0.0.0", "requests@2.31.0")}
    assert not g["nodes"]["urllib3@2.0.7"]["direct"]
    cargo = '''
[[package]]
name = "myapp"
version = "0.1.0"
dependencies = ["serde", "rand 0.8.5"]

[[package]]
name = "serde"
version = "1.0.190"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aa"

[[package]]
name = "rand"
version = "0.8.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bb"
'''
    g = parse("Cargo.lock", cargo)
    assert g["root"] == "myapp@0.1.0" and g["nodes"]["serde@1.0.190"]["direct"]
    r = parse("requirements.txt", "django==4.2.1  # web\nrequests>=2\n-r other.txt\nnumpy[extra]==1.26.0\n")
    assert set(r["nodes"]) == {"requirements@0.0.0", "django@4.2.1", "numpy@1.26.0"} and r["unpinned"] == ["requests>=2"]
    with pytest.raises(LockfileError):
        detect_format("weird.bin", "hello")


def test_osv_summary_picks_fix_for_this_package():
    raw, _ = DemoProvider().vuln("DEMO-2026-yaml-1")
    v = summarise_vuln(raw, "demo-yaml-parse", "npm")
    assert v["fixed"] == ["1.2.4"] and v["score"] == 9.8 and v["severity"] == "critical"
    assert summarise_vuln(raw, "other", "npm")["fixed"] == []


def test_registry_and_github_parsers():
    m = parse_registry("PyPI", "x", "1.0", {"info": {"version": "1.1", "author": "A", "project_urls": {"Source": "https://github.com/o/x"}},
                                           "releases": {"1.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00Z"}], "1.1": []}})
    assert m["repository"] == "https://github.com/o/x" and m["published"] == "2020-01-01" and m["latest"] == "1.1"
    assert parse_github({"full_name": "o/x", "archived": True})["archived"]


def test_demo_analysis():
    r = analyze(parse("package-lock.json", lockfile()), DemoProvider(), provenance="all")
    assert r["summary"]["advisories"] == 5
    top = r["findings"][0]
    assert top["vuln_severity"] == "critical" and top["name"] == "demo-yaml-parse"
    assert len(top["paths"]) == 2 and set(x.split("@")[0] for x in top["introduced_via"]) == {"demo-config-loader", "demo-cli-kit"}
    assert "Transitive" in top["remedy"]
    http = next(f for f in r["findings"] if f["name"] == "demo-http-client")
    assert http["remedy"] == "Upgrade demo-http-client to ≥ 0.21.3."
    tar = next(f for f in r["findings"] if f["name"] == "demo-tar-stream")
    assert tar["version"] == "2.1.0" and tar["paths"] == [["demo-storefront@1.0.0", "demo-archive@3.2.0", "demo-tar-stream@2.1.0"]]
    nodes = {n["id"]: n for n in r["nodes"]}
    codes = {s["code"] for s in nodes["demo-telemetry-helper@0.0.9"]["signals"]}
    assert {"install_script", "fresh_release", "no_repository", "single_maintainer"} <= codes
    assert "archived" in {s["code"] for s in nodes["demo-color-utils@1.4.0"]["signals"]}
    assert r["blast_radius"][0]["max_severity"] == "critical"
    assert "## Findings" in to_markdown(r) and findings_csv(r).count("\n") == 6


def test_paths_handle_cycles():
    g = {"root": "r", "edges": [["r", "a"], ["a", "b"], ["b", "a"], ["b", "c"]], "nodes": {}}
    ps, _ = paths_to(g, "c")
    assert ps == [["r", "a", "b", "c"]]


def test_api():
    c = TestClient(app)
    d = c.get("/api/demo").json()
    assert d["summary"]["packages"] == 30
    assert c.post("/api/analyze", json={"filename": "x.bin", "content": "nope"}).status_code == 422
    assert c.post("/api/analyze", json={"filename": "a", "content": "{}", "provenance": "bad"}).status_code == 422
    assert c.post("/api/export/report.md", json=d).status_code == 200
    assert c.post("/api/export/findings.csv", json={}).status_code == 422
    assert c.get("/").status_code == 200
