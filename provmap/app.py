"""FastAPI application: JSON API + D3 UI."""

from __future__ import annotations

from pathlib import Path

from fastapi import Body, FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .demo import DemoProvider, lockfile
from .lockfiles import LockfileError, parse
from .mapper import analyze
from .report import findings_csv, to_markdown

STATIC = Path(__file__).parent / "static"
MAX_TEXT = 20 * 1024 * 1024


def create_app() -> FastAPI:
    app = FastAPI(title="Software Provenance Mapper", version=__version__)

    @app.get("/api/health")
    def health():
        return {"ok": True, "version": __version__}

    @app.post("/api/analyze")
    def api_analyze(filename: str = Body(...), content: str = Body(...), provenance: str = Body("auto")):
        if len(content) > MAX_TEXT:
            raise HTTPException(413, "lockfile too large")
        if provenance not in ("auto", "direct", "all", "none"):
            raise HTTPException(422, "provenance must be auto, direct, all or none")
        try:
            g = parse(filename, content)
        except LockfileError as exc:
            raise HTTPException(422, str(exc)) from exc
        return analyze(g, provenance=provenance)

    @app.get("/api/demo")
    def api_demo():
        return analyze(parse("package-lock.json", lockfile()), DemoProvider(), provenance="all")

    def _render(fn, result):
        try:
            return fn(result)
        except (KeyError, TypeError) as exc:
            raise HTTPException(422, f"not an analysis result: {exc}") from exc

    @app.post("/api/export/report.md", response_class=PlainTextResponse)
    def export_md(result: dict = Body(...)):
        return _render(to_markdown, result)

    @app.post("/api/export/findings.csv", response_class=PlainTextResponse)
    def export_csv(result: dict = Body(...)):
        return _render(findings_csv, result)

    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    return app


app = create_app()
