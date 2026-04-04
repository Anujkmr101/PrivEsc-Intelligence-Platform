"""
pip/api/server.py

REST API Server.

Exposes PIP scan functionality over HTTP/HTTPS for integration with:
  - CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins)
  - SIEM platforms (Splunk, ELK)
  - Security dashboards and orchestration tools

All endpoints require JWT or API-key authentication unless auth=none
(development only).

Run with:
    python pip.py serve --host 0.0.0.0 --port 8443 --auth jwt
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel, Field

from pip.api.auth import get_auth_dependency
from pip.models.context import ScanConfig, ScanMode, StealthProfile, ReportType


# ── Request / Response models ─────────────────────────────────────────────────

class ScanRequest(BaseModel):
    mode:            ScanMode       = Field(ScanMode.DEEP,   description="Scan depth profile.")
    stealth:         StealthProfile = Field(StealthProfile.NORMAL, description="Noise control profile.")
    report_types:    list[ReportType] = Field(default_factory=lambda: [ReportType.ALL])
    mitre_map:       bool           = Field(True)
    blue_team:       bool           = Field(False)
    timeout:         int            = Field(300, ge=30, le=3600)
    no_disk:         bool           = Field(False)
    exploit_enabled: bool           = Field(False)


class ScanResponse(BaseModel):
    scan_id:       str
    status:        str
    risk_level:    str | None = None
    root_possible: bool = False
    paths_found:   int  = 0
    verified:      int  = 0
    top_score:     float = 0.0
    report_url:    str | None = None


class HealthResponse(BaseModel):
    status:  str = "ok"
    version: str = "2.0.0"


# ── App factory ───────────────────────────────────────────────────────────────

def create_app(auth_method: str = "jwt") -> FastAPI:
    """
    Build and return the FastAPI application.

    Args:
        auth_method: "jwt" | "apikey" | "none"
    """
    app = FastAPI(
        title="PIP — PrivEsc Intelligence Platform",
        description="REST API for the PIP Linux privilege escalation intelligence toolkit.",
        version="2.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    auth_dep = get_auth_dependency(auth_method)

    # ── Routes ─────────────────────────────────────────────────────────────────

    @app.get("/health", response_model=HealthResponse, tags=["system"])
    async def health():
        """Liveness check. No authentication required."""
        return HealthResponse()

    @app.post("/scan", response_model=ScanResponse, tags=["scan"],
              dependencies=[Depends(auth_dep)])
    async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
        """
        Start a new privilege escalation scan.

        Returns a scan_id immediately. The scan runs in the background.
        Poll /scan/{scan_id} for results, or use /scan/{scan_id}/stream
        for real-time JSON streaming.
        """
        import uuid
        scan_id = str(uuid.uuid4())[:8]
        output_dir = Path(f"/tmp/pip-scans/{scan_id}")
        output_dir.mkdir(parents=True, exist_ok=True)

        config = ScanConfig(
            mode=request.mode,
            stealth=request.stealth,
            report_types=request.report_types,
            mitre_map=request.mitre_map,
            blue_team=request.blue_team,
            timeout=request.timeout,
            no_disk=request.no_disk,
            exploit_enabled=False,  # API never permits exploit execution
            output_dir=output_dir,
        )

        background_tasks.add_task(_run_scan_background, scan_id, config)

        return ScanResponse(scan_id=scan_id, status="running")

    @app.get("/scan/{scan_id}", response_model=ScanResponse, tags=["scan"],
             dependencies=[Depends(auth_dep)])
    async def get_scan(scan_id: str):
        """
        Poll the status and results of a running or completed scan.
        Returns a 404 if the scan_id is unknown.
        """
        result_path = Path(f"/tmp/pip-scans/{scan_id}/result.json")
        if not result_path.exists():
            status_path = Path(f"/tmp/pip-scans/{scan_id}")
            if not status_path.exists():
                raise HTTPException(status_code=404, detail="Scan not found.")
            return ScanResponse(scan_id=scan_id, status="running")

        result = json.loads(result_path.read_text())
        return ScanResponse(scan_id=scan_id, status="complete", **result)

    @app.get("/scan/{scan_id}/stream", tags=["scan"],
             dependencies=[Depends(auth_dep)])
    async def stream_scan(scan_id: str):
        """
        Server-Sent Events stream of scan progress.

        Each event is a JSON object:
            {"type": "progress"|"finding"|"path"|"complete", "data": {...}}
        """
        async def event_generator() -> AsyncGenerator[str, None]:
            log_path = Path(f"/tmp/pip-scans/{scan_id}/stream.jsonl")
            last_pos = 0
            for _ in range(600):  # max 10 minutes
                if log_path.exists():
                    content = log_path.read_text()
                    new_content = content[last_pos:]
                    for line in new_content.splitlines():
                        if line.strip():
                            yield f"data: {line}\n\n"
                    last_pos = len(content)
                result_path = Path(f"/tmp/pip-scans/{scan_id}/result.json")
                if result_path.exists():
                    break
                await asyncio.sleep(1)

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    @app.get("/scan/{scan_id}/report/{report_type}", tags=["scan"],
             dependencies=[Depends(auth_dep)])
    async def get_report(scan_id: str, report_type: str):
        """
        Download a generated report.

        report_type: technical | executive | blue_team
        Returns the JSON content of the requested report.
        """
        report_map = {
            "technical":  "technical_report.json",
            "executive":  "executive_report.html",
            "blue_team":  "blue_team_report.json",
            "sarif":      "technical_report.sarif",
        }
        filename = report_map.get(report_type)
        if not filename:
            raise HTTPException(status_code=400, detail=f"Unknown report type: {report_type}")

        report_path = Path(f"/tmp/pip-scans/{scan_id}/{filename}")
        if not report_path.exists():
            raise HTTPException(status_code=404, detail="Report not yet available.")

        content = report_path.read_text()
        if filename.endswith(".json") or filename.endswith(".sarif"):
            return JSONResponse(content=json.loads(content))
        return StreamingResponse(iter([content]), media_type="text/html")

    @app.get("/knowledge/sync", tags=["knowledge"],
             dependencies=[Depends(auth_dep)])
    async def sync_knowledge(background_tasks: BackgroundTasks):
        """Trigger a background knowledge base sync (GTFOBins, NVD)."""
        from pip.analysis.knowledge_base import KnowledgeBase
        background_tasks.add_task(KnowledgeBase().sync)
        return {"status": "sync started"}

    return app


# ── Background scan runner ────────────────────────────────────────────────────

async def _run_scan_background(scan_id: str, config: ScanConfig) -> None:
    """
    Execute a full scan pipeline and write results to /tmp/pip-scans/{scan_id}/.
    Called as a FastAPI background task.
    """
    result_path = Path(f"/tmp/pip-scans/{scan_id}/result.json")
    try:
        from pip.core.orchestrator import Orchestrator
        orch = Orchestrator.__new__(Orchestrator)
        orch.config = config
        orch._start_time = __import__("time").time()

        from pip.core.context_engine import ContextEngine
        from pip.core.stealth_engine import StealthEngine
        from pip.core.shell_compat import ShellCompat

        orch.context_engine = ContextEngine(config)
        orch.stealth_engine = StealthEngine(config)
        orch.shell = ShellCompat(config)
        orch.findings = []
        orch.attack_paths = []

        await orch._pipeline()

        # Write compact result summary
        paths = orch.attack_paths
        summary = {
            "risk_level":    paths[0].score_label if paths else "NONE",
            "root_possible": bool(paths),
            "paths_found":   len(paths),
            "verified":      sum(1 for p in paths if p.verified),
            "top_score":     paths[0].composite_score if paths else 0.0,
        }
        result_path.write_text(json.dumps(summary))

    except Exception as exc:
        result_path.write_text(json.dumps({
            "risk_level": "ERROR", "root_possible": False,
            "paths_found": 0, "verified": 0, "top_score": 0.0,
            "error": str(exc),
        }))
