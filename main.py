"""
main.py – FastAPI web service for the Tamper-Evident Logging System.

Thin API layer over the existing Python security modules.
All cryptographic and verification logic stays inside tamper_evident_logging/.

Endpoints:
  GET  /                 → Landing page with API overview
  GET  /health           → System health check
  POST /logs             → Add a new log entry
  GET  /logs             → List all log entries
  GET  /logs/{seq}       → Get a specific log entry
  GET  /verify           → Run full integrity verification
  GET  /checkpoints      → List all Merkle checkpoints
  POST /simulate-tamper  → Deliberately corrupt an entry for demo
  GET  /report           → Get the latest verification report
  POST /reset            → Reset all data (demo only)
"""

from __future__ import annotations

import json
import shutil
import traceback
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

# ── Import existing modules ───────────────────────────────────────────
from tamper_evident_logging.log_entry import LogEntry
from tamper_evident_logging.log_writer import LogWriter
from tamper_evident_logging.storage import AppendOnlyStorage
from tamper_evident_logging.crypto_signer import CryptoSigner
from tamper_evident_logging.verifier import (
    IntegrityVerifier,
    generate_tamper_report,
)

# ── Configuration ─────────────────────────────────────────────────────
DATA_DIR = Path(__file__).resolve().parent / "api_data"
BATCH_SIZE = 5

# ── Global state (initialised at startup) ─────────────────────────────
storage: AppendOnlyStorage
signer: CryptoSigner
writer: LogWriter


def _init_system() -> None:
    """(Re-)initialise storage, signer, and writer from disk."""
    global storage, signer, writer
    storage = AppendOnlyStorage(DATA_DIR)
    keys_exist = (storage.keys_dir / "private_key.pem").exists()
    if keys_exist:
        signer = CryptoSigner.load_keys(storage.keys_dir)
    else:
        signer = CryptoSigner()
    writer = LogWriter(storage, signer, batch_size=BATCH_SIZE)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    _init_system()
    yield


# ── FastAPI app ───────────────────────────────────────────────────────
app = FastAPI(
    title="Tamper-Evident Logging System",
    description=(
        "A production-grade secure audit-log prototype with SHA-256 hash chains, "
        "Merkle-tree checkpointing, Ed25519 digital signatures, and RFC 3161-style "
        "trusted timestamping. Built for the Cybersecurity & Network Security "
        "Internship Assessment – Task 1."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Allow browser / Postman / Swagger from any origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =====================================================================
# Pydantic request / response models
# =====================================================================

class LogCreateRequest(BaseModel):
    """Payload for creating a new log entry."""
    event_type: str = Field(..., min_length=1, max_length=100, examples=["LOGIN"])
    description: str = Field(..., min_length=1, max_length=1000, examples=["User alice logged in from 192.168.1.10"])
    actor: str = Field(..., min_length=1, max_length=200, examples=["alice"])
    metadata: Optional[Dict[str, Any]] = Field(default=None, examples=[{"ip": "192.168.1.10"}])


class TamperType(str, Enum):
    modify = "modify"
    delete = "delete"
    reorder = "reorder"


class TamperRequest(BaseModel):
    """Payload for simulating a tamper scenario."""
    tamper_type: TamperType = Field(..., examples=["modify"])
    target_seq: int = Field(..., ge=1, examples=[3], description="Entry sequence # to tamper with")
    new_description: Optional[str] = Field(
        default="TAMPERED ENTRY",
        description="New description (only used for 'modify' type)",
    )
    swap_with_seq: Optional[int] = Field(
        default=None,
        ge=1,
        description="Second entry # to swap with (only used for 'reorder' type)",
    )


class APIResponse(BaseModel):
    """Standard envelope for all responses."""
    success: bool
    message: str
    data: Optional[Any] = None


# =====================================================================
# Endpoints
# =====================================================================

# ── Landing page ──────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def landing_page():
    """Serve a styled landing page with links to Swagger and all endpoints."""
    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Tamper-Evident Logging System</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);border:1px solid #334155;border-radius:16px;padding:48px;max-width:720px;width:90%;box-shadow:0 25px 50px rgba(0,0,0,.5)}
h1{font-size:1.8rem;font-weight:700;background:linear-gradient(135deg,#38bdf8,#818cf8);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:8px}
.sub{color:#94a3b8;font-size:.95rem;margin-bottom:32px}
.badge{display:inline-block;background:#1e3a5f;color:#38bdf8;font-size:.7rem;font-weight:600;padding:4px 10px;border-radius:20px;margin-bottom:16px;letter-spacing:.5px}
.endpoints{list-style:none;display:grid;gap:12px}
.ep{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:14px 18px;display:flex;align-items:center;gap:12px;transition:border-color .2s}
.ep:hover{border-color:#38bdf8}
.method{font-size:.7rem;font-weight:700;padding:3px 8px;border-radius:6px;min-width:52px;text-align:center}
.get{background:#065f46;color:#34d399}.post{background:#7c2d12;color:#fb923c}
.path{font-family:monospace;color:#e2e8f0;font-size:.9rem}
.desc{color:#94a3b8;font-size:.78rem;margin-left:auto}
.cta{display:inline-block;margin-top:28px;padding:12px 28px;background:linear-gradient(135deg,#2563eb,#7c3aed);color:#fff;text-decoration:none;border-radius:10px;font-weight:600;font-size:.9rem;transition:opacity .2s}
.cta:hover{opacity:.85}
.footer{text-align:center;margin-top:24px;color:#475569;font-size:.75rem}
</style>
</head>
<body>
<div class="card">
<div class="badge">CYBERSECURITY TASK 1</div>
<h1>🔒 Tamper-Evident Logging System</h1>
<p class="sub">SHA-256 hash chains · Merkle trees · Ed25519 signatures · RFC 3161 timestamps</p>
<ul class="endpoints">
<li class="ep"><span class="method get">GET</span><span class="path">/health</span><span class="desc">System health check</span></li>
<li class="ep"><span class="method post">POST</span><span class="path">/logs</span><span class="desc">Add a new log entry</span></li>
<li class="ep"><span class="method get">GET</span><span class="path">/logs</span><span class="desc">List all log entries</span></li>
<li class="ep"><span class="method get">GET</span><span class="path">/logs/{seq}</span><span class="desc">Get specific entry</span></li>
<li class="ep"><span class="method get">GET</span><span class="path">/verify</span><span class="desc">Full integrity verification</span></li>
<li class="ep"><span class="method get">GET</span><span class="path">/checkpoints</span><span class="desc">Merkle checkpoints</span></li>
<li class="ep"><span class="method post">POST</span><span class="path">/simulate-tamper</span><span class="desc">Tamper simulation</span></li>
<li class="ep"><span class="method get">GET</span><span class="path">/report</span><span class="desc">Latest forensic report</span></li>
<li class="ep"><span class="method post">POST</span><span class="path">/reset</span><span class="desc">Reset all data</span></li>
</ul>
<a class="cta" href="/docs">Open Swagger UI →</a>
<p class="footer">Built for Cybersecurity &amp; Network Security Internship Assessment</p>
</div>
</body>
</html>"""
    return HTMLResponse(content=html)


# ── Health check ──────────────────────────────────────────────────────

@app.get("/health", response_model=APIResponse, tags=["System"])
async def health_check():
    """Confirm API is running and core subsystems are available."""
    try:
        checks = {
            "api": "running",
            "storage": "reachable" if DATA_DIR.exists() else "initialising",
            "crypto_signer": "loaded",
            "verifier": "available",
            "entries_on_disk": len(storage.read_entries()),
            "checkpoints_on_disk": len(storage.read_checkpoints()),
            "public_key_present": (storage.keys_dir / "public_key.pem").exists(),
        }
        return APIResponse(success=True, message="System healthy", data=checks)
    except Exception as e:
        return APIResponse(success=False, message=f"Health check failed: {e}")


# ── Create log entry ─────────────────────────────────────────────────

@app.post("/logs", response_model=APIResponse, tags=["Logs"])
async def create_log(req: LogCreateRequest):
    """Add a new log entry (append-only)."""
    try:
        entry = writer.add_event(
            event_type=req.event_type.upper().strip(),
            description=req.description.strip(),
            actor=req.actor.strip(),
            metadata=req.metadata,
        )
        return APIResponse(
            success=True,
            message=f"Entry #{entry.seq} logged successfully",
            data=entry.to_dict(),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create log entry: {e}")


# ── List log entries ──────────────────────────────────────────────────

@app.get("/logs", response_model=APIResponse, tags=["Logs"])
async def list_logs(
    limit: int = Query(default=100, ge=1, le=1000, description="Max entries to return"),
    offset: int = Query(default=0, ge=0, description="Skip this many entries"),
):
    """Retrieve all log entries (read-only)."""
    try:
        entries = storage.read_entries()
        total = len(entries)
        page = entries[offset : offset + limit]
        return APIResponse(
            success=True,
            message=f"Showing {len(page)} of {total} entries",
            data={
                "total": total,
                "offset": offset,
                "limit": limit,
                "entries": [e.to_dict() for e in page],
            },
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read logs: {e}")


# ── Get single entry ─────────────────────────────────────────────────

@app.get("/logs/{seq}", response_model=APIResponse, tags=["Logs"])
async def get_log_entry(seq: int):
    """Retrieve a single log entry by sequence number."""
    try:
        entries = storage.read_entries()
        for entry in entries:
            if entry.seq == seq:
                return APIResponse(
                    success=True,
                    message=f"Entry #{seq} found",
                    data=entry.to_dict(),
                )
        raise HTTPException(status_code=404, detail=f"Entry #{seq} not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read entry: {e}")


# ── Verify integrity ─────────────────────────────────────────────────

@app.get("/verify", response_model=APIResponse, tags=["Verification"])
async def verify_integrity():
    """Run a full integrity verification across all 5 security layers.

    Checks: hash chain, sequence order, Merkle roots, Ed25519 signatures,
    timestamp tokens, and timestamp ordering.
    """
    try:
        verifier = IntegrityVerifier(storage, batch_size=BATCH_SIZE)
        result = verifier.verify()
        report = generate_tamper_report(result)

        # Save report to disk
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        storage.save_report(report, f"api_report_{ts}.json")

        return APIResponse(
            success=True,
            message="Verification complete",
            data=report,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failed: {e}")


# ── Checkpoints ───────────────────────────────────────────────────────

@app.get("/checkpoints", response_model=APIResponse, tags=["Verification"])
async def list_checkpoints():
    """List all Merkle-tree checkpoints with signatures and timestamps."""
    try:
        checkpoints = storage.read_checkpoints()
        return APIResponse(
            success=True,
            message=f"{len(checkpoints)} checkpoint(s) found",
            data={"total": len(checkpoints), "checkpoints": checkpoints},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read checkpoints: {e}")


# ── Tamper simulation ────────────────────────────────────────────────

@app.post("/simulate-tamper", response_model=APIResponse, tags=["Tamper Simulation"])
async def simulate_tamper(req: TamperRequest):
    """Deliberately corrupt a log entry to demonstrate tamper detection.

    Three tamper types:
    - **modify**: Change the description of an entry
    - **delete**: Remove an entry from the log
    - **reorder**: Swap two entries
    """
    try:
        lines = storage.read_raw_lines()
        if not lines:
            raise HTTPException(status_code=400, detail="No log entries to tamper with")

        idx = req.target_seq - 1
        if idx < 0 or idx >= len(lines):
            raise HTTPException(
                status_code=400,
                detail=f"Entry #{req.target_seq} not found (have {len(lines)} entries)",
            )

        if req.tamper_type == TamperType.modify:
            entry_data = json.loads(lines[idx])
            old_desc = entry_data["description"]
            entry_data["description"] = req.new_description or "TAMPERED ENTRY"
            lines[idx] = json.dumps(entry_data, sort_keys=True, separators=(",", ":"))
            storage.write_raw_lines(lines)
            return APIResponse(
                success=True,
                message=f"Entry #{req.target_seq} modified",
                data={
                    "tamper_type": "modify",
                    "target_seq": req.target_seq,
                    "old_description": old_desc,
                    "new_description": entry_data["description"],
                },
            )

        elif req.tamper_type == TamperType.delete:
            removed = json.loads(lines[idx])
            del lines[idx]
            storage.write_raw_lines(lines)
            return APIResponse(
                success=True,
                message=f"Entry #{req.target_seq} deleted",
                data={
                    "tamper_type": "delete",
                    "removed_entry": removed,
                    "remaining_entries": len(lines),
                },
            )

        elif req.tamper_type == TamperType.reorder:
            if req.swap_with_seq is None:
                raise HTTPException(
                    status_code=400,
                    detail="swap_with_seq is required for reorder tamper type",
                )
            idx2 = req.swap_with_seq - 1
            if idx2 < 0 or idx2 >= len(lines):
                raise HTTPException(
                    status_code=400,
                    detail=f"Entry #{req.swap_with_seq} not found",
                )
            lines[idx], lines[idx2] = lines[idx2], lines[idx]
            storage.write_raw_lines(lines)
            return APIResponse(
                success=True,
                message=f"Entries #{req.target_seq} and #{req.swap_with_seq} swapped",
                data={
                    "tamper_type": "reorder",
                    "swapped": [req.target_seq, req.swap_with_seq],
                },
            )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Tamper simulation failed: {e}")


# ── Latest report ─────────────────────────────────────────────────────

@app.get("/report", response_model=APIResponse, tags=["Verification"])
async def get_latest_report():
    """Get the most recent verification report."""
    try:
        report_files = sorted(storage.reports_dir.glob("*.json"))
        if not report_files:
            return APIResponse(
                success=True,
                message="No reports yet. Run /verify first.",
                data=None,
            )
        latest = report_files[-1]
        with open(latest, "r") as f:
            report = json.load(f)
        return APIResponse(
            success=True,
            message=f"Latest report: {latest.name}",
            data=report,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read report: {e}")


# ── Reset (demo only) ────────────────────────────────────────────────

@app.post("/reset", response_model=APIResponse, tags=["System"])
async def reset_data():
    """Delete all data and start fresh. For demonstration only."""
    try:
        if DATA_DIR.exists():
            shutil.rmtree(DATA_DIR)
        _init_system()
        return APIResponse(
            success=True,
            message="All data reset. System re-initialised.",
            data=None,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Reset failed: {e}")


# ── Run directly ─────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
