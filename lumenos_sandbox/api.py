#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""REST API for LUMENOS Sandbox — FastAPI endpoints."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .types import BunkerConfig, BunkerState
from .bunker import Bunker, get_state_store
from .forensics import collect_evidence
from .compliance import ComplianceReport
from .observability import check_health

logger = logging.getLogger("LUMENOS_SANDBOX")

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="LUMENOS Sandbox API",
    description="REST interface for the LUMENOS multi-layer malware isolation sandbox",
    version="2.1.0",
)

# In-memory bunker registry (keyed by bunker id)
_bunkers: Dict[str, Bunker] = {}


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class BunkerCreate(BaseModel):
    """Payload for POST /bunkers."""
    id: str = Field(..., description="Unique bunker identifier")
    name: str = Field(..., description="Human-readable name")
    memory_mb: int = Field(8192, ge=512, description="RAM in MB")
    cpu_cores: int = Field(4, ge=1, description="Number of CPU cores")
    disk_gb: int = Field(100, ge=10, description="Disk size in GB")
    max_session_hours: int = Field(24, ge=1)
    decontamination_minutes: int = Field(30, ge=5)
    guest_username: str = Field("Administrator")
    guest_password: str = Field("")


class AnalyzeRequest(BaseModel):
    """Payload for POST /bunkers/{id}/analyze."""
    sample_path: str = Field(..., description="Path to the sample inside the guest")


class MessageResponse(BaseModel):
    """Generic action response."""
    ok: bool
    message: str
    data: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_bunker(bunker_id: str) -> Bunker:
    """Return an in-memory bunker or try to restore from state store."""
    if bunker_id in _bunkers:
        return _bunkers[bunker_id]

    # Attempt restore from persisted state
    store = get_state_store()
    state = store.load(bunker_id)
    if state is None:
        raise HTTPException(status_code=404, detail=f"Bunker not found: {bunker_id}")

    valid_fields = {f.name for f in BunkerConfig.__dataclass_fields__.values()}
    filtered = {k: v for k, v in state["config"].items() if k in valid_fields}
    config = BunkerConfig(**filtered)
    bunker = Bunker(config)
    bunker.state = BunkerState[state["state"]]
    bunker._vm_name = state.get("vm_name")
    bunker._switch_name = state.get("switch_name")
    _bunkers[bunker_id] = bunker
    return bunker


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health_check():
    """System health check."""
    return {"status": "ok", "version": "2.1.0"}


@app.get("/bunkers")
def list_bunkers():
    """List all known bunkers."""
    store = get_state_store()
    return store.list_all()


@app.post("/bunkers", response_model=MessageResponse, status_code=201)
def create_bunker(payload: BunkerCreate):
    """Create a new bunker (initializes Hyper-V resources)."""
    store = get_state_store()
    if store.load(payload.id) is not None:
        raise HTTPException(status_code=409, detail=f"Bunker already exists: {payload.id}")

    config = BunkerConfig(
        id=payload.id,
        name=payload.name,
        memory_mb=payload.memory_mb,
        cpu_cores=payload.cpu_cores,
        disk_gb=payload.disk_gb,
        max_session_hours=payload.max_session_hours,
        decontamination_minutes=payload.decontamination_minutes,
        guest_username=payload.guest_username,
        guest_password=payload.guest_password,
    )

    bunker = Bunker(config)
    if not bunker.initialize():
        raise HTTPException(status_code=500, detail="Failed to initialize bunker")

    _bunkers[config.id] = bunker
    return MessageResponse(ok=True, message=f"Bunker {config.id} created", data=bunker.get_full_status())


@app.get("/bunkers/{bunker_id}")
def get_bunker(bunker_id: str):
    """Get full status of a bunker."""
    bunker = _get_bunker(bunker_id)
    return bunker.get_full_status()


@app.post("/bunkers/{bunker_id}/start", response_model=MessageResponse)
def start_bunker(bunker_id: str):
    """Initialize a bunker (create VM + switch)."""
    bunker = _get_bunker(bunker_id)
    if bunker.state != BunkerState.DESTROYED:
        raise HTTPException(status_code=409, detail=f"Bunker is in state {bunker.state.name}, expected DESTROYED")

    if not bunker.initialize():
        raise HTTPException(status_code=500, detail="Failed to initialize bunker")

    return MessageResponse(ok=True, message=f"Bunker {bunker_id} initialized")


@app.post("/bunkers/{bunker_id}/stop", response_model=MessageResponse)
def stop_bunker(bunker_id: str):
    """Terminate and decontaminate a bunker."""
    bunker = _get_bunker(bunker_id)
    if bunker.state != BunkerState.ACTIVE:
        raise HTTPException(status_code=409, detail=f"Bunker is in state {bunker.state.name}, expected ACTIVE")

    if not bunker.terminate():
        raise HTTPException(status_code=500, detail="Termination failed")

    return MessageResponse(ok=True, message=f"Bunker {bunker_id} terminated")


@app.post("/bunkers/{bunker_id}/activate", response_model=MessageResponse)
def activate_bunker(bunker_id: str):
    """Activate security layers + monitoring."""
    bunker = _get_bunker(bunker_id)
    if bunker.state != BunkerState.READY:
        raise HTTPException(status_code=409, detail=f"Bunker is in state {bunker.state.name}, expected READY")

    if not bunker.activate():
        raise HTTPException(status_code=500, detail="Activation failed")

    return MessageResponse(ok=True, message=f"Bunker {bunker_id} activated")


@app.get("/bunkers/{bunker_id}/metrics")
def get_metrics(bunker_id: str):
    """Get collector metrics from bunker."""
    bunker = _get_bunker(bunker_id)
    return bunker.get_full_status()["collector_metrics"]


@app.post("/bunkers/{bunker_id}/analyze", response_model=MessageResponse)
def analyze_sample(bunker_id: str, payload: AnalyzeRequest):
    """Analyze a sample — deploy to guest VM."""
    bunker = _get_bunker(bunker_id)
    if bunker.state != BunkerState.ACTIVE:
        raise HTTPException(status_code=409, detail=f"Bunker is in state {bunker.state.name}, expected ACTIVE")

    return MessageResponse(
        ok=True,
        message=f"Sample deployment queued for {bunker_id}",
        data={
            "sample_path": payload.sample_path,
            "vm_name": bunker._vm_name,
            "instruction": "Execute via PowerShell Direct, monitor for 60s, collect artifacts",
        },
    )


@app.get("/bunkers/{bunker_id}/report")
def get_report(bunker_id: str):
    """Get security report for a bunker."""
    bunker = _get_bunker(bunker_id)
    return {
        "bunker_id": bunker_id,
        "state": bunker.state.name,
        "security_report": bunker.security_monitor.get_security_report(),
        "integrity_report": bunker.integrity_verifier.get_verification_report(),
    }


@app.get("/evidence/{bunker_id}")
def get_evidence(bunker_id: str):
    """Collect and verify forensic evidence chain."""
    # Verify bunker exists
    _get_bunker(bunker_id)

    chain = collect_evidence(bunker_id)
    return chain.to_dict()


@app.get("/compliance")
def get_compliance():
    """Evaluate security controls and return compliance report."""
    report = ComplianceReport()
    return report.evaluate()


# ---------------------------------------------------------------------------
# Uvicorn runner (called by CLI)
# ---------------------------------------------------------------------------

def run_api(host: str = "127.0.0.1", port: int = 8000, reload: bool = False):
    """Start the API server."""
    import uvicorn
    uvicorn.run(
        "lumenos_sandbox.api:app",
        host=host,
        port=port,
        reload=reload,
    )
