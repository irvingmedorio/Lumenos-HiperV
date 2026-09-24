#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""REST API for LUMENOS Sandbox — FastAPI endpoints."""

from __future__ import annotations

import atexit
import concurrent.futures
import hmac
import logging
import os
import re
import threading
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException
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

# A bunker id is not just a label: it becomes a VM/switch name, an on-disk
# artifact path (``evidence/<id>``, ``snapshots/<id>_system.vhdx``) and a glob
# pattern (``<id>_decontamination_*.json``). An unconstrained id is therefore a
# traversal / glob-injection primitive, so the charset is pinned at the two
# boundaries that matter: id creation (``BunkerCreate.id``) and the one route
# that turns an id into a path (``get_evidence``). It is deliberately NOT
# enforced when resolving an existing bunker: a record written before this
# guard existed must stay manageable, or its VM, switch and disk would be
# stranded with no way to stop, decontaminate or decommission them.
_BUNKER_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class BunkerCreate(BaseModel):
    """Payload for POST /bunkers.

    ``id`` is constrained to ``_BUNKER_ID_PATTERN`` because it is propagated
    into VM/switch names and host filesystem paths.
    """
    id: str = Field(..., pattern=_BUNKER_ID_PATTERN,
                    description="Unique bunker identifier")
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


class AnalyzeSyncRequest(BaseModel):
    """Payload for POST /analyze-sync (one-shot synchronous analysis)."""
    sample_path: str = Field(..., description="Host-accessible path to the sample file")
    monitor_seconds: float = Field(
        5.0, ge=0, le=3600,
        description="Bounded guest monitoring duration in seconds",
    )
    timeout_seconds: float = Field(
        120.0, gt=0, le=3600,
        description="Wall-clock cap for the whole cycle so a hung guest "
                    "cannot hang the API forever",
    )
    execute_timeout: int = Field(
        30, ge=1, le=600,
        description="Per guest command timeout in seconds",
    )


# /analyze-sync executor and admission control.
#
# - The pool bounds concurrent *running* analyses at _ANALYSIS_MAX_IN_FLIGHT.
#   The pool alone is not enough: concurrent.futures queues further
#   submissions without limit and cannot cancel a future that already started,
#   so without backpressure a few stuck guests would absorb every worker while
#   later requests sat queued.
# - _analysis_slots is the admission bound: a request that cannot take a slot
#   is refused immediately with HTTP 503 instead of piling up in the queue.
# - The worker receives timeout_seconds and analyze_sync enforces it as a
#   cooperative deadline: it aborts the cycle between steps and still runs its
#   decontamination ``finally`` before returning. The slot is released when
#   the worker returns, so a deadline-aborted analysis restores capacity
#   instead of occupying a worker forever.
_ANALYSIS_MAX_IN_FLIGHT = 4

# The caller waits longer than the worker's own deadline so the worker's clean
# cooperative abort (structured error verdict) normally wins the race. The 504
# is reserved for the residual non-interruptible tail (e.g. a backend call that
# ignores the deadline); the margin gives the worker time to finish aborting
# and decontaminating before the caller gives up.
_ANALYSIS_TEARDOWN_MARGIN_SECONDS = 30

_analysis_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=_ANALYSIS_MAX_IN_FLIGHT, thread_name_prefix="inspect-sync"
)
_analysis_slots = threading.BoundedSemaphore(_ANALYSIS_MAX_IN_FLIGHT)

# At interpreter exit, drop analyses that are still queued (cancel_futures
# discards the pending submissions). This does NOT unblock an analysis that is
# already running: concurrent.futures.thread joins its worker threads at
# shutdown, so a stuck worker can still delay process exit.
atexit.register(lambda: _analysis_executor.shutdown(wait=False, cancel_futures=True))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_bunker(bunker_id: str) -> Bunker:
    """Return an in-memory bunker or try to restore from state store.

    The id charset is deliberately NOT enforced here. A persisted record may
    predate the creation-time constraint, and refusing to resolve such an id
    would strand its VM, switch and disk: they could never be stopped,
    decontaminated or decommissioned. Resolution therefore accepts any id the
    store already knows; the charset is enforced at creation and at the one
    route that turns an id into a filesystem path (``get_evidence``).
    """
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


def _authorize_and_resolve(sample_path: str, authorization: Optional[str]) -> Path:
    """Fail-closed auth + path confinement for ``POST /analyze-sync``.

    Unconfigured token/root -> 503, bad token -> 401, sample outside
    ``LUMENOS_SAMPLES_ROOT`` -> 403. Returns the resolved sample path.
    """
    expected = os.environ.get("LUMENOS_API_TOKEN", "")
    if not expected:
        raise HTTPException(status_code=503, detail="API token not configured")
    scheme, _, presented = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not presented or not hmac.compare_digest(
        presented.encode("utf-8"), expected.encode("utf-8")
    ):
        raise HTTPException(status_code=401, detail="Invalid or missing bearer token")

    root_raw = os.environ.get("LUMENOS_SAMPLES_ROOT", "")
    if not root_raw:
        raise HTTPException(status_code=503, detail="Sample root not configured")
    root = Path(root_raw).resolve()
    candidate = Path(sample_path).resolve()
    if candidate != root and root not in candidate.parents:
        raise HTTPException(status_code=403, detail="Sample path is outside the allowed root")
    return candidate


# ---------------------------------------------------------------------------
# Authentication for the remaining endpoints
# ---------------------------------------------------------------------------
#
# POST /analyze-sync authenticates itself inside its handler (via
# ``_authorize_and_resolve``), and GET /health is deliberately open so liveness
# probes can reach it without credentials. Every other endpoint authenticates
# through this router-level dependency, so a request without a valid bearer
# token is rejected before the handler runs.
#
# TODO(auth-debt): this check is a deliberate DUPLICATE of the token logic
# inlined in ``_authorize_and_resolve`` above. Both paths must stay in
# agreement on the scheme, the constant-time comparison and the fail-closed
# 503. The intended fix is to extract a single shared verifier that
# ``_authorize_and_resolve`` also calls, but that touches bytes carrying burned
# review authority from the previous session, so the refactor is deliberately
# deferred. Until it lands: change one, change BOTH.

def _verify_bearer_token_standalone(authorization: Optional[str] = Header(None)) -> None:
    """Fail-closed bearer-token check used as a FastAPI dependency.

    Unconfigured token -> 503, missing or wrong token -> 401. Mirrors
    ``_authorize_and_resolve``'s token half; see the TODO above.
    """
    expected = os.environ.get("LUMENOS_API_TOKEN", "")
    if not expected:
        raise HTTPException(status_code=503, detail="API token not configured")
    scheme, _, presented = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not presented or not hmac.compare_digest(
        presented.encode("utf-8"), expected.encode("utf-8")
    ):
        raise HTTPException(status_code=401, detail="Invalid or missing bearer token")


# Routes declared on this router require the bearer token. Anything added here
# later is therefore protected by default rather than by remembering to opt in.
protected = APIRouter(dependencies=[Depends(_verify_bearer_token_standalone)])


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

# Deliberately NOT on the protected router: liveness/readiness probes run
# without credentials, and this response exposes nothing but a status and a
# version. It must keep answering 200 even when LUMENOS_API_TOKEN is unset.
@app.get("/health")
def health_check():
    """System health check. Unauthenticated by design (see the note above)."""
    return {"status": "ok", "version": "2.1.0"}


@protected.get("/bunkers")
def list_bunkers():
    """List all known bunkers."""
    store = get_state_store()
    return store.list_all()


@protected.post("/bunkers", response_model=MessageResponse, status_code=201)
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
    try:
        if not bunker.initialize():
            raise HTTPException(status_code=500, detail="Failed to initialize bunker")
    except Exception:
        # A create is atomic. initialize() persists INITIALIZING and then ERROR
        # through transition_to -> _persist_state, so a failure would otherwise
        # leave an orphan row the caller never learned about (the 500 hides it).
        # Drop it so the id is free again; the host resources were already
        # removed by Bunker._cleanup_on_failure(). Best-effort: a rollback
        # failure must never mask the original error.
        try:
            store.delete(config.id)
        except Exception as exc:
            logger.debug("Could not roll back failed create %s: %s", config.id, exc)
        raise

    _bunkers[config.id] = bunker
    return MessageResponse(ok=True, message=f"Bunker {config.id} created", data=bunker.get_full_status())


@protected.get("/bunkers/{bunker_id}")
def get_bunker(bunker_id: str):
    """Get full status of a bunker."""
    bunker = _get_bunker(bunker_id)
    return bunker.get_full_status()


@protected.post("/bunkers/{bunker_id}/start", response_model=MessageResponse)
def start_bunker(bunker_id: str):
    """Initialize a bunker (create VM + switch)."""
    bunker = _get_bunker(bunker_id)
    if bunker.state != BunkerState.DESTROYED:
        raise HTTPException(status_code=409, detail=f"Bunker is in state {bunker.state.name}, expected DESTROYED")

    if not bunker.initialize():
        raise HTTPException(status_code=500, detail="Failed to initialize bunker")

    return MessageResponse(ok=True, message=f"Bunker {bunker_id} initialized")


@protected.post("/bunkers/{bunker_id}/stop", response_model=MessageResponse)
def stop_bunker(bunker_id: str):
    """Terminate and decontaminate a bunker."""
    bunker = _get_bunker(bunker_id)
    if bunker.state != BunkerState.ACTIVE:
        raise HTTPException(status_code=409, detail=f"Bunker is in state {bunker.state.name}, expected ACTIVE")

    if not bunker.terminate():
        raise HTTPException(status_code=500, detail="Termination failed")

    return MessageResponse(ok=True, message=f"Bunker {bunker_id} terminated")


@protected.post("/bunkers/{bunker_id}/activate", response_model=MessageResponse)
def activate_bunker(bunker_id: str):
    """Activate security layers + monitoring."""
    bunker = _get_bunker(bunker_id)
    if bunker.state != BunkerState.READY:
        raise HTTPException(status_code=409, detail=f"Bunker is in state {bunker.state.name}, expected READY")

    if not bunker.activate():
        raise HTTPException(status_code=500, detail="Activation failed")

    return MessageResponse(ok=True, message=f"Bunker {bunker_id} activated")


@protected.get("/bunkers/{bunker_id}/metrics")
def get_metrics(bunker_id: str):
    """Get collector metrics from bunker."""
    bunker = _get_bunker(bunker_id)
    return bunker.get_full_status()["collector_metrics"]


@protected.post("/bunkers/{bunker_id}/analyze", response_model=MessageResponse)
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


@protected.get("/bunkers/{bunker_id}/report")
def get_report(bunker_id: str):
    """Get security report for a bunker."""
    bunker = _get_bunker(bunker_id)
    return {
        "bunker_id": bunker_id,
        "state": bunker.state.name,
        "security_report": bunker.security_monitor.get_security_report(),
        "integrity_report": bunker.integrity_verifier.get_verification_report(),
    }


@protected.get("/evidence/{bunker_id}")
def get_evidence(bunker_id: str):
    """Collect and verify forensic evidence chain.

    This is the one route that turns the id into a filesystem path
    (``evidence/<id>``) and into a glob, so the charset is enforced here rather
    than in ``_get_bunker``: a legacy id stays manageable everywhere else while
    this sink still refuses a traversal-shaped or glob-shaped id.
    """
    if not re.fullmatch(_BUNKER_ID_PATTERN, bunker_id):
        raise HTTPException(
            status_code=400, detail=f"Invalid bunker id: {bunker_id!r}"
        )

    # Verify bunker exists
    _get_bunker(bunker_id)

    chain = collect_evidence(bunker_id)
    return chain.to_dict()


@protected.get("/compliance")
def get_compliance():
    """Evaluate security controls and return compliance report."""
    report = ComplianceReport()
    return report.evaluate()


@app.post("/analyze-sync")
def analyze_sync_endpoint(
    payload: AnalyzeSyncRequest, authorization: Optional[str] = Header(None)
):
    """Synchronous one-shot analysis for LUMENOS_Custom.

    The caller does NOT manage bunkers: an ephemeral bunker is created
    internally, the full inspect-file cycle runs (stage -> bunker lifecycle
    -> execute + bounded monitor -> IOCs -> decontaminate), and the verdict
    JSON is returned. ``timeout_seconds`` is forwarded to the worker as the
    analysis's own cooperative deadline, so a cycle that outlives it aborts
    between steps and returns a structured ``error`` verdict; the caller
    additionally waits ``timeout_seconds + _ANALYSIS_TEARDOWN_MARGIN_SECONDS``
    so that clean abort normally wins the race. Validation errors yield
    400/422; a worker still running past that longer wait (an uninterruptible
    backend call) yields 504; an exhausted admission budget yields 503.
    """
    resolved = _authorize_and_resolve(payload.sample_path, authorization)
    if not resolved.is_file():
        raise HTTPException(
            status_code=400, detail=f"Sample not found: {payload.sample_path}"
        )
    # Downstream stages use the confined resolved path, not the raw input.
    payload.sample_path = str(resolved)

    # Admission bound: refuse instead of queueing without limit. The slot is
    # held until the worker finishes, even when the caller has already given up.
    if not _analysis_slots.acquire(blocking=False):
        raise HTTPException(
            status_code=503,
            detail="Analysis capacity is full — retry shortly",
        )
    try:
        future = _analysis_executor.submit(_run_analysis_and_release, payload)
    except Exception:
        _analysis_slots.release()
        raise

    caller_wait_seconds = payload.timeout_seconds + _ANALYSIS_TEARDOWN_MARGIN_SECONDS
    try:
        return future.result(timeout=caller_wait_seconds)
    except concurrent.futures.TimeoutError:
        logger.error(
            "analyze-sync exceeded its %.1fs deadline plus %.1fs teardown "
            "margin for %s (residual uninterruptible tail; decontamination "
            "continues in background)",
            payload.timeout_seconds, _ANALYSIS_TEARDOWN_MARGIN_SECONDS,
            payload.sample_path,
        )
        raise HTTPException(
            status_code=504,
            detail="Analysis timed out — bunker decontamination continues in background",
        )
    except Exception as exc:  # unexpected worker crash
        logger.error("analyze-sync worker crashed for %s: %s", payload.sample_path, exc)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}")


def _run_analysis_and_release(payload: AnalyzeSyncRequest) -> Dict[str, Any]:
    """Run one admitted analysis and always release its admission slot."""
    try:
        return _run_analysis(payload)
    finally:
        _analysis_slots.release()


def _run_analysis(payload: AnalyzeSyncRequest) -> Dict[str, Any]:
    """Run the inspect-file cycle for the endpoint (returns an error verdict
    instead of raising, so a timed-out consumer still gets a report).

    ``payload.timeout_seconds`` is forwarded as the analysis's own deadline;
    a cycle that exhausts it aborts cooperatively (running decontamination)
    and surfaces here as a structured ``error`` verdict.
    """
    from .inspect import analyze_sync, build_error_report

    try:
        return analyze_sync(
            payload.sample_path,
            monitor_seconds=payload.monitor_seconds,
            execute_timeout=payload.execute_timeout,
            timeout_seconds=payload.timeout_seconds,
        )
    except Exception as exc:
        logger.error("analyze-sync analysis failed: %s", exc)
        return build_error_report(payload.sample_path, exc)


# Mount the protected routes with an explicit empty prefix so every published
# URL stays byte-for-byte the same as before this change.
app.include_router(protected, prefix="")


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
