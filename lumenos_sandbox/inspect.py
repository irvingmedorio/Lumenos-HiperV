#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""inspect-file — synchronous one-shot sample analysis with a verdict report.

The full cycle implemented here is the one LUMENOS_Custom (the external
aduana/gateway) consumes:

    stage -> bunker lifecycle (initialize/activate) -> execute + bounded
    monitoring -> IOCs -> decontaminate (always) -> verdict

The public entry point is :func:`analyze_sync`, a single shared implementation
used by both the REST endpoint (``POST /analyze-sync``) and the CLI command
(``lumenos-sandbox inspect-file``).
"""

import hashlib
import json
import logging
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from .bunker import Bunker, get_state_store
from .types import (
    BunkerConfig,
    BunkerState,
    EscapeAttemptType,
    SecurityLayer,
    ThreatLevel,
)
from .hypervisor.mock_backend import MockBackend

logger = logging.getLogger("LUMENOS_SANDBOX")

INSPECT_SCHEMA = "lumenos.inspect-report/v1"

_VALID_IOC_TYPES = {"file", "network", "process", "persistence", "registry", "memory"}
_VALID_SEVERITIES = {"low", "medium", "high", "critical"}
_SEVERITY_WEIGHTS = {"low": 1, "medium": 10, "high": 50, "critical": 100}
_CONFIDENCE_BY_VERDICT = {"clean": 1.0, "suspicious": 0.6, "malicious": 0.9, "error": 0.0}

# Cap for the static byte scan of the sample (content-based IOC extraction).
_STATIC_SCAN_LIMIT = 65536

# SecurityLayer -> IOC type.
_LAYER_TO_IOC_TYPE: Dict[SecurityLayer, str] = {
    SecurityLayer.NETWORK: "network",
    SecurityLayer.FILESYSTEM: "file",
    SecurityLayer.PROCESS: "process",
    SecurityLayer.MEMORY: "memory",
    SecurityLayer.HYPERVISOR: "process",
}

# Monitoring analyze_patterns() category -> (ioc type, severity).
_PATTERN_CATEGORY_TO_IOC: Dict[str, Tuple[str, str]] = {
    "vm_escape_indicators": ("process", "high"),
    "debugging_indicators": ("process", "low"),
    "persistence_indicators": ("persistence", "medium"),
    "network_exfil_indicators": ("network", "high"),
    "injection_indicators": ("process", "critical"),
}

# Fallback for a pattern category the mapping does not know yet. An unknown
# category means the indicator's type/severity cannot be trusted, so surface
# it conservatively (process/high) instead of silently downgrading it: a
# generic file/medium label would hide a potential indicator behind a
# suspicious-only verdict.
_UNKNOWN_CATEGORY_IOC: Tuple[str, str] = ("process", "high")

# EscapeAttemptType -> (ioc type, severity).
_ESCAPE_TO_IOC: Dict[EscapeAttemptType, Tuple[str, str]] = {
    EscapeAttemptType.VM_ESCAPE: ("process", "critical"),
    EscapeAttemptType.NETWORK_EXFILTRATION: ("network", "critical"),
    EscapeAttemptType.FILE_PERSISTENCE: ("persistence", "high"),
    EscapeAttemptType.PROCESS_INJECTION: ("process", "critical"),
    EscapeAttemptType.MEMORY_MANIPULATION: ("memory", "critical"),
    EscapeAttemptType.HYPERVISOR_ATTACK: ("process", "critical"),
    EscapeAttemptType.SIDE_CHANNEL: ("memory", "high"),
    EscapeAttemptType.ROOTKIT_DETECTED: ("process", "critical"),
}

# Canonical decontamination step names produced by DecontaminationRunner
# (used only when the runner report is unavailable).
_DECON_STEP_NAMES = [
    "terminate_processes",
    "purge_memory",
    "destroy_differential_disk",
    "clean_network_config",
    "remove_snapshots",
    "verify_host_integrity",
    "generate_report",
]


@dataclass
class IOC:
    """A structured Indicator of Compromise.

    Attributes:
        type: One of ``file|network|process|persistence|registry|memory``.
        value: The observable artifact (name, address, path, ...).
        severity: One of ``low|medium|high|critical``.
        evidence: Human-readable description of how the IOC was observed.
    """

    type: str
    value: str
    severity: str
    evidence: str = ""

    def __post_init__(self):
        if self.type not in _VALID_IOC_TYPES:
            raise ValueError(f"Invalid IOC type: {self.type!r}")
        if self.severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid IOC severity: {self.severity!r}")

    def to_dict(self) -> Dict[str, str]:
        """Serialize to the contract dict."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Report building
# ---------------------------------------------------------------------------

def _severity_from_threat(level: ThreatLevel) -> str:
    """Map a ThreatLevel enum to the contract severity string."""
    return {
        ThreatLevel.CRITICAL: "critical",
        ThreatLevel.HIGH: "high",
        ThreatLevel.MEDIUM: "medium",
        ThreatLevel.LOW: "low",
        ThreatLevel.NONE: "low",
    }[level]


def _verdict_from_iocs(iocs: List[IOC], error: Optional[str] = None) -> str:
    """Derive the verdict from observed IOC severities.

    Any critical/high -> malicious; medium -> suspicious; none -> clean;
    any infrastructure failure (error set) -> error.
    """
    if error:
        return "error"
    if any(i.severity in ("critical", "high") for i in iocs):
        return "malicious"
    if any(i.severity == "medium" for i in iocs):
        return "suspicious"
    return "clean"


def _chain_of_custody_hash(report: Dict[str, Any]) -> str:
    """SHA-256 over the canonical JSON of the report content.

    The ``chain_of_custody.hash`` field itself is blanked before hashing so
    the digest is recomputable by the consumer: hash of
    ``json.dumps(report_with_blank_hash, sort_keys=True, indent=2)``.
    """
    report["chain_of_custody"]["hash"] = ""
    canonical = json.dumps(report, sort_keys=True, indent=2)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_inspect_report(
    *,
    sample: Dict[str, Any],
    iocs: List[IOC],
    bunker_id: str,
    duration_ms: int,
    decontamination: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a versioned inspect-report in the ``lumenos.inspect-report/v1`` contract.

    Args:
        sample: ``{"path", "sha256", "size"}`` describing the analyzed file.
        iocs: Observed indicators of compromise.
        bunker_id: Id of the ephemeral bunker that ran the cycle.
        duration_ms: Wall-clock duration of the whole cycle.
        decontamination: ``{"success", "steps"}``; defaults to a failure record
            when omitted.
        error: Infrastructure/analysis failure detail; when set, the verdict
            becomes ``error`` and the detail is appended to the
            ``decontamination.steps`` evidence list.

    Returns:
        The verdict report dict matching the contract shape consumed by
        LUMENOS_Custom.
    """
    verdict = _verdict_from_iocs(iocs, error=error)
    decon = dict(decontamination) if decontamination else {"success": False, "steps": []}
    decon.setdefault("steps", [])
    if error:
        decon["steps"] = list(decon["steps"]) + [f"error: {error}"]

    report = {
        "schema": INSPECT_SCHEMA,
        "verdict": verdict,
        "confidence": _CONFIDENCE_BY_VERDICT[verdict],
        "score": sum(_SEVERITY_WEIGHTS[i.severity] for i in iocs),
        "sample": {
            "path": sample.get("path", ""),
            "sha256": sample.get("sha256", ""),
            "size": sample.get("size", 0),
        },
        "iocs": [i.to_dict() for i in iocs],
        "chain_of_custody": {"hash": "", "valid": True},
        "decontamination": decon,
        "bunker_id": bunker_id,
        "duration_ms": int(duration_ms),
    }
    report["chain_of_custody"]["hash"] = _chain_of_custody_hash(report)
    return report


def build_error_report(sample_path, exc: Exception) -> Dict[str, Any]:
    """Build an ``error``-verdict report for failures that occur before a
    bunker could be created (e.g. the sample vanished mid-flight)."""
    return build_inspect_report(
        sample={"path": str(sample_path), "sha256": "", "size": 0},
        iocs=[],
        bunker_id="",
        duration_ms=0,
        decontamination={"success": False, "steps": []},
        error=f"{type(exc).__name__}: {exc}",
    )


# ---------------------------------------------------------------------------
# Cycle helpers
# ---------------------------------------------------------------------------

def _hash_sample(path: Path) -> Dict[str, Any]:
    """Streaming SHA-256 + size of the staged sample."""
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
            size += len(chunk)
    return {"path": str(path), "sha256": h.hexdigest(), "size": size}


def _default_config() -> BunkerConfig:
    """Ephemeral bunker config — the caller never sees or manages it."""
    return BunkerConfig(
        id=f"inspect-{uuid4().hex[:12]}",
        name="inspect-file ephemeral bunker",
        guest_username="Administrator",
        guest_password="",
    )


def _default_guest_path(sample_name: str) -> str:
    """Well-known staging path for the sample inside the guest."""
    return f"C:\\Samples\\{sample_name}"


def _stage_to_guest(bunker: Bunker, path: Path, guest_path: str, execute_timeout: int) -> None:
    """Copy the sample into the guest (best-effort integrity staging).

    With MockBackend there is no real guest, so staging is reduced to the
    already-performed integrity check. With a real backend the sample is
    copied via PowerShell Direct and a failure is an analysis error (the
    bunker is still decontaminated by the caller's finally semantics).
    """
    if isinstance(bunker.backend, MockBackend):
        logger.debug("MockBackend active — skipping guest copy of %s", path.name)
        return
    copy_cmd = (
        f"If(!(Test-Path 'C:\\Samples')){{New-Item -ItemType Directory -Force -Path 'C:\\Samples' | Out-Null}}; "
        f"Copy-Item -Force -LiteralPath '{path}' -Destination '{guest_path}'"
    )
    result = bunker.backend.execute_in_guest(
        bunker._vm_name,
        bunker.config.guest_username,
        bunker._get_guest_password(),
        copy_cmd,
        timeout=execute_timeout,
    )
    if not result.success:
        raise RuntimeError(f"Failed to stage sample in guest: {result.stderr or result.stdout}")


def _execute_sample(bunker: Bunker, guest_path: str, execute_timeout: int) -> None:
    """Run the staged sample in the guest."""
    run_cmd = f'& "{guest_path}"'
    result = bunker.backend.execute_in_guest(
        bunker._vm_name,
        bunker.config.guest_username,
        bunker._get_guest_password(),
        run_cmd,
        timeout=execute_timeout,
    )
    if not result.success and not isinstance(bunker.backend, MockBackend):
        raise RuntimeError(f"Sample execution failed in guest: {result.stderr or result.stdout}")
    logger.info("Sample executed in guest (success=%s)", result.success)


def _collect_iocs(bunker: Bunker, sample_path: Path) -> List[IOC]:
    """Gather IOCs from a static byte scan of the sample plus monitor events."""
    iocs: List[IOC] = []
    seen = set()

    def add(ioc: IOC) -> None:
        key = (ioc.type, ioc.value, ioc.severity, ioc.evidence)
        if key not in seen:
            seen.add(key)
            iocs.append(ioc)

    # Static scan: content-based indicators from the sample itself.
    try:
        with open(sample_path, "rb") as f:
            chunk = f.read(_STATIC_SCAN_LIMIT)
        text = chunk.decode("utf-8", errors="replace")
        findings = bunker.security_monitor.analyze_patterns(text)
        for finding in findings:
            category, _, pattern = finding.partition(": ")
            ioc_kind = _PATTERN_CATEGORY_TO_IOC.get(category)
            if ioc_kind is None:
                ioc_kind = _UNKNOWN_CATEGORY_IOC
                logger.warning(
                    "Static IOC scan: unknown pattern category %r surfaced as %s/%s",
                    category,
                    *ioc_kind,
                )
            ioc_type, severity = ioc_kind
            add(IOC(type=ioc_type, value=pattern.strip(), severity=severity, evidence=finding))
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Static IOC scan failed: %s", exc)

    # Dynamic: security events logged by the monitor during the cycle.
    for event in bunker.security_monitor.events:
        add(IOC(
            type=_LAYER_TO_IOC_TYPE.get(event.layer, "process"),
            value=event.event_type,
            severity=_severity_from_threat(event.severity),
            evidence=event.description,
        ))

    # Dynamic: escape attempts (also logged as events; deduped above).
    for attempt in bunker.security_monitor.escape_attempts:
        ioc_type, severity = _ESCAPE_TO_IOC.get(attempt, ("process", "critical"))
        add(IOC(
            type=ioc_type,
            value=attempt.value,
            severity=severity,
            evidence=f"escape attempt: {attempt.value}",
        ))

    return iocs


def _decontaminate(bunker: Optional[Bunker]) -> Dict[str, Any]:
    """Destroy the bunker — ALWAYS called, even when the cycle failed.

    Prefers the full ``Bunker.terminate()`` decontamination path; when the
    bunker never reached ACTIVE, falls back to a direct backend teardown of
    the VM, switch and differential disk. The ephemeral state-store record is
    removed either way so no half-destroyed VM is left behind.
    """
    if bunker is None:
        return {"success": False, "steps": ["no bunker created"]}
    steps: List[str] = []
    success = False
    bunker_id = bunker.config.id
    try:
        bunker.security_monitor.stop_monitoring()
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("stop_monitoring failed during decon: %s", exc)

    if bunker.state == BunkerState.ACTIVE:
        try:
            ok = bunker.terminate()
            report = getattr(bunker, "_decontamination_report", None)
            if report is not None:
                steps = list(report.steps_completed)
                steps += [f"failed: {s}" for s in report.steps_failed]
                steps += [f"warning: {w}" for w in report.warnings]
                success = report.success
            else:
                steps = _DECON_STEP_NAMES if ok else ["terminate returned failure"]
                success = ok
        except Exception as exc:
            steps = [f"decontamination error: {exc}"]
            success = False
    else:
        # Bunker never became ACTIVE (init/activate failed mid-cycle): tear
        # down whatever resources were allocated, mirroring Bunker._cleanup_on_failure.
        backend = bunker.backend
        if bunker._vm_name:
            try:
                ok = backend.remove_vm(bunker._vm_name, force=True)
                steps.append(f"remove_vm({bunker._vm_name})={'ok' if ok else 'failed'}")
                bunker._vm_name = None
            except Exception as exc:  # pragma: no cover - defensive
                steps.append(f"remove_vm failed: {exc}")
        if bunker._switch_name:
            try:
                ok = backend.remove_switch(bunker._switch_name)
                steps.append(f"remove_switch({bunker._switch_name})={'ok' if ok else 'failed'}")
                bunker._switch_name = None
            except Exception as exc:  # pragma: no cover - defensive
                steps.append(f"remove_switch failed: {exc}")
        diff_vhd = Path("snapshots") / f"{bunker_id}_system.vhdx"
        try:
            if diff_vhd.exists():
                ok = backend.delete_file(str(diff_vhd))
                steps.append(f"delete_file({diff_vhd})={'ok' if ok else 'failed'}")
        except Exception as exc:  # pragma: no cover - defensive
            steps.append(f"delete_file failed: {exc}")
        success = True  # nothing active was leaked once resources are removed

    # Ephemeral bunkers must not accumulate in the persisted state store.
    try:
        get_state_store().delete(bunker_id)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Could not delete ephemeral state for %s: %s", bunker_id, exc)

    return {"success": success, "steps": steps}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyze_sync(
    sample_path,
    *,
    monitor_seconds: float = 5.0,
    execute_timeout: int = 30,
    bunker_config: Optional[BunkerConfig] = None,
    backend=None,
    guest_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Run the full inspect-file cycle synchronously and return the verdict.

    Order of operations:
        1. stage  — validate + hash the host file (SHA-256, integrity check)
        2. ciclo bunker — create/initialize/activate an ephemeral bunker
        3. monitoreo — copy into the guest, execute, monitor for a bounded
           duration
        4. analyze_report — collect IOCs and build the structured report
        5. descontaminar — destroy the bunker (try/finally: ALWAYS runs)
        6. veredicto — return the verdict JSON

    Any failure mid-cycle still decontaminates the bunker and produces a
    verdict of ``error`` with the failure detail in ``decontamination.steps``.

    Args:
        sample_path: Host-accessible path to the sample file.
        monitor_seconds: Bounded monitoring duration after execution.
        execute_timeout: Per guest-command timeout (seconds).
        bunker_config: Optional BunkerConfig override (tests/advanced use).
        backend: Optional hypervisor backend override (tests use this).
        guest_path: Staging path inside the guest.

    Returns:
        The versioned inspect-report dict.

    Raises:
        FileNotFoundError: If the sample path does not exist / is not a file.
    """
    start = time.monotonic()
    path = Path(sample_path)
    if not path.is_file():
        raise FileNotFoundError(f"Sample not found: {sample_path}")

    sample = _hash_sample(path)
    bunker: Optional[Bunker] = None
    iocs: List[IOC] = []
    error: Optional[str] = None
    decon = {"success": False, "steps": []}

    try:
        # 2. Bunker lifecycle.
        config = bunker_config if bunker_config is not None else _default_config()
        bunker = Bunker(config, backend=backend)
        if not bunker.initialize():
            raise RuntimeError("bunker initialize failed")
        if not bunker.activate():
            raise RuntimeError("bunker activate failed")

        # 3. Stage (copy to guest) + execute + bounded monitoring.
        gp = guest_path or _default_guest_path(path.name)
        _stage_to_guest(bunker, path, gp, execute_timeout)
        _execute_sample(bunker, gp, execute_timeout)
        if monitor_seconds > 0:
            time.sleep(monitor_seconds)

        # 4. Build IOCs.
        iocs = _collect_iocs(bunker, path)
    except FileNotFoundError:
        raise
    except Exception as exc:
        logger.error("inspect-file analysis failed: %s", exc)
        error = f"{type(exc).__name__}: {exc}"
    finally:
        # 5. Decontaminate — ALWAYS, even on failure.
        decon = _decontaminate(bunker)

    duration_ms = int((time.monotonic() - start) * 1000)
    return build_inspect_report(
        sample=sample,
        iocs=iocs,
        bunker_id=bunker.config.id if bunker is not None else "",
        duration_ms=duration_ms,
        decontamination=decon,
        error=error,
    )