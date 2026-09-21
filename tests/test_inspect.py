"""Tests for inspect-file: synchronous one-shot sample analysis with verdict.

Covers: clean-path verdict, malicious-path verdict (static scan + injected
monitor findings), error-path decontamination, report contract (schema,
verdict derivation, chain-of-custody hash), API endpoint happy path +
validation, and CLI happy path + missing file.
"""
import argparse
import hashlib
import json
import threading
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from lumenos_sandbox.inspect import (
    IOC,
    INSPECT_SCHEMA,
    analyze_sync,
    build_error_report,
    build_inspect_report,
)
from lumenos_sandbox.types import (
    SecurityEvent,
    SecurityLayer,
    ThreatLevel,
)


# ---------------------------------------------------------------------------
# Deterministic guest behaviour (no live pwsh / hypervisor in unit tests)
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def deterministic_guest():
    """Make the monitor's guest-facing checks deterministic for unit tests."""
    patches = [
        patch("lumenos_sandbox.hyperv_client.read_guest_event_log", return_value=[]),
        patch("lumenos_sandbox.hyperv_client.test_guest_connectivity", return_value=True),
        patch(
            "lumenos_sandbox.hyperv_client.check_guest_vbs_status",
            return_value={"vbs_enabled": True, "hvci_enabled": False, "secure_boot": True},
        ),
        patch("lumenos_sandbox.hyperv_client.get_guest_processes", return_value=[]),
        patch("lumenos_sandbox.hyperv_client.execute_in_guest", return_value=(True, "")),
    ]
    for p in patches:
        p.start()
    yield
    for p in patches:
        p.stop()


@pytest.fixture
def sample_file(tmp_path):
    """A clean (non-malicious) sample file."""
    p = tmp_path / "clean_sample.bin"
    p.write_bytes(b"benign payload content")
    return str(p)


# ---------------------------------------------------------------------------
# Report contract
# ---------------------------------------------------------------------------

class TestInspectReportContract:
    """The verdict report must match the versioned contract shape."""

    def test_clean_report_shape(self, sample_file):
        report = analyze_sync(sample_file, monitor_seconds=0)

        assert sorted(report.keys()) == [
            "bunker_id", "chain_of_custody", "confidence", "decontamination",
            "duration_ms", "iocs", "sample", "schema", "score", "verdict",
        ]
        assert report["schema"] == INSPECT_SCHEMA
        assert report["verdict"] == "clean"
        assert report["confidence"] == 1.0
        assert report["score"] == 0
        assert report["sample"]["sha256"]
        assert report["sample"]["size"] == len(b"benign payload content")
        assert report["chain_of_custody"]["valid"] is True
        assert len(report["chain_of_custody"]["hash"]) == 64
        assert report["decontamination"]["success"] is True
        assert report["decontamination"]["steps"]
        assert report["bunker_id"].startswith("inspect-")
        assert isinstance(report["duration_ms"], int)

    def test_clean_report_has_no_iocs(self, sample_file):
        report = analyze_sync(sample_file, monitor_seconds=0)
        assert report["iocs"] == []

    def test_verdict_malicious_on_critical_ioc(self):
        report = build_inspect_report(
            sample={"path": "/s", "sha256": "a" * 64, "size": 1},
            iocs=[IOC(type="process", value="injection", severity="critical",
                      evidence="CreateRemoteThread")],
            bunker_id="b", duration_ms=1,
        )
        assert report["verdict"] == "malicious"
        assert report["score"] == 100

    def test_verdict_malicious_on_high_ioc(self):
        report = build_inspect_report(
            sample={"path": "/s", "sha256": "a" * 64, "size": 1},
            iocs=[IOC(type="network", value="beacon", severity="high")],
            bunker_id="b", duration_ms=1,
        )
        assert report["verdict"] == "malicious"

    def test_verdict_suspicious_on_medium_ioc(self):
        report = build_inspect_report(
            sample={"path": "/s", "sha256": "a" * 64, "size": 1},
            iocs=[IOC(type="persistence", value="Run key", severity="medium")],
            bunker_id="b", duration_ms=1,
        )
        assert report["verdict"] == "suspicious"

    def test_verdict_error_overrides_iocs(self):
        report = build_inspect_report(
            sample={"path": "/s", "sha256": "", "size": 0},
            iocs=[IOC(type="process", value="x", severity="critical")],
            bunker_id="b", duration_ms=1, error="boom",
        )
        assert report["verdict"] == "error"
        assert report["confidence"] == 0.0

    def test_error_detail_lands_in_decontamination_steps(self):
        report = build_inspect_report(
            sample={"path": "/s", "sha256": "", "size": 0},
            iocs=[], bunker_id="b", duration_ms=1, error="host exploded",
        )
        assert any("host exploded" in s for s in report["decontamination"]["steps"])

    def test_chain_of_custody_hash_is_recomputable(self):
        report = build_inspect_report(
            sample={"path": "/s", "sha256": "b" * 64, "size": 2},
            iocs=[IOC(type="file", value="artifact", severity="low")],
            bunker_id="b", duration_ms=5,
        )
        recomputed = json.loads(json.dumps(report))
        recomputed["chain_of_custody"] = {"hash": "", "valid": True}
        canonical = json.dumps(recomputed, sort_keys=True, indent=2)
        assert report["chain_of_custody"]["hash"] == (
            hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        )

    def test_invalid_ioc_type_rejected(self):
        with pytest.raises(ValueError):
            IOC(type="bogus", value="x", severity="low")

    def test_build_error_report(self):
        report = build_error_report("/missing.bin", RuntimeError("nope"))
        assert report["verdict"] == "error"
        assert "RuntimeError: nope" in report["decontamination"]["steps"][-1]


# ---------------------------------------------------------------------------
# Full cycle verdicts
# ---------------------------------------------------------------------------

class TestAnalyzeSync:
    """End-to-end cycle with the default (Mock) backend."""

    def test_clean_path(self, sample_file):
        report = analyze_sync(sample_file, monitor_seconds=0)
        assert report["verdict"] == "clean"
        assert report["iocs"] == []
        assert report["decontamination"]["success"] is True
        assert report["bunker_id"]

    def test_malicious_path_via_static_scan(self, tmp_path):
        p = tmp_path / "evil.txt"
        p.write_text("CreateRemoteThread WriteProcessMemory mimikatz")
        report = analyze_sync(str(p), monitor_seconds=0)
        assert report["verdict"] == "malicious"
        assert any(
            i["severity"] in ("high", "critical") for i in report["iocs"]
        )

    def test_unknown_pattern_category_surfaces_conservatively(self, tmp_path, monkeypatch):
        """An unlisted pattern category must not be silently downgraded to
        file/medium: the fallback surfaces it as process/high so a potential
        indicator keeps a malicious weighted verdict."""
        import lumenos_sandbox.inspect as inspect_mod

        # Drop every known category: any static finding is now "unknown".
        monkeypatch.setattr(inspect_mod, "_PATTERN_CATEGORY_TO_IOC", {})

        p = tmp_path / "unknown-category.txt"
        p.write_text("CreateRemoteThread WriteProcessMemory")
        report = analyze_sync(str(p), monitor_seconds=0)

        static_iocs = [i for i in report["iocs"] if i["value"]]
        assert static_iocs
        assert all(
            i["type"] == "process" and i["severity"] == "high"
            for i in static_iocs
        )
        assert report["verdict"] == "malicious"

    def test_malicious_path_via_monitor_findings(self, tmp_path, monkeypatch):
        """Inject a critical monitor finding: the monitor used by the bunker
        logs a CRITICAL injection event when constructed."""
        import lumenos_sandbox.bunker as bunker_mod
        from lumenos_sandbox.monitoring import SecurityMonitor as RealMonitor

        def evil_monitor(*args, **kwargs):
            monitor = RealMonitor(*args, **kwargs)
            monitor.log_event(SecurityEvent(
                timestamp=datetime.now(),
                layer=SecurityLayer.PROCESS,
                event_type="REMOTE_THREAD_INJECTION",
                severity=ThreatLevel.CRITICAL,
                description="CreateRemoteThread observed in guest",
                bunker_id=args[0],
            ))
            return monitor

        monkeypatch.setattr(bunker_mod, "SecurityMonitor", evil_monitor)

        p = tmp_path / "sample.bin"
        p.write_bytes(b"data")
        report = analyze_sync(str(p), monitor_seconds=0)
        assert report["verdict"] == "malicious"
        assert any(
            i["type"] == "process" and i["severity"] == "critical"
            for i in report["iocs"]
        )

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            analyze_sync(str(tmp_path / "ghost.bin"), monitor_seconds=0)

    def test_error_path_still_decontaminates(self, tmp_path, monkeypatch):
        """If activation fails mid-cycle, the verdict must be error and the
        bunker resources must still be torn down (no leaked VM)."""
        import lumenos_sandbox.bunker as bunker_mod

        monkeypatch.setattr(bunker_mod.Bunker, "activate", lambda self: False)

        p = tmp_path / "sample.bin"
        p.write_bytes(b"data")
        report = analyze_sync(str(p), monitor_seconds=0)

        assert report["verdict"] == "error"
        assert any("bunker activate failed" in s for s in report["decontamination"]["steps"])
        assert report["bunker_id"]
        # No VM/switch left behind: cleanup steps recorded for the allocated
        # resources (the mock backend removes them).
        assert report["decontamination"]["success"] is True

    def test_deadline_abort_raises_and_still_decontaminates(self, tmp_path, monkeypatch):
        """R4-1: once the overall deadline is exhausted the cycle aborts by
        raising, and the finally decontamination still destroys the bunker —
        no orphaned VM/switch is left behind on the abort path."""
        import lumenos_sandbox.inspect as inspect_mod
        from lumenos_sandbox.hypervisor.mock_backend import MockBackend

        removed = {"vm": [], "switch": []}
        real_remove_vm = MockBackend.remove_vm
        real_remove_switch = MockBackend.remove_switch

        def spy_remove_vm(self, vm_name, force=True):
            removed["vm"].append(vm_name)
            return real_remove_vm(self, vm_name, force)

        def spy_remove_switch(self, switch_name):
            removed["switch"].append(switch_name)
            return real_remove_switch(self, switch_name)

        monkeypatch.setattr(MockBackend, "remove_vm", spy_remove_vm)
        monkeypatch.setattr(MockBackend, "remove_switch", spy_remove_switch)

        # Force the blocking step to outlive the deadline while the bunker is
        # ACTIVE, so the abort happens with allocated resources to tear down.
        monkeypatch.setattr(inspect_mod, "_execute_sample", lambda *a, **k: time.sleep(1))

        p = tmp_path / "slow.bin"
        p.write_bytes(b"data")

        with pytest.raises(inspect_mod.AnalysisDeadlineExceeded):
            analyze_sync(str(p), monitor_seconds=0, timeout_seconds=0.2)

        assert removed["vm"], "deadline abort must still destroy the VM"
        assert removed["switch"], "deadline abort must still destroy the switch"

    def test_deadline_caps_guest_command_timeout(self, tmp_path, monkeypatch):
        """The configured per-command timeout must be reduced to the remaining
        deadline budget (never below 1 s) so a slow guest command cannot run
        past the overall cap."""
        from lumenos_sandbox.hypervisor.base import BackendResult
        from lumenos_sandbox.hypervisor.mock_backend import MockBackend

        seen = []

        def recording_execute(self, vm_name, username, password, command, timeout=30):
            seen.append(timeout)
            return BackendResult(True, "", "")

        monkeypatch.setattr(MockBackend, "execute_in_guest", recording_execute)

        p = tmp_path / "sample.bin"
        p.write_bytes(b"data")
        analyze_sync(str(p), monitor_seconds=0, execute_timeout=30, timeout_seconds=5.0)

        assert seen, "sample execution must reach the backend"
        assert all(1 <= t <= 5 for t in seen), seen


class TestInterruptibleTailBudget:
    """R4-001: the uninterruptible tail must respect the cycle deadline."""

    def test_hash_sample_aborts_when_budget_already_exhausted(self, tmp_path):
        import lumenos_sandbox.inspect as inspect_mod

        p = tmp_path / "s.bin"; p.write_bytes(b"data")
        with pytest.raises(inspect_mod.AnalysisDeadlineExceeded):
            inspect_mod._hash_sample(p, time.monotonic() - 1.0, 5.0)

    def test_initialize_with_exhausted_deadline_skips_backend(self, monkeypatch):
        from lumenos_sandbox.bunker import Bunker
        from lumenos_sandbox.inspect import AnalysisDeadlineExceeded
        from lumenos_sandbox.types import BunkerConfig

        steps = []
        monkeypatch.setattr(Bunker, "_verify_system_requirements", lambda self: steps.append("verify"))
        monkeypatch.setattr(Bunker, "_load_base_image", lambda self: steps.append("load"))
        bunker = Bunker(BunkerConfig(id="dl", name="dl"))
        with pytest.raises(AnalysisDeadlineExceeded):
            bunker.initialize(deadline=time.monotonic() - 1.0)
        assert steps == []


# ---------------------------------------------------------------------------
# API endpoint
# ---------------------------------------------------------------------------

class TestAnalyzeSyncAPI:
    """POST /analyze-sync — happy path, validation errors, timeout path."""

    @pytest.fixture(autouse=True)
    def _client(self, tmp_path, monkeypatch):
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient
        from lumenos_sandbox.api import app

        monkeypatch.setenv("LUMENOS_API_TOKEN", "test-token")
        monkeypatch.setenv("LUMENOS_SAMPLES_ROOT", str(tmp_path))
        with TestClient(app) as client:
            client.headers["Authorization"] = "Bearer test-token"
            yield client

    def test_endpoint_happy_path(self, _client, sample_file):
        r = _client.post(
            "/analyze-sync",
            json={"sample_path": sample_file, "monitor_seconds": 0},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["schema"] == INSPECT_SCHEMA
        assert data["verdict"] == "clean"
        assert data["decontamination"]["success"] is True

    def test_endpoint_missing_sample_file(self, _client, tmp_path):
        r = _client.post(
            "/analyze-sync",
            json={"sample_path": str(tmp_path / "ghost.bin"), "monitor_seconds": 0},
        )
        assert r.status_code == 400
        assert "not found" in r.json()["detail"].lower()

    def test_endpoint_validation_error(self, _client):
        # Missing required sample_path -> pydantic 422.
        r = _client.post("/analyze-sync", json={"monitor_seconds": 0})
        assert r.status_code == 422

    def test_endpoint_timeout_path(self, _client, sample_file, monkeypatch):
        """A worker stuck in the uninterruptible tail must surface as 504, not
        hang the API. The caller waits ``timeout_seconds`` plus the teardown
        margin, so the test shortens that margin and keeps the hang just long
        enough to outlive it — proving 504 is reserved for the residual tail."""
        import lumenos_sandbox.api as api_mod

        monkeypatch.setattr(api_mod, "_ANALYSIS_TEARDOWN_MARGIN_SECONDS", 0.3)

        def hang(*args, **kwargs):
            time.sleep(2)
            return {}

        monkeypatch.setattr(api_mod, "_run_analysis", hang)
        r = _client.post(
            "/analyze-sync",
            json={
                "sample_path": sample_file,
                "monitor_seconds": 0,
                "timeout_seconds": 0.2,
            },
        )
        assert r.status_code == 504

    def test_worker_receives_forwarded_deadline(self, _client, sample_file, monkeypatch):
        """The endpoint must forward ``payload.timeout_seconds`` into the
        analysis worker — not merely use it as the caller's wait cap."""
        import lumenos_sandbox.inspect as inspect_mod

        captured = {}

        def spy(sample_path, *, monitor_seconds=5.0, execute_timeout=30,
                timeout_seconds=None, **kwargs):
            captured["timeout_seconds"] = timeout_seconds
            captured["sample_path"] = sample_path
            return {
                "schema": INSPECT_SCHEMA,
                "verdict": "clean",
                "confidence": 1.0,
                "score": 0,
                "sample": {},
                "iocs": [],
                "chain_of_custody": {"hash": "", "valid": True},
                "decontamination": {"success": True, "steps": []},
                "bunker_id": "spy",
                "duration_ms": 0,
            }

        monkeypatch.setattr(inspect_mod, "analyze_sync", spy)

        r = _client.post(
            "/analyze-sync",
            json={
                "sample_path": sample_file,
                "monitor_seconds": 0,
                "timeout_seconds": 7.5,
            },
        )

        assert r.status_code == 200
        assert captured["timeout_seconds"] == 7.5
        assert captured["sample_path"] == sample_file

    def test_endpoint_deadline_aborts_with_structured_error(self, _client, tmp_path):
        """A request whose work outlives its deadline must abort on its own
        deadline (cooperatively) and yield the structured error verdict
        instead of hanging until the caller's wait expires."""
        p = tmp_path / "slow.bin"
        p.write_bytes(b"data")

        started = time.monotonic()
        r = _client.post(
            "/analyze-sync",
            json={
                "sample_path": str(p),
                "monitor_seconds": 30,
                "timeout_seconds": 0.3,
            },
        )
        elapsed = time.monotonic() - started

        assert r.status_code == 200
        assert r.json()["verdict"] == "error"
        assert elapsed < 10, f"deadline was not honoured cooperatively: {elapsed:.1f}s"

    def test_capacity_recovers_after_deadline_abort(self, _client, tmp_path, monkeypatch):
        """R4-1 core criterion: an analysis that expires on its own deadline
        while holding an admission slot must release that slot, so capacity is
        restored and a subsequent request is admitted and executes (not 503)."""
        import lumenos_sandbox.api as api_mod

        # Single-slot pool: if the deadline-aborted worker leaked its slot,
        # the follow-up request would be refused with 503.
        monkeypatch.setattr(api_mod, "_analysis_slots", threading.BoundedSemaphore(1))

        p = tmp_path / "slow.bin"
        p.write_bytes(b"data")

        first = _client.post(
            "/analyze-sync",
            json={
                "sample_path": str(p),
                "monitor_seconds": 30,
                "timeout_seconds": 0.3,
            },
        )
        assert first.status_code == 200
        assert first.json()["verdict"] == "error"

        # Observable recovery: capacity is available again.
        second = _client.post(
            "/analyze-sync",
            json={"sample_path": str(p), "monitor_seconds": 0},
        )
        assert second.status_code == 200
        assert second.json()["verdict"] == "clean"


    # --- R1: bearer auth + sample-root confinement -------------------------

    def test_auth_missing_token_is_401(self, _client, sample_file):
        r = _client.post("/analyze-sync", headers={"Authorization": ""},
                         json={"sample_path": sample_file, "monitor_seconds": 0})
        assert r.status_code == 401

    def test_auth_wrong_token_is_401(self, _client, sample_file):
        r = _client.post("/analyze-sync", headers={"Authorization": "Bearer wrong"},
                         json={"sample_path": sample_file, "monitor_seconds": 0})
        assert r.status_code == 401

    def test_auth_unconfigured_token_fails_closed_503(self, _client, sample_file, monkeypatch):
        monkeypatch.delenv("LUMENOS_API_TOKEN", raising=False)
        r = _client.post("/analyze-sync", headers={"Authorization": "Bearer test-token"},
                         json={"sample_path": sample_file, "monitor_seconds": 0})
        assert r.status_code == 503

    def test_auth_sample_outside_root_is_403(self, _client, sample_file):
        outside = Path(sample_file).parent.parent / "r1_outside.bin"
        outside.write_bytes(b"x")
        r = _client.post("/analyze-sync", headers={"Authorization": "Bearer test-token"},
                         json={"sample_path": str(outside), "monitor_seconds": 0})
        assert r.status_code == 403

    def test_auth_sibling_prefix_dir_is_403(self, _client, tmp_path, monkeypatch):
        # A `startswith` check would wrongly authorize "/…/samples-evil" under
        # root "/…/samples"; the resolved-containment test must reject it.
        root = tmp_path / "samples"; root.mkdir()
        evil = tmp_path / "samples-evil"; evil.mkdir()
        (evil / "p.bin").write_bytes(b"x")
        monkeypatch.setenv("LUMENOS_SAMPLES_ROOT", str(root))
        r = _client.post("/analyze-sync", headers={"Authorization": "Bearer test-token"},
                         json={"sample_path": str(evil / "p.bin"), "monitor_seconds": 0})
        assert r.status_code == 403

    def test_auth_valid_token_in_root_succeeds(self, _client, sample_file):
        r = _client.post("/analyze-sync", headers={"Authorization": "Bearer test-token"},
                         json={"sample_path": sample_file, "monitor_seconds": 0})
        assert r.status_code == 200 and r.json()["verdict"] == "clean"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _inspect_args(archivo, monitor_seconds=0.0, execute_timeout=30, timeout_seconds=None):
    return argparse.Namespace(
        archivo=archivo,
        monitor_seconds=monitor_seconds,
        execute_timeout=execute_timeout,
        timeout_seconds=timeout_seconds,
    )


class TestInspectFileCLI:
    """lumenos-sandbox inspect-file <archivo>."""

    def test_cli_happy_path(self, capsys, sample_file):
        from lumenos_sandbox.cli import cmd_inspect_file

        rc = cmd_inspect_file(_inspect_args(sample_file))
        out = capsys.readouterr().out
        assert rc == 0
        data = json.loads(out)
        assert data["schema"] == INSPECT_SCHEMA
        assert data["verdict"] == "clean"

    def test_cli_malicious_exit_zero(self, capsys, tmp_path):
        """A malicious verdict is still a verdict: exit 0."""
        from lumenos_sandbox.cli import cmd_inspect_file

        p = tmp_path / "evil.bin"
        p.write_bytes(b"CreateRemoteThread mimikatz")
        rc = cmd_inspect_file(_inspect_args(str(p)))
        out = capsys.readouterr().out
        assert rc == 0
        assert json.loads(out)["verdict"] == "malicious"

    def test_cli_missing_file(self, capsys, tmp_path):
        from lumenos_sandbox.cli import cmd_inspect_file

        rc = cmd_inspect_file(_inspect_args(str(tmp_path / "ghost.bin")))
        captured = capsys.readouterr()
        assert rc == 1
        assert "not found" in captured.err.lower()
        assert captured.out == ""

    def test_subcommand_registered(self, monkeypatch, capsys):
        """'inspect-file' must be wired into the argparse dispatch."""
        import sys
        from lumenos_sandbox.cli import main

        monkeypatch.setattr(sys, "argv", ["lumenos", "inspect-file", "--help"])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        assert "inspect-file" in capsys.readouterr().out

    def test_cli_forwards_timeout_seconds(self, capsys, sample_file, monkeypatch):
        """--timeout-seconds must be forwarded to analyze_sync as the overall
        deadline (mirroring the API bound)."""
        import lumenos_sandbox.inspect as inspect_mod
        from lumenos_sandbox.cli import cmd_inspect_file

        captured = {}

        def spy(sample_path, *, monitor_seconds=5.0, execute_timeout=30,
                timeout_seconds=None, **kwargs):
            captured["timeout_seconds"] = timeout_seconds
            return {"schema": INSPECT_SCHEMA, "verdict": "clean"}

        monkeypatch.setattr(inspect_mod, "analyze_sync", spy)

        rc = cmd_inspect_file(_inspect_args(sample_file, timeout_seconds=42.0))

        assert rc == 0
        assert captured["timeout_seconds"] == 42.0

    def test_cli_report_without_verdict_fails_closed(self, capsys, sample_file, monkeypatch):
        """A malformed report must fail closed with the documented [FAIL]
        message and exit 1 instead of a bare KeyError traceback."""
        import lumenos_sandbox.inspect as inspect_mod
        from lumenos_sandbox.cli import cmd_inspect_file

        monkeypatch.setattr(
            inspect_mod, "analyze_sync", lambda *a, **k: {"schema": INSPECT_SCHEMA}
        )

        rc = cmd_inspect_file(_inspect_args(sample_file))
        captured = capsys.readouterr()

        assert rc == 1
        assert "[FAIL]" in captured.err

    def test_cli_timeout_seconds_flag_registered(self, monkeypatch, capsys):
        """The CLI must expose --timeout-seconds on inspect-file."""
        import sys
        from lumenos_sandbox.cli import main

        monkeypatch.setattr(
            sys, "argv", ["lumenos", "inspect-file", "--help"]
        )
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        assert "--timeout-seconds" in capsys.readouterr().out

    def test_cli_timeout_seconds_rejects_out_of_range(self, monkeypatch, capsys, tmp_path):
        """--timeout-seconds mirrors the API bound: must be > 0 and <= 3600."""
        import sys
        from lumenos_sandbox.cli import main

        sample = tmp_path / "s.bin"
        sample.write_bytes(b"data")
        monkeypatch.setattr(
            sys,
            "argv",
            ["lumenos", "inspect-file", str(sample), "--timeout-seconds", "0"],
        )
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 2
        assert "timeout-seconds" in capsys.readouterr().err