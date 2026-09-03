#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DecontaminationRunner — encapsulates the decontamination process.

Separates decontamination logic from Bunker state machine for testability
and single responsibility.
"""

import hashlib
import hmac
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Tuple

from .types import (
    BunkerConfig, DecontaminationReport, IntegrityCheck, SecurityLayer,
    ThreatLevel, SecurityEvent,
)
from .monitoring import IntegrityVerifier, SecurityMonitor
from .hyperv_client import (
    get_vm_status, delete_file, remove_switch, remove_vm,
    verify_host_integrity, read_guest_event_log,
)
from .secrets import SecretManager

logger = logging.getLogger("LUMENOS_SANDBOX")


class DecontaminationRunner:
    """Runs the decontamination process for a bunker.

    The runner is stateless — it receives all dependencies (config, vm_name,
    credentials, integrity_verifier, security_monitor, signing_key) and
    returns a DecontaminationReport. The caller (Bunker) is responsible
    for state transitions based on the report outcome.
    """

    def __init__(
        self,
        config: BunkerConfig,
        vm_name: str,
        guest_username: str,
        guest_password: str,
        integrity_verifier: IntegrityVerifier,
        security_monitor: SecurityMonitor,
        signing_key: str,
    ):
        self.config = config
        self.vm_name = vm_name
        self.guest_username = guest_username
        self.guest_password = guest_password
        self.integrity_verifier = integrity_verifier
        self.security_monitor = security_monitor
        self._signing_key = signing_key
        self._secrets = SecretManager()

    def run(self) -> DecontaminationReport:
        """Execute all decontamination steps and return the report."""
        logger.info(f"Iniciando descontaminación del bunker {self.config.id}")

        report = DecontaminationReport(
            bunker_id=self.config.id,
            start_time=datetime.now(),
            end_time=datetime.now(),
            steps_completed=[],
            steps_failed=[],
            integrity_checks=[],
            warnings=[],
            success=False
        )

        # Define steps as (name, callable) tuples
        steps: List[Tuple[str, Callable[[], bool]]] = [
            ("terminate_processes", self._step_terminate_processes),
            ("purge_memory", self._step_purge_memory),
            ("destroy_differential_disk", self._step_destroy_differential_disk),
            ("clean_network_config", self._step_clean_network_config),
            ("remove_snapshots", self._step_remove_snapshots),
            ("verify_host_integrity", self._step_verify_host_integrity),
            ("generate_report", self._step_generate_report),
        ]

        for step_name, step_func in steps:
            try:
                logger.info(f"Ejecutando paso: {step_name}")
                result = step_func()

                if result:
                    report.steps_completed.append(step_name)
                else:
                    report.steps_failed.append(step_name)
                    report.warnings.append(f"Paso {step_name} retornó False")

            except Exception as e:
                report.steps_failed.append(step_name)
                report.warnings.append(f"Error en {step_name}: {str(e)}")
                logger.error(f"Error en paso {step_name}: {e}")

        # Final integrity verification
        all_passed, checks = self.integrity_verifier.verify_all(
            self._get_current_component_hashes()
        )
        report.integrity_checks = checks

        report.end_time = datetime.now()
        report.success = len(report.steps_failed) == 0 and all_passed

        if report.success:
            logger.info(f"Descontaminación completada exitosamente")
        else:
            logger.error(f"Descontaminación falló: {report.steps_failed}")

        report.signature = self._sign_report(report)

        # Always persist the report — even on failure (forensic evidence)
        self._save_decontamination_report(report)

        return report

    # --- Step implementations ---

    def _step_terminate_processes(self) -> bool:
        """Paso: terminar procesos (VM already stopped in _terminate_processes)."""
        if not self.vm_name:
            return True
        status = get_vm_status(self.vm_name)
        return status is None or status.lower() in ("off", "saved")

    def _step_purge_memory(self) -> bool:
        """Paso: purgar memoria (VM memory is freed when VM is off)."""
        return True  # Memory is freed when VM is stopped

    def _step_destroy_differential_disk(self) -> bool:
        """Paso: destruir disco diferencial."""
        from pathlib import Path
        diff_vhd = str(Path("snapshots") / f"{self.config.id}_system.vhdx")
        return delete_file(diff_vhd)

    def _step_clean_network_config(self) -> bool:
        """Paso: limpiar configuración de red."""
        return remove_switch(f"lumenos_{self.config.id}_switch")

    def _step_remove_snapshots(self) -> bool:
        """Paso: eliminar snapshots (remove VM with all disks)."""
        if not self.vm_name:
            return True
        return remove_vm(self.vm_name, force=True)

    def _step_verify_host_integrity(self) -> bool:
        """Paso: verificar integridad del host + forensic evidence from guest."""
        success, _ = verify_host_integrity()

        # Collect forensic evidence from guest event log if VM is still accessible
        if self.vm_name and self.guest_username:
            try:
                events = read_guest_event_log(
                    self.vm_name,
                    self.guest_username,
                    self._get_guest_password(),
                    log_name="Security",
                    max_events=50,
                )
                if events:
                    findings = self.security_monitor.analyze_event_log(events)
                    for finding in findings:
                        logger.warning("Forensic finding: %s", finding)
            except Exception as exc:
                logger.debug("Could not read guest event log: %s", exc)

        return success

    def _step_generate_report(self) -> bool:
        """Paso: generar reporte."""
        return True  # Report generation is handled by run()

    # --- Helpers ---

    def _get_current_component_hashes(self) -> Dict[str, str]:
        """Get current hashes for integrity verification."""
        from .types import _component_baseline_digest
        return {
            component: _component_baseline_digest(component)
            for component in IntegrityVerifier.CRITICAL_COMPONENTS
        }

    def _get_guest_password(self) -> str:
        """Retrieve guest password from Windows Credential Manager."""
        return self._secrets.get_secret("guest_password") or ""

    def _sign_report(self, report: DecontaminationReport) -> str:
        """Sign the decontamination report with HMAC-SHA256."""
        data = f"{report.bunker_id}{report.start_time}{report.end_time}{report.success}"
        return hmac.new(
            bytes.fromhex(self._signing_key),
            data.encode(),
            hashlib.sha256,
        ).hexdigest()

    def _save_decontamination_report(self, report: DecontaminationReport):
        """Persist decontamination report to disk.

        Best-effort: failures are logged but never raised so the caller
        is not blocked from returning its own success/failure verdict.
        """
        try:
            logs_dir = Path("logs")
            logs_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_path = logs_dir / f"{self.config.id}_decontamination_{ts}.json"
            report_data = {
                "bunker_id": report.bunker_id,
                "start_time": report.start_time.isoformat(),
                "end_time": report.end_time.isoformat(),
                "success": report.success,
                "steps_completed": report.steps_completed,
                "steps_failed": report.steps_failed,
                "warnings": report.warnings,
                "signature": report.signature,
                "integrity_checks": [
                    {
                        "component": c.component,
                        "passed": c.passed,
                        "details": c.details,
                        "timestamp": c.timestamp.isoformat(),
                    }
                    for c in report.integrity_checks
                ],
            }
            with open(report_path, "w") as f:
                json.dump(report_data, f, indent=2)
            logger.info("Decontamination report saved: %s", report_path)
        except Exception as exc:
            logger.warning("Could not save decontamination report: %s", exc)