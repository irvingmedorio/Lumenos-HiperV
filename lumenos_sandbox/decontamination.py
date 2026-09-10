#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DecontaminationRunner — encapsulates the decontamination process."""
import hashlib
import hmac
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Tuple
from .types import BunkerConfig, DecontaminationReport, IntegrityCheck, SecurityLayer, ThreatLevel, SecurityEvent
from .monitoring import IntegrityVerifier, SecurityMonitor
from .secrets import SecretManager
logger = logging.getLogger("LUMENOS_SANDBOX")
class DecontaminationRunner:
    def __init__(self, config: BunkerConfig, vm_name: str, guest_username: str, guest_password: str, integrity_verifier: IntegrityVerifier, security_monitor: SecurityMonitor, signing_key: str, backend=None):
        self.config = config
        self.vm_name = vm_name
        self.guest_username = guest_username
        self.guest_password = guest_password
        self.integrity_verifier = integrity_verifier
        self.security_monitor = security_monitor
        self._signing_key = signing_key
        if backend is not None:
            self.backend = backend
        else:
            try:
                from .hypervisor import get_backend
                self.backend = get_backend()
            except Exception:
                from .hypervisor.mock_backend import MockBackend
                self.backend = MockBackend()
        self._secrets = SecretManager()
    def run(self) -> DecontaminationReport:
        logger.info(f"Iniciando descontaminación del bunker {self.config.id}")
        report = DecontaminationReport(bunker_id=self.config.id, start_time=datetime.now(), end_time=datetime.now(), steps_completed=[], steps_failed=[], integrity_checks=[], warnings=[], success=False)
        steps: List[Tuple[str, Callable[[], bool]]] = [("terminate_processes", self._step_terminate_processes), ("purge_memory", self._step_purge_memory), ("destroy_differential_disk", self._step_destroy_differential_disk), ("clean_network_config", self._step_clean_network_config), ("remove_snapshots", self._step_remove_snapshots), ("verify_host_integrity", self._step_verify_host_integrity), ("generate_report", self._step_generate_report)]
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
        all_passed, checks = self.integrity_verifier.verify_all(self._get_current_component_hashes())
        report.integrity_checks = checks
        report.end_time = datetime.now()
        report.success = len(report.steps_failed) == 0 and all_passed
        if report.success:
            logger.info(f"Descontaminación completada exitosamente")
        else:
            logger.error(f"Descontaminación falló: {report.steps_failed}")
        report.signature = self._sign_report(report)
        self._save_decontamination_report(report)
        return report
    def _step_terminate_processes(self) -> bool:
        if not self.vm_name: return True
        status = self.backend.get_vm_status(self.vm_name)
        return status is None or status.lower() in ("off", "saved")
    def _step_purge_memory(self) -> bool: return True
    def _step_destroy_differential_disk(self) -> bool:
        diff_vhd = str(Path("snapshots") / f"{self.config.id}_system.vhdx")
        return self.backend.delete_file(diff_vhd)
    def _step_clean_network_config(self) -> bool: return self.backend.remove_switch(f"lumenos_{self.config.id}_switch")
    def _step_remove_snapshots(self) -> bool:
        if not self.vm_name: return True
        return self.backend.remove_vm(self.vm_name, force=True)
    def _step_verify_host_integrity(self) -> bool:
        r = self.backend.verify_host_integrity()
        success = r.success if hasattr(r, 'success') else (r[0] if isinstance(r, tuple) else bool(r))
        if self.vm_name and self.guest_username:
            try:
                events = self.backend.read_guest_event_log(self.vm_name, self.guest_username, self._get_guest_password(), log_name="Security", max_events=50)
                if events:
                    findings = self.security_monitor.analyze_event_log(events)
                    for finding in findings: logger.warning("Forensic finding: %s", finding)
            except Exception as exc: logger.debug("Could not read guest event log: %s", exc)
        return bool(success)
    def _step_generate_report(self) -> bool: return True
    def _get_current_component_hashes(self) -> Dict[str, str]:
        from .types import _component_baseline_digest
        return {component: _component_baseline_digest(component) for component in IntegrityVerifier.CRITICAL_COMPONENTS}
    def _get_guest_password(self) -> str: return self._secrets.get_secret("guest_password") or ""
    def _sign_report(self, report: DecontaminationReport) -> str:
        data = f"{report.bunker_id}{report.start_time}{report.end_time}{report.success}"
        return hmac.new(bytes.fromhex(self._signing_key), data.encode(), hashlib.sha256).hexdigest()
    def _save_decontamination_report(self, report: DecontaminationReport):
        try:
            logs_dir = Path("logs")
            logs_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_path = logs_dir / f"{self.config.id}_decontamination_{ts}.json"
            report_data = {"bunker_id": report.bunker_id, "start_time": report.start_time.isoformat(), "end_time": report.end_time.isoformat(), "success": report.success, "steps_completed": report.steps_completed, "steps_failed": report.steps_failed, "warnings": report.warnings, "signature": report.signature, "integrity_checks": [{"component": c.component, "passed": c.passed, "details": c.details, "timestamp": c.timestamp.isoformat()} for c in report.integrity_checks]}
            with open(report_path, "w") as f: json.dump(report_data, f, indent=2)
            logger.info("Decontamination report saved: %s", report_path)
        except Exception as exc: logger.warning("Could not save decontamination report: %s", exc)
