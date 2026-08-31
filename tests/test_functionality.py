#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LUMENOS SANDBOX - TESTS DE FUNCIONALIDAD
Pruebas exhaustivas del sistema de aislamiento

Autor: Irvin Diaz Medorio
Version: 1.0.0
"""

import unittest
import sys
import os
import time
import threading
from datetime import datetime
from unittest.mock import patch, MagicMock

# Agregar directorio raíz al path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lumenos_sandbox import (
    Bunker, BunkerConfig, BunkerState, BunkerMetrics, SecurityEvent,
    DualBunkerManager, SecurityLayer, ThreatLevel,
    IntegrityVerifier, SecurityMonitor,
    LumenosException, InvalidStateTransition, SecurityViolation,
    EscapeAttempt, EscapeAttemptType,
    NetworkSecurityLayer, FilesystemSecurityLayer,
    ProcessSecurityLayer, MemorySecurityLayer, HypervisorSecurityLayer,
)


class TestBunkerConfig(unittest.TestCase):
    """Pruebas de configuración del bunker."""
    
    def test_create_default_config(self):
        """Verifica creación de configuración por defecto."""
        config = BunkerConfig(id="test_1", name="TestBunker")
        
        self.assertEqual(config.id, "test_1")
        self.assertEqual(config.name, "TestBunker")
        self.assertEqual(config.memory_mb, 8192)
        self.assertEqual(config.cpu_cores, 4)
        self.assertTrue(config.enable_network_isolation)
    
    def test_create_custom_config(self):
        """Verifica creación de configuración personalizada."""
        config = BunkerConfig(
            id="custom_1",
            name="CustomBunker",
            memory_mb=16384,
            cpu_cores=8,
            max_session_hours=48
        )
        
        self.assertEqual(config.memory_mb, 16384)
        self.assertEqual(config.cpu_cores, 8)
        self.assertEqual(config.max_session_hours, 48)

    def test_guest_config_defaults(self):
        """Verifica que BunkerConfig tiene campos de guest con valores por defecto."""
        config = BunkerConfig(id="g", name="G")
        self.assertEqual(config.guest_username, "Administrator")
        self.assertEqual(config.guest_password, "")
        self.assertFalse(config.sysmon_installed)
        self.assertIn("Sysmon64", config.sysmon_path)


class TestBunkerStates(unittest.TestCase):
    """Pruebas de transiciones de estado del bunker."""
    
    def setUp(self):
        """Configuración inicial para cada prueba."""
        self.config = BunkerConfig(id="state_test", name="StateTest")
        self.bunker = Bunker(self.config)
    
    def test_initial_state(self):
        """Verifica que el estado inicial es DESTROYED."""
        self.assertEqual(self.bunker.state, BunkerState.DESTROYED)
    
    def test_valid_transition(self):
        """Verifica transición válida de estado."""
        self.bunker.state = BunkerState.INITIALIZING
        self.assertTrue(self.bunker.transition_to(BunkerState.READY))
        self.assertEqual(self.bunker.state, BunkerState.READY)
    
    def test_invalid_transition(self):
        """Verifica que transiciones inválidas lanzan excepción."""
        self.bunker.state = BunkerState.DESTROYED
        
        with self.assertRaises(InvalidStateTransition):
            self.bunker.transition_to(BunkerState.ACTIVE)  # Debe pasar por INITIALIZING primero
    
    def test_full_lifecycle(self):
        """Verifica el ciclo de vida completo del bunker."""
        # DESTROYED -> INITIALIZING
        self.bunker.state = BunkerState.INITIALIZING
        
        # INITIALIZING -> READY
        self.bunker.transition_to(BunkerState.READY)
        self.assertEqual(self.bunker.state, BunkerState.READY)
        
        # READY -> ACTIVE
        self.bunker.transition_to(BunkerState.ACTIVE)
        self.assertEqual(self.bunker.state, BunkerState.ACTIVE)
        
        # ACTIVE -> TERMINATING
        self.bunker.transition_to(BunkerState.TERMINATING)
        self.assertEqual(self.bunker.state, BunkerState.TERMINATING)
        
        # TERMINATING -> DECONTAMINATING
        self.bunker.transition_to(BunkerState.DECONTAMINATING)
        self.assertEqual(self.bunker.state, BunkerState.DECONTAMINATING)
        
        # DECONTAMINATING -> DESTROYED
        self.bunker.transition_to(BunkerState.DESTROYED)
        self.assertEqual(self.bunker.state, BunkerState.DESTROYED)


class TestSecurityLayers(unittest.TestCase):
    """Pruebas de las capas de seguridad."""
    
    def setUp(self):
        self.bunker_id = "security_test"
    
    def test_network_layer_activation(self):
        """Verifica activación de capa de red."""
        layer = NetworkSecurityLayer(self.bunker_id)
        
        self.assertFalse(layer.active)
        result = layer.activate()
        self.assertTrue(result)
        self.assertTrue(layer.active)
    
    def test_filesystem_layer_activation(self):
        """Verifica activación de capa de archivos."""
        layer = FilesystemSecurityLayer(self.bunker_id)
        
        result = layer.activate()
        self.assertTrue(result)
        self.assertTrue(layer.active)
    
    def test_process_layer_activation(self):
        """Verifica activación de capa de procesos."""
        layer = ProcessSecurityLayer(self.bunker_id)
        
        result = layer.activate()
        self.assertTrue(result)
        self.assertTrue(layer.active)
    
    def test_memory_layer_activation(self):
        """Verifica activación de capa de memoria."""
        layer = MemorySecurityLayer(self.bunker_id)
        
        result = layer.activate()
        self.assertTrue(result)
        self.assertTrue(layer.active)
    
    def test_hypervisor_layer_activation(self):
        """Verifica activación de capa de hipervisor."""
        layer = HypervisorSecurityLayer(self.bunker_id)
        
        result = layer.activate()
        self.assertTrue(result)
        self.assertTrue(layer.active)
    
    def test_layer_failure_probability(self):
        """Verifica probabilidades de fallo de cada capa."""
        network = NetworkSecurityLayer(self.bunker_id)
        filesystem = FilesystemSecurityLayer(self.bunker_id)
        process = ProcessSecurityLayer(self.bunker_id)
        memory = MemorySecurityLayer(self.bunker_id)
        hypervisor = HypervisorSecurityLayer(self.bunker_id)
        
        self.assertEqual(network.get_failure_probability(), 1e-6)
        self.assertEqual(filesystem.get_failure_probability(), 1e-8)
        self.assertEqual(process.get_failure_probability(), 1e-5)
        self.assertEqual(memory.get_failure_probability(), 1e-9)
        self.assertEqual(hypervisor.get_failure_probability(), 1e-12)
    
    def test_layer_verification(self):
        """Verifica que las capas pasan verificación."""
        layer = NetworkSecurityLayer(self.bunker_id)
        layer.activate()
        
        result = layer.verify()
        self.assertTrue(result)
    
    def test_layer_deactivation(self):
        """Verifica desactivación de capas."""
        layer = NetworkSecurityLayer(self.bunker_id)
        layer.activate()
        
        result = layer.deactivate()
        self.assertTrue(result)
        self.assertFalse(layer.active)

    def test_set_vm_credentials(self):
        """Verifica que set_vm_credentials configura los atributos internos."""
        layer = NetworkSecurityLayer(self.bunker_id)
        layer.set_vm_credentials("test_vm", "admin", "pass123")
        self.assertEqual(layer._vm_name, "test_vm")
        self.assertEqual(layer._username, "admin")
        self.assertEqual(layer._password, "pass123")

    def test_verify_without_vm_returns_active(self):
        """Verifica que verify() sin VM retorna el estado active."""
        layer = NetworkSecurityLayer(self.bunker_id)
        layer.activate()
        self.assertTrue(layer.verify())
        layer.deactivate()
        self.assertFalse(layer.verify())

    @patch("lumenos_sandbox.hypervisor.enable_guest_integration", return_value=True)
    @patch("lumenos_sandbox.hypervisor.configure_guest_firewall", return_value=True)
    def test_network_activate_calls_guest_firewall(self, mock_fw, mock_integ):
        """Verifica que activate llama configure_guest_firewall."""
        layer = NetworkSecurityLayer(self.bunker_id)
        layer.set_vm_credentials("test_vm", "admin", "pass")
        layer.activate()
        mock_integ.assert_called_once()
        mock_fw.assert_called_once()

    @patch("lumenos_sandbox.hypervisor.test_guest_connectivity", return_value=True)
    def test_network_verify_guest_blocked(self, mock_conn):
        """Verifica que verify retorna True cuando el guest está bloqueado."""
        layer = NetworkSecurityLayer(self.bunker_id)
        layer.set_vm_credentials("test_vm", "admin", "pass")
        layer.activate()
        self.assertTrue(layer.verify())
        mock_conn.assert_called_once()

    @patch("lumenos_sandbox.hypervisor.test_guest_connectivity", return_value=False)
    def test_network_verify_guest_reachable(self, mock_conn):
        """Verifica que verify retorna False cuando el guest puede salir."""
        layer = NetworkSecurityLayer(self.bunker_id)
        layer.set_vm_credentials("test_vm", "admin", "pass")
        layer.activate()
        self.assertFalse(layer.verify())

    @patch("lumenos_sandbox.hypervisor.get_guest_processes", return_value=[
        {"Id": 1, "ProcessName": "mimikatz", "CPU": 1.0, "WorkingSet64": 4096},
    ])
    def test_process_verify_suspicious_detected(self, mock_proc):
        """Verifica que process layer detecta mimikatz."""
        layer = ProcessSecurityLayer(self.bunker_id)
        layer.set_vm_credentials("test_vm", "admin", "pass")
        layer.activate()
        self.assertFalse(layer.verify())

    @patch("lumenos_sandbox.hypervisor.get_guest_processes", return_value=[
        {"Id": 1, "ProcessName": "notepad", "CPU": 0.1, "WorkingSet64": 1024},
    ])
    def test_process_verify_clean(self, mock_proc):
        """Verifica que process layer pasa con procesos limpios."""
        layer = ProcessSecurityLayer(self.bunker_id)
        layer.set_vm_credentials("test_vm", "admin", "pass")
        layer.activate()
        self.assertTrue(layer.verify())

    @patch("lumenos_sandbox.hypervisor.check_guest_vbs_status",
           return_value={"vbs_enabled": True, "hvci_enabled": False, "secure_boot": True})
    def test_memory_verify_vbs_enabled(self, mock_vbs):
        """Verifica que memory layer verifica VBS."""
        layer = MemorySecurityLayer(self.bunker_id)
        layer.set_vm_credentials("test_vm", "admin", "pass")
        layer.activate()
        self.assertTrue(layer.verify())

    @patch("lumenos_sandbox.hypervisor.check_guest_vbs_status",
           return_value={"vbs_enabled": False, "hvci_enabled": False, "secure_boot": False})
    def test_memory_verify_vbs_disabled(self, mock_vbs):
        """Verifica que memory layer falla cuando VBS está deshabilitado."""
        layer = MemorySecurityLayer(self.bunker_id)
        layer.set_vm_credentials("test_vm", "admin", "pass")
        layer.activate()
        self.assertFalse(layer.verify())

    @patch("lumenos_sandbox.hypervisor.check_guest_registry", return_value=[])
    def test_filesystem_verify_no_persistence(self, mock_reg):
        """Verifica que filesystem layer pasa sin persistencia."""
        layer = FilesystemSecurityLayer(self.bunker_id)
        layer.set_vm_credentials("test_vm", "admin", "pass")
        layer.activate()
        self.assertTrue(layer.verify())

    @patch("lumenos_sandbox.hypervisor.check_guest_registry",
           return_value=[{"Default": "malware.exe"}])
    def test_filesystem_verify_persistence_detected(self, mock_reg):
        """Verifica que filesystem layer detecta persistencia."""
        layer = FilesystemSecurityLayer(self.bunker_id)
        layer.set_vm_credentials("test_vm", "admin", "pass")
        layer.activate()
        self.assertFalse(layer.verify())


class TestIntegrityVerifier(unittest.TestCase):
    """Pruebas del verificador de integridad."""
    
    def setUp(self):
        self.verifier = IntegrityVerifier()
    
    def test_compute_hash(self):
        """Verifica computación de hash."""
        data = b"test_data"
        hash1 = self.verifier.compute_hash(data)
        hash2 = self.verifier.compute_hash(data)
        
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 128)  # SHA-512 produce 128 caracteres hex
    
    def test_set_baseline(self):
        """Verifica establecimiento de baseline."""
        test_hash = "a" * 128
        self.verifier.set_baseline("test_component", test_hash)
        
        self.assertIn("test_component", self.verifier.baseline_hashes)
        self.assertEqual(self.verifier.baseline_hashes["test_component"], test_hash)
    
    def test_verify_component_pass(self):
        """Verifica verificación exitosa de componente."""
        test_hash = "b" * 128
        self.verifier.set_baseline("test_comp", test_hash)
        
        check = self.verifier.verify_component("test_comp", test_hash)
        
        self.assertTrue(check.passed)
        self.assertEqual(check.expected_hash, test_hash)
        self.assertEqual(check.actual_hash, test_hash)
    
    def test_verify_component_fail(self):
        """Verifica detección de componente comprometido."""
        expected_hash = "c" * 128
        actual_hash = "d" * 128
        self.verifier.set_baseline("compromised_comp", expected_hash)
        
        check = self.verifier.verify_component("compromised_comp", actual_hash)
        
        self.assertFalse(check.passed)
        self.assertIn("COMPROMISO", check.details)
    
    def test_verify_all(self):
        """Verifica verificación de todos los componentes."""
        # Establecer baselines
        for comp in IntegrityVerifier.CRITICAL_COMPONENTS:
            self.verifier.set_baseline(comp, "e" * 128)
        
        # Verificar con hashes correctos
        current_hashes = {
            comp: "e" * 128 
            for comp in IntegrityVerifier.CRITICAL_COMPONENTS
        }
        
        all_passed, results = self.verifier.verify_all(current_hashes)
        
        self.assertTrue(all_passed)
        self.assertEqual(len(results), len(IntegrityVerifier.CRITICAL_COMPONENTS))


class TestSecurityMonitor(unittest.TestCase):
    """Pruebas del monitor de seguridad."""
    
    def setUp(self):
        self.monitor = SecurityMonitor("test_bunker")
    
    def test_log_event(self):
        """Verifica registro de eventos."""
        event = SecurityEvent(
            timestamp=datetime.now(),
            layer=SecurityLayer.NETWORK,
            event_type="TEST_EVENT",
            severity=ThreatLevel.LOW,
            description="Evento de prueba",
            bunker_id="test_bunker"
        )
        
        self.monitor.log_event(event)
        
        self.assertEqual(len(self.monitor.events), 1)
        self.assertEqual(self.monitor.events[0].event_type, "TEST_EVENT")
    
    def test_detect_escape_attempt(self):
        """Verifica detección de intento de escape."""
        result = self.monitor.detect_escape_attempt(
            EscapeAttemptType.NETWORK_EXFILTRATION,
            "Intento de exfiltración detectado"
        )
        
        self.assertTrue(result)
        self.assertEqual(len(self.monitor.escape_attempts), 1)
        self.assertIn(EscapeAttemptType.NETWORK_EXFILTRATION, self.monitor.escape_attempts)
    
    def test_analyze_patterns(self):
        """Verifica análisis de patrones sospechosos."""
        suspicious_data = "VBOX VMware virtualbox qemu hypervisor"
        
        detected = self.monitor.analyze_patterns(suspicious_data)
        
        self.assertGreater(len(detected), 0)
        self.assertTrue(any("vm_escape_indicators" in d for d in detected))
    
    def test_security_report(self):
        """Verifica generación de reporte de seguridad."""
        # Agregar algunos eventos
        for i in range(5):
            event = SecurityEvent(
                timestamp=datetime.now(),
                layer=SecurityLayer.NETWORK,
                event_type=f"EVENT_{i}",
                severity=ThreatLevel.LOW if i < 3 else ThreatLevel.HIGH,
                description=f"Evento {i}",
                bunker_id="test_bunker"
            )
            self.monitor.log_event(event)
        
        report = self.monitor.get_security_report()
        
        self.assertEqual(report["total_events"], 5)
        self.assertEqual(report["events_by_severity"]["LOW"], 3)
        self.assertEqual(report["events_by_severity"]["HIGH"], 2)

    def test_analyze_event_log_sysmon_injection(self):
        """Verifica detección de inyección via Sysmon Event ID 8."""
        events = [
            {"Id": 8, "ProcessName": "mimikatz.exe", "Message": "CreateRemoteThread into lsass"},
        ]
        findings = self.monitor.analyze_event_log(events)
        self.assertTrue(any("injection" in f.lower() or "CreateRemoteThread" in f for f in findings))

    def test_analyze_event_log_sysmon_process_access(self):
        """Verifica detección de ProcessAccess via Sysmon Event ID 10."""
        events = [
            {"Id": 10, "ProcessName": "procdump.exe", "Message": "ProcessAccess to lsass.exe"},
        ]
        findings = self.monitor.analyze_event_log(events)
        self.assertTrue(any("ProcessAccess" in f or "process access" in f.lower() for f in findings))

    def test_analyze_event_log_suspicious_pattern(self):
        """Verifica que analyze_event_log escanea patrones sospechosos en Message."""
        events = [
            {"Id": 1, "ProcessName": "test.exe", "Message": "VBOX detected in environment"},
        ]
        findings = self.monitor.analyze_event_log(events)
        self.assertTrue(any("vm_escape_indicators" in f for f in findings))

    def test_analyze_event_log_empty(self):
        """Verifica que analyze_event_log con eventos vacíos retorna lista vacía."""
        self.assertEqual(self.monitor.analyze_event_log([]), [])


class TestBunker(unittest.TestCase):
    """Pruebas del bunker completo."""

    def setUp(self):
        self.config = BunkerConfig(id="bunker_test", name="BunkerTest")
        self.bunker = Bunker(self.config)

    @patch("lumenos_sandbox.hypervisor.check_hyper_v_available", return_value=True)
    @patch("lumenos_sandbox.hypervisor.create_internal_switch", return_value=True)
    @patch("lumenos_sandbox.hypervisor.create_vm", return_value=True)
    @patch("lumenos_sandbox.hypervisor.enable_guest_integration", return_value=True)
    def test_initialize(self, mock_integ, mock_create_vm, mock_create_switch, mock_hv):
        """Verifica inicialización del bunker."""
        result = self.bunker.initialize()

        self.assertTrue(result)
        self.assertEqual(self.bunker.state, BunkerState.READY)
        self.assertIsNotNone(self.bunker.created_at)
        self.assertIsNotNone(self.bunker._vm_name)
        self.assertIsNotNone(self.bunker._switch_name)
        mock_hv.assert_called_once()
        mock_create_switch.assert_called_once()
        mock_create_vm.assert_called_once()
        mock_integ.assert_called_once()
    
    def test_activate_without_initialize(self):
        """Verifica que no se puede activar sin inicializar."""
        with self.assertRaises(InvalidStateTransition):
            self.bunker.activate()

    @patch("lumenos_sandbox.hypervisor.check_hyper_v_available", return_value=True)
    @patch("lumenos_sandbox.hypervisor.create_internal_switch", return_value=True)
    @patch("lumenos_sandbox.hypervisor.create_vm", return_value=True)
    @patch("lumenos_sandbox.hypervisor.enable_guest_integration", return_value=True)
    @patch("lumenos_sandbox.hypervisor.configure_guest_firewall", return_value=True)
    @patch("lumenos_sandbox.hypervisor.test_guest_connectivity", return_value=True)
    @patch("lumenos_sandbox.hypervisor.get_guest_processes", return_value=[{"Id": 1, "ProcessName": "System"}])
    @patch("lumenos_sandbox.hypervisor.check_guest_vbs_status",
           return_value={"vbs_enabled": True, "hvci_enabled": False, "secure_boot": True})
    @patch("lumenos_sandbox.hypervisor.check_guest_registry", return_value=[])
    @patch("lumenos_sandbox.hypervisor.create_checkpoint", return_value=True)
    @patch("lumenos_sandbox.hypervisor.stop_vm", return_value=True)
    @patch("lumenos_sandbox.hypervisor.get_vm_status", return_value="Off")
    @patch("lumenos_sandbox.hypervisor.delete_file", return_value=True)
    @patch("lumenos_sandbox.hypervisor.remove_switch", return_value=True)
    @patch("lumenos_sandbox.hypervisor.remove_vm", return_value=True)
    @patch("lumenos_sandbox.hypervisor.verify_host_integrity", return_value=(True, "OK"))
    @patch("lumenos_sandbox.hypervisor.read_guest_event_log", return_value=[])
    def test_full_activation_cycle(self, *mocks):
        """Verifica ciclo completo de activación."""
        # Inicializar
        self.bunker.initialize()
        self.assertEqual(self.bunker.state, BunkerState.READY)

        # Activar
        result = self.bunker.activate()
        self.assertTrue(result)
        self.assertEqual(self.bunker.state, BunkerState.ACTIVE)

        # Verificar capas activas
        for layer in self.bunker.security_layers.values():
            self.assertTrue(layer.active)

    @patch("lumenos_sandbox.hypervisor.check_hyper_v_available", return_value=True)
    @patch("lumenos_sandbox.hypervisor.create_internal_switch", return_value=True)
    @patch("lumenos_sandbox.hypervisor.create_vm", return_value=True)
    @patch("lumenos_sandbox.hypervisor.enable_guest_integration", return_value=True)
    @patch("lumenos_sandbox.hypervisor.configure_guest_firewall", return_value=True)
    @patch("lumenos_sandbox.hypervisor.test_guest_connectivity", return_value=True)
    @patch("lumenos_sandbox.hypervisor.get_guest_processes", return_value=[{"Id": 1, "ProcessName": "System"}])
    @patch("lumenos_sandbox.hypervisor.check_guest_vbs_status",
           return_value={"vbs_enabled": True, "hvci_enabled": False, "secure_boot": True})
    @patch("lumenos_sandbox.hypervisor.check_guest_registry", return_value=[])
    @patch("lumenos_sandbox.hypervisor.create_checkpoint", return_value=True)
    @patch("lumenos_sandbox.hypervisor.stop_vm", return_value=True)
    @patch("lumenos_sandbox.hypervisor.get_vm_status", return_value="Off")
    @patch("lumenos_sandbox.hypervisor.delete_file", return_value=True)
    @patch("lumenos_sandbox.hypervisor.remove_switch", return_value=True)
    @patch("lumenos_sandbox.hypervisor.remove_vm", return_value=True)
    @patch("lumenos_sandbox.hypervisor.verify_host_integrity", return_value=(True, "OK"))
    @patch("lumenos_sandbox.hypervisor.read_guest_event_log", return_value=[])
    def test_terminate(self, *mocks):
        """Verifica terminación del bunker."""
        self.bunker.initialize()
        self.bunker.activate()

        result = self.bunker.terminate()
        self.assertTrue(result)
        self.assertEqual(self.bunker.state, BunkerState.DESTROYED)

    @patch("lumenos_sandbox.hypervisor.check_hyper_v_available", return_value=True)
    @patch("lumenos_sandbox.hypervisor.create_internal_switch", return_value=True)
    @patch("lumenos_sandbox.hypervisor.create_vm", return_value=True)
    @patch("lumenos_sandbox.hypervisor.enable_guest_integration", return_value=True)
    @patch("lumenos_sandbox.hypervisor.configure_guest_firewall", return_value=True)
    @patch("lumenos_sandbox.hypervisor.test_guest_connectivity", return_value=True)
    @patch("lumenos_sandbox.hypervisor.get_guest_processes", return_value=[{"Id": 1, "ProcessName": "System"}])
    @patch("lumenos_sandbox.hypervisor.check_guest_vbs_status",
           return_value={"vbs_enabled": True, "hvci_enabled": False, "secure_boot": True})
    @patch("lumenos_sandbox.hypervisor.check_guest_registry", return_value=[])
    def test_force_quarantine(self, *mocks):
        """Verifica cuarentena forzada."""
        self.bunker.initialize()
        self.bunker.activate()

        self.bunker.force_quarantine("Test de cuarentena")

        self.assertEqual(self.bunker.state, BunkerState.QUARANTINE)

    @patch("lumenos_sandbox.hypervisor.check_hyper_v_available", return_value=True)
    @patch("lumenos_sandbox.hypervisor.create_internal_switch", return_value=True)
    @patch("lumenos_sandbox.hypervisor.create_vm", return_value=True)
    @patch("lumenos_sandbox.hypervisor.enable_guest_integration", return_value=True)
    @patch("lumenos_sandbox.hypervisor.configure_guest_firewall", return_value=True)
    @patch("lumenos_sandbox.hypervisor.test_guest_connectivity", return_value=True)
    @patch("lumenos_sandbox.hypervisor.get_guest_processes", return_value=[{"Id": 1, "ProcessName": "System"}])
    @patch("lumenos_sandbox.hypervisor.check_guest_vbs_status",
           return_value={"vbs_enabled": True, "hvci_enabled": False, "secure_boot": True})
    @patch("lumenos_sandbox.hypervisor.check_guest_registry", return_value=[])
    def test_escape_probability_calculation(self, *mocks):
        """Verifica cálculo de probabilidad de escape."""
        self.bunker.initialize()
        self.bunker.activate()

        prob = self.bunker.get_escape_probability()

        # La probabilidad debe ser el producto de todas las capas
        expected = 1e-6 * 1e-8 * 1e-5 * 1e-9 * 1e-12  # = 1e-40
        self.assertAlmostEqual(prob, expected, places=45)

    @patch("lumenos_sandbox.hypervisor.check_hyper_v_available", return_value=True)
    @patch("lumenos_sandbox.hypervisor.create_internal_switch", return_value=True)
    @patch("lumenos_sandbox.hypervisor.create_vm", return_value=True)
    @patch("lumenos_sandbox.hypervisor.enable_guest_integration", return_value=True)
    @patch("lumenos_sandbox.hypervisor.configure_guest_firewall", return_value=True)
    @patch("lumenos_sandbox.hypervisor.test_guest_connectivity", return_value=True)
    @patch("lumenos_sandbox.hypervisor.get_guest_processes", return_value=[{"Id": 1, "ProcessName": "System"}])
    @patch("lumenos_sandbox.hypervisor.check_guest_vbs_status",
           return_value={"vbs_enabled": True, "hvci_enabled": False, "secure_boot": True})
    @patch("lumenos_sandbox.hypervisor.check_guest_registry", return_value=[])
    def test_get_full_status(self, *mocks):
        """Verifica obtención de estado completo."""
        self.bunker.initialize()
        self.bunker.activate()

        status = self.bunker.get_full_status()

        self.assertIn("config", status)
        self.assertIn("state", status)
        self.assertIn("security_layers", status)
        self.assertIn("metrics", status)
        self.assertEqual(status["state"], "ACTIVE")


class TestDualBunkerManager(unittest.TestCase):
    """Pruebas del gestor de bunkers duales."""
    
    def setUp(self):
        self.config = BunkerConfig(id="dual_test", name="DualTest")
        self.manager = DualBunkerManager(self.config)

    def test_initial_state(self):
        """Verifica estado inicial del gestor."""
        self.assertIsNone(self.manager.active_bunker)
        self.assertEqual(self.manager.rotation_count, 0)

    @patch("lumenos_sandbox.hypervisor.check_hyper_v_available", return_value=True)
    @patch("lumenos_sandbox.hypervisor.create_internal_switch", return_value=True)
    @patch("lumenos_sandbox.hypervisor.create_vm", return_value=True)
    @patch("lumenos_sandbox.hypervisor.enable_guest_integration", return_value=True)
    @patch("lumenos_sandbox.hypervisor.configure_guest_firewall", return_value=True)
    @patch("lumenos_sandbox.hypervisor.test_guest_connectivity", return_value=True)
    @patch("lumenos_sandbox.hypervisor.get_guest_processes", return_value=[{"Id": 1, "ProcessName": "System"}])
    @patch("lumenos_sandbox.hypervisor.check_guest_vbs_status",
           return_value={"vbs_enabled": True, "hvci_enabled": False, "secure_boot": True})
    @patch("lumenos_sandbox.hypervisor.check_guest_registry", return_value=[])
    def test_start_first_session(self, *mocks):
        """Verifica inicio de primera sesión."""
        result = self.manager.start_session()

        self.assertTrue(result)
        self.assertIsNotNone(self.manager.active_bunker)
        self.assertEqual(self.manager.active_bunker.state, BunkerState.ACTIVE)
        self.assertEqual(self.manager.total_sessions, 1)

    @patch("lumenos_sandbox.hypervisor.check_hyper_v_available", return_value=True)
    @patch("lumenos_sandbox.hypervisor.create_internal_switch", return_value=True)
    @patch("lumenos_sandbox.hypervisor.create_vm", return_value=True)
    @patch("lumenos_sandbox.hypervisor.enable_guest_integration", return_value=True)
    @patch("lumenos_sandbox.hypervisor.configure_guest_firewall", return_value=True)
    @patch("lumenos_sandbox.hypervisor.test_guest_connectivity", return_value=True)
    @patch("lumenos_sandbox.hypervisor.get_guest_processes", return_value=[{"Id": 1, "ProcessName": "System"}])
    @patch("lumenos_sandbox.hypervisor.check_guest_vbs_status",
           return_value={"vbs_enabled": True, "hvci_enabled": False, "secure_boot": True})
    @patch("lumenos_sandbox.hypervisor.check_guest_registry", return_value=[])
    @patch("lumenos_sandbox.hypervisor.create_checkpoint", return_value=True)
    @patch("lumenos_sandbox.hypervisor.stop_vm", return_value=True)
    @patch("lumenos_sandbox.hypervisor.get_vm_status", return_value="Off")
    @patch("lumenos_sandbox.hypervisor.delete_file", return_value=True)
    @patch("lumenos_sandbox.hypervisor.remove_switch", return_value=True)
    @patch("lumenos_sandbox.hypervisor.remove_vm", return_value=True)
    @patch("lumenos_sandbox.hypervisor.verify_host_integrity", return_value=(True, "OK"))
    @patch("lumenos_sandbox.hypervisor.read_guest_event_log", return_value=[])
    def test_bunker_rotation(self, *mocks):
        """Verifica rotación de bunkers."""
        self.assertTrue(self.manager.start_session())
        first_bunker = self.manager.active_bunker
        first_active = first_bunker.config.id
        self.assertEqual(self.manager.rotation_count, 0)

        result = self.manager._rotate_bunkers()

        self.assertTrue(result)
        second_active = self.manager.active_bunker.config.id
        self.assertNotEqual(second_active, first_active)
        self.assertIs(self.manager.inactive_bunker, first_bunker)
        self.assertEqual(self.manager.active_bunker.state, BunkerState.ACTIVE)
        self.assertEqual(self.manager.inactive_bunker.state, BunkerState.DESTROYED)
        self.assertEqual(self.manager.rotation_count, 1)
        self.assertEqual(self.manager.total_sessions, 2)

    @patch("lumenos_sandbox.hypervisor.check_hyper_v_available", return_value=True)
    @patch("lumenos_sandbox.hypervisor.create_internal_switch", return_value=True)
    @patch("lumenos_sandbox.hypervisor.create_vm", return_value=True)
    @patch("lumenos_sandbox.hypervisor.enable_guest_integration", return_value=True)
    @patch("lumenos_sandbox.hypervisor.configure_guest_firewall", return_value=True)
    @patch("lumenos_sandbox.hypervisor.test_guest_connectivity", return_value=True)
    @patch("lumenos_sandbox.hypervisor.get_guest_processes", return_value=[{"Id": 1, "ProcessName": "System"}])
    @patch("lumenos_sandbox.hypervisor.check_guest_vbs_status",
           return_value={"vbs_enabled": True, "hvci_enabled": False, "secure_boot": True})
    @patch("lumenos_sandbox.hypervisor.check_guest_registry", return_value=[])
    @patch("lumenos_sandbox.hypervisor.create_checkpoint", return_value=True)
    @patch("lumenos_sandbox.hypervisor.stop_vm", return_value=True)
    @patch("lumenos_sandbox.hypervisor.get_vm_status", return_value="Off")
    @patch("lumenos_sandbox.hypervisor.delete_file", return_value=True)
    @patch("lumenos_sandbox.hypervisor.remove_switch", return_value=True)
    @patch("lumenos_sandbox.hypervisor.remove_vm", return_value=True)
    @patch("lumenos_sandbox.hypervisor.verify_host_integrity", return_value=(True, "OK"))
    @patch("lumenos_sandbox.hypervisor.read_guest_event_log", return_value=[])
    def test_end_session(self, *mocks):
        """Verifica terminación de sesión."""
        self.manager.start_session()

        result = self.manager.end_session()

        self.assertTrue(result)

    @patch("lumenos_sandbox.hypervisor.check_hyper_v_available", return_value=True)
    @patch("lumenos_sandbox.hypervisor.create_internal_switch", return_value=True)
    @patch("lumenos_sandbox.hypervisor.create_vm", return_value=True)
    @patch("lumenos_sandbox.hypervisor.enable_guest_integration", return_value=True)
    @patch("lumenos_sandbox.hypervisor.configure_guest_firewall", return_value=True)
    @patch("lumenos_sandbox.hypervisor.test_guest_connectivity", return_value=True)
    @patch("lumenos_sandbox.hypervisor.get_guest_processes", return_value=[{"Id": 1, "ProcessName": "System"}])
    @patch("lumenos_sandbox.hypervisor.check_guest_vbs_status",
           return_value={"vbs_enabled": True, "hvci_enabled": False, "secure_boot": True})
    @patch("lumenos_sandbox.hypervisor.check_guest_registry", return_value=[])
    def test_combined_probability(self, *mocks):
        """Verifica cálculo de probabilidad combinada."""
        self.manager.start_session()

        prob = self.manager._calculate_combined_probability()

        self.assertGreater(prob, 0)
        self.assertLess(prob, 1e-30)

    @patch("lumenos_sandbox.hypervisor.check_hyper_v_available", return_value=True)
    @patch("lumenos_sandbox.hypervisor.create_internal_switch", return_value=True)
    @patch("lumenos_sandbox.hypervisor.create_vm", return_value=True)
    @patch("lumenos_sandbox.hypervisor.enable_guest_integration", return_value=True)
    @patch("lumenos_sandbox.hypervisor.configure_guest_firewall", return_value=True)
    @patch("lumenos_sandbox.hypervisor.test_guest_connectivity", return_value=True)
    @patch("lumenos_sandbox.hypervisor.get_guest_processes", return_value=[{"Id": 1, "ProcessName": "System"}])
    @patch("lumenos_sandbox.hypervisor.check_guest_vbs_status",
           return_value={"vbs_enabled": True, "hvci_enabled": False, "secure_boot": True})
    @patch("lumenos_sandbox.hypervisor.check_guest_registry", return_value=[])
    def test_emergency_shutdown(self, *mocks):
        """Verifica apagado de emergencia."""
        self.manager.start_session()

        self.manager.emergency_shutdown("Test de emergencia")

        self.assertEqual(self.manager.active_bunker.state, BunkerState.QUARANTINE)


class TestBunkerMetrics(unittest.TestCase):
    """Pruebas de métricas del bunker."""
    
    def test_default_metrics(self):
        """Verifica valores por defecto de métricas."""
        metrics = BunkerMetrics()
        
        self.assertEqual(metrics.cpu_usage, 0.0)
        self.assertEqual(metrics.memory_usage, 0.0)
        self.assertEqual(metrics.network_packets_blocked, 0)
        self.assertEqual(metrics.escape_attempts_blocked, 0)


if __name__ == "__main__":
    # Ejecutar todas las pruebas
    unittest.main(verbosity=2)
