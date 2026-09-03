#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DualBunkerManager and __main__ demo entry point."""

import logging
import threading
import time
from typing import Optional, Dict, Any

from .types import BunkerState, BunkerConfig
from .bunker import Bunker

logger = logging.getLogger('LUMENOS_SANDBOX')


class DualBunkerManager:
    """
    Gestor de bunkers duales rotativos.
    Garantiza que solo un bunker esté activo a la vez.
    """

    def __init__(self, base_config: BunkerConfig):
        self.base_config = base_config

        config1 = BunkerConfig(
            id=f"{base_config.id}_1",
            name=f"{base_config.name}-Bunker1",
            **{k: v for k, v in vars(base_config).items() if k not in ['id', 'name']}
        )
        config2 = BunkerConfig(
            id=f"{base_config.id}_2",
            name=f"{base_config.name}-Bunker2",
            **{k: v for k, v in vars(base_config).items() if k not in ['id', 'name']}
        )

        self.bunker1 = Bunker(config1)
        self.bunker2 = Bunker(config2)

        self.active_bunker: Optional[Bunker] = None
        self.inactive_bunker: Optional[Bunker] = None

        self.rotation_count = 0
        self.total_sessions = 0

        self._lock = threading.Lock()

        logger.info(f"Gestor de bunkers duales inicializado: {base_config.id}")

    def start_session(self) -> bool:
        """
        Inicia una nueva sesión de pruebas.
        Rota los bunkers si es necesario.
        """
        with self._lock:
            if self.active_bunker is None:
                logger.info("Iniciando primera sesión - inicializando Bunker 1")

                if not self.bunker1.initialize():
                    logger.error("Fallo inicializando Bunker 1")
                    return False

                if not self.bunker1.activate():
                    logger.error("Fallo activando Bunker 1")
                    return False

                self.active_bunker = self.bunker1
                self.inactive_bunker = self.bunker2

                self.total_sessions += 1
                return True

            if self.active_bunker.state == BunkerState.ACTIVE:
                logger.warning("Ya hay una sesión activa")
                return True

            return self._rotate_bunkers()

    def _rotate_bunkers(self) -> bool:
        """
        Rota los bunkers: cierra el activo, activa el inactivo.
        """
        logger.info("=" * 60)
        logger.info("INICIANDO ROTACIÓN DE BUNKERS")
        logger.info("=" * 60)

        old_active = self.active_bunker
        old_inactive = self.inactive_bunker

        # Only terminate if the old active is still running
        if old_active.state in (BunkerState.ACTIVE, BunkerState.READY):
            logger.info(f"Paso 1: Terminando bunker activo {old_active.config.id}")
            if not old_active.terminate():
                logger.error("Fallo terminando bunker activo")
                old_active.force_quarantine("Fallo en terminación")
                return False

            logger.info("Paso 2: Esperando descontaminación...")
            while old_active.state == BunkerState.DECONTAMINATING:
                time.sleep(1)

            if old_active.state != BunkerState.DESTROYED:
                logger.error(f"Bunker no se destruyó correctamente: {old_active.state}")
                return False
        else:
            logger.info(f"Paso 1: Bunker {old_active.config.id} ya no está activo ({old_active.state.name})")

        logger.info(f"Paso 3: Inicializando nuevo bunker {old_inactive.config.id}")
        if not old_inactive.initialize():
            logger.error("Fallo inicializando nuevo bunker")
            return False

        logger.info(f"Paso 4: Activando nuevo bunker {old_inactive.config.id}")
        if not old_inactive.activate():
            logger.error("Fallo activando nuevo bunker")
            return False

        self.active_bunker = old_inactive
        self.inactive_bunker = old_active

        self.rotation_count += 1
        self.total_sessions += 1

        logger.info("=" * 60)
        logger.info(f"ROTACIÓN COMPLETADA - Total rotaciones: {self.rotation_count}")
        logger.info(f"Bunker activo: {self.active_bunker.config.id}")
        logger.info("=" * 60)

        return True

    def end_session(self) -> bool:
        """Termina la sesión actual."""
        with self._lock:
            if self.active_bunker is None:
                logger.warning("No hay sesión activa")
                return True

            logger.info("Terminando sesión actual")
            result = self.active_bunker.terminate()
            # Prevent double-terminate on next start_session rotation
            self.active_bunker = None
            self.inactive_bunker = None
            return result

    def get_status(self) -> Dict[str, Any]:
        """Obtiene el estado del sistema de bunkers duales."""
        return {
            "rotation_count": self.rotation_count,
            "total_sessions": self.total_sessions,
            "active_bunker": self.active_bunker.config.id if self.active_bunker else None,
            "inactive_bunker": self.inactive_bunker.config.id if self.inactive_bunker else None,
            "bunker1_status": self.bunker1.get_full_status() if self.bunker1 else None,
            "bunker2_status": self.bunker2.get_full_status() if self.bunker2 else None,
            "combined_escape_probability": self._calculate_combined_probability(),
        }

    def _calculate_combined_probability(self) -> float:
        if self.active_bunker is None:
            return 0.0

        base_prob = self.active_bunker.get_escape_probability()
        rotation_factor = 0.99 ** self.rotation_count

        return base_prob * rotation_factor

    def emergency_shutdown(self, reason: str):
        """Apagado de emergencia del sistema."""
        logger.critical(f"APAGADO DE EMERGENCIA: {reason}")

        if self.active_bunker:
            self.active_bunker.force_quarantine(reason)

        if self.inactive_bunker:
            self.inactive_bunker.force_quarantine(reason)


# ---------------------------------------------------------------------------
# __main__ demo
# ---------------------------------------------------------------------------

def main():
    """Función principal de demostración."""
    from .hyperv_client import check_hyper_v_available

    print("=" * 70)
    print("  LUMENOS SANDBOX ARCHITECTURE v2.0.0")
    print("  Sistema de Aislamiento Multinivel para Pruebas de Malware")
    print("  Autor: Irvin Diaz Medorio")
    print("=" * 70)

    hv_available = check_hyper_v_available()
    if not hv_available:
        print("\n  [!] Hyper-V no está disponible en este host.")
        print("  [!] El sandbox requiere Hyper-V habilitado para crear VMs reales.")
        print("  [!] Para habilitarlo, ejecuta como Administrador:")
        print("      Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All")
        print("=" * 70)
        return

    print("\n  [OK] Hyper-V detectado correctamente")

    config = BunkerConfig(
        id="lumenos_prod",
        name="LumenosProduction",
        memory_mb=8192,
        cpu_cores=4,
        disk_gb=100,
        max_session_hours=24,
        decontamination_minutes=30,
    )

    manager = DualBunkerManager(config)

    print("\n[1] Iniciando primera sesión...")
    if manager.start_session():
        print("    ✓ Sesión iniciada exitosamente")
    else:
        print("    ✗ Fallo iniciando sesión")
        return

    print("\n[2] Estado del sistema:")
    status = manager.get_status()
    print(f"    - Bunker activo: {status['active_bunker']}")
    print(f"    - Probabilidad de escape: {status['combined_escape_probability']:.2e}")

    print("\n[3] Estado del bunker activo:")
    bunker_status = status['bunker1_status']
    print(f"    - Estado: {bunker_status['state']}")
    print(f"    - VM Name: {manager.active_bunker._vm_name}")
    print(f"    - Capas activas: {sum(1 for l in bunker_status['security_layers'].values() if l['active'])}/5")

    for layer_name, layer_info in bunker_status['security_layers'].items():
        status_icon = "✓" if layer_info['active'] else "✗"
        print(f"      [{status_icon}] {layer_name}: prob={layer_info['failure_probability']:.0e}")

    print("\n[4] Rotando bunkers...")
    if manager.start_session():
        print("    ✓ Rotación completada")

    print("\n[5] Estado después de rotación:")
    status = manager.get_status()
    print(f"    - Rotaciones totales: {status['rotation_count']}")
    print(f"    - Bunker activo: {status['active_bunker']}")

    print("\n[6] Terminando sesión...")
    if manager.end_session():
        print("    ✓ Sesión terminada")

    print("\n" + "=" * 70)
    print("  Demostración completada exitosamente")
    print("=" * 70)


if __name__ == "__main__":
    main()
