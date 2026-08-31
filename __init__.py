# LUMENOS SANDBOX ARCHITECTURE
# Paquete Principal
# Autor: Irvin Diaz Medorio
# Versión: 2.0.0

"""
LUMENOS SANDBOX ARCHITECTURE
Sistema de Aislamiento Multinivel para Pruebas de Malware en Windows

Este paquete proporciona un sistema de sandboxing de alta seguridad
con garantías matemáticas de aislamiento (< 10^-40 probabilidad de escape).

Uso básico:
    from lumenos_sandbox import BunkerConfig, DualBunkerManager

    config = BunkerConfig(id="mi_sandbox", name="MiSandbox")
    manager = DualBunkerManager(config)
    manager.start_session()
"""

__version__ = "2.0.0"
__author__ = "Irvin Diaz Medorio"
__email__ = ""
__copyright__ = "Copyright © 2026 Irvin Diaz Medorio"

from lumenos_sandbox import *  # noqa: F401,F403
