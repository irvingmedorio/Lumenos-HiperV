#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Custom exceptions for LumenOS Sandbox."""

from .types import EscapeAttemptType


class LumenosException(Exception):
    """Excepción base del sistema Lumenos."""
    pass


class InvalidStateTransition(LumenosException):
    """Transición de estado no válida."""
    pass


class SecurityViolation(LumenosException):
    """Violación de seguridad detectada."""
    pass


class EscapeAttempt(SecurityViolation):
    """Intento de escape del bunker detectado."""
    def __init__(self, escape_type: EscapeAttemptType, details: str):
        self.escape_type = escape_type
        self.details = details
        super().__init__(f"Escape attempt detected: {escape_type.value} - {details}")


class DecontaminationFailure(LumenosException):
    """Fallo en el proceso de descontaminación."""
    pass


class IntegrityCheckFailure(LumenosException):
    """Fallo en verificación de integridad."""
    pass


class BunkerNotReady(LumenosException):
    """El bunker no está listo para la operación solicitada."""
    pass
