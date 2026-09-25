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


class SampleTooLarge(LumenosException):
    """A sample exceeds the configured size cap and is refused unread.

    Carries the observed size and the effective limit so the API can answer
    413 without re-stat-ing the file.
    """

    def __init__(self, size_bytes: int, limit_bytes: int):
        self.size_bytes = size_bytes
        self.limit_bytes = limit_bytes
        super().__init__(
            f"Sample is {size_bytes} bytes, over the "
            f"{limit_bytes}-byte limit (see MAX_SAMPLE_SIZE_MB)"
        )


class GuestTelemetryUnavailable(LumenosException):
    """Guest telemetry could not be collected, so its absence proves nothing.

    Raised by a backend that cannot inspect the guest, instead of returning an
    empty result: an empty list means "nothing was found", while this means
    "nothing was looked at". Callers that would otherwise report an all-clear
    must treat it as an infrastructure failure.
    """

    def __init__(self, capability: str, detail: str = ""):
        self.capability = capability
        self.detail = detail
        super().__init__(
            f"guest telemetry unavailable: {capability}"
            + (f" ({detail})" if detail else "")
        )
