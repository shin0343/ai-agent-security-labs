"""Bounded application errors mapped to stable API error envelopes."""

from __future__ import annotations


class WorkbenchError(Exception):
    status_code = 400
    code = "BAD_REQUEST"

    def __init__(self, message: str, *, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class NotFoundError(WorkbenchError):
    status_code = 404
    code = "NOT_FOUND"


class ConflictError(WorkbenchError):
    status_code = 409
    code = "CONFLICT"


class ForbiddenError(WorkbenchError):
    status_code = 403
    code = "FORBIDDEN"


class UnauthorizedError(WorkbenchError):
    status_code = 401
    code = "UNAUTHENTICATED"


class ValidationError(WorkbenchError):
    status_code = 422
    code = "VALIDATION_ERROR"


class AuditIntegrityError(WorkbenchError):
    status_code = 503
    code = "AUDIT_INTEGRITY_FAILED"


class RateLimitError(WorkbenchError):
    status_code = 429
    code = "RATE_LIMITED"
