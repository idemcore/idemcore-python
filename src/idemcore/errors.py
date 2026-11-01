# SPDX-License-Identifier: Apache-2.0
"""Errors raised by the client. The API returns ``{"error": {"type", "message"}}``."""
from __future__ import annotations

from typing import Mapping, Optional


class IdemcoreError(Exception):
    """Base class. ``status`` is the HTTP status (``None`` for network errors)."""

    def __init__(self, message: str, *, type: str = "error", status: Optional[int] = None,
                 headers: Optional[Mapping[str, str]] = None):
        super().__init__(message)
        self.message = message
        self.type = type
        self.status = status
        self.headers = dict(headers or {})

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(status={self.status!r}, type={self.type!r}, message={self.message!r})"


class APIConnectionError(IdemcoreError):
    """The request did not reach the API or the connection broke."""


class InvalidRequestError(IdemcoreError):
    """400 / 415: the request was rejected (bad parameters)."""


class AuthenticationError(IdemcoreError):
    """401: missing or invalid API key."""


class PermissionDeniedError(IdemcoreError):
    """403: the API key lacks the required scope."""


class NotFoundError(IdemcoreError):
    """404: unknown receipt or endpoint."""


class RateLimitError(IdemcoreError):
    """429 ``rate_limit_error``. ``retry_after`` is in seconds when the API sends it."""

    @property
    def retry_after(self) -> Optional[float]:
        v = self.headers.get("retry-after")
        try:
            return float(v) if v is not None else None
        except ValueError:
            return None


class InsufficientQuotaError(IdemcoreError):
    """429 ``insufficient_quota``: the organisation's token quota is used up."""


class ServiceUnavailableError(IdemcoreError):
    """503: the inference backend is temporarily unavailable."""


class ConflictError(IdemcoreError):
    """409: e.g. a replay whose stored payload is no longer available."""


class InternalServerError(IdemcoreError):
    """500 or another 5xx."""


_BY_TYPE = {
    "invalid_request_error": InvalidRequestError,
    "authentication_error": AuthenticationError,
    "permission_error": PermissionDeniedError,
    "not_found_error": NotFoundError,
    "rate_limit_error": RateLimitError,
    "insufficient_quota": InsufficientQuotaError,
    "service_unavailable": ServiceUnavailableError,
    "server_error": InternalServerError,
}
_BY_STATUS = {400: InvalidRequestError, 401: AuthenticationError, 403: PermissionDeniedError,
              404: NotFoundError, 409: ConflictError, 413: InvalidRequestError, 415: InvalidRequestError, 429: RateLimitError, 503: ServiceUnavailableError}


def error_from(status: Optional[int], type: Optional[str], message: str,
               headers: Optional[Mapping[str, str]] = None) -> IdemcoreError:
    cls = _BY_TYPE.get(type or "") or _BY_STATUS.get(status or 0) or (
        InternalServerError if status and status >= 500 else IdemcoreError)
    return cls(message, type=type or "error", status=status, headers=headers)
