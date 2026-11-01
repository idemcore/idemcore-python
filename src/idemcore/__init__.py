# SPDX-License-Identifier: Apache-2.0
"""Idemcore Python SDK: chat completions with signed receipts, and local verification."""
from ._version import __version__
from ._types import ChatResult, Message, ReceiptLog, StreamChunk, Usage
from .client import AsyncChatStream, AsyncIdemcore, ChatStream, Idemcore, DEFAULT_BASE_URL
from .errors import (APIConnectionError, AuthenticationError, ConflictError, IdemcoreError, InsufficientQuotaError,
                     InternalServerError, InvalidRequestError, NotFoundError, PermissionDeniedError,
                     RateLimitError, ServiceUnavailableError)
from .verify import DEFAULT_TRUSTED_KEYS, VerificationResult, verify_receipt

__all__ = [
    "__version__", "Idemcore", "AsyncIdemcore", "ChatStream", "AsyncChatStream", "DEFAULT_BASE_URL",
    "ChatResult", "StreamChunk", "ReceiptLog", "Message", "Usage",
    "IdemcoreError", "APIConnectionError", "InvalidRequestError", "AuthenticationError",
    "PermissionDeniedError", "NotFoundError", "ConflictError", "RateLimitError", "InsufficientQuotaError",
    "ServiceUnavailableError", "InternalServerError",
    "verify_receipt", "VerificationResult", "DEFAULT_TRUSTED_KEYS",
]
