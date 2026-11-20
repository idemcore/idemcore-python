# SPDX-License-Identifier: Apache-2.0
"""Result types. Every result keeps the full JSON body in ``raw``."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from typing import Literal, TypedDict

Role = Literal["system", "user", "assistant"]
Privacy = Literal["hash_only", "full"]


class Message(TypedDict):
    role: Role
    content: str


class Usage(TypedDict, total=False):
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


@dataclass
class ChatResult:
    """A chat completion with its signed receipt.

    ``salt`` (hash_only receipts only) is the base64url salt the prompt/output
    commitments were made with. Anyone who holds it and the text can check the
    commitments, so store it like the conversation itself.
    """
    text: str
    receipt_id: str
    receipt: Dict[str, Any]
    id: str
    model: str
    finish_reason: Optional[str]
    usage: Usage
    privacy: str
    salt: Optional[str] = None
    output_token_ids: Optional[List[int]] = None
    messages: List[Message] = field(default_factory=list)
    rate_limit: Dict[str, str] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StreamChunk:
    """One ``chat.completion.chunk`` event. ``delta`` is the new text (may be empty)."""
    delta: str
    finish_reason: Optional[str]
    raw: Dict[str, Any]


@dataclass
class ReceiptLog:
    receipt_id: str
    receipt: Dict[str, Any]
    log_format: str
    log_text: Optional[str]
    raw: Dict[str, Any] = field(default_factory=dict)
