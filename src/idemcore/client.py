# SPDX-License-Identifier: Apache-2.0
"""HTTP client for the Idemcore API (``https://api.idemcore.net``).

Standard library only (``urllib``). Responses that carry an Idemcore receipt are
returned as typed results; everything else as plain ``dict``.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, AsyncIterator, Dict, Iterator, List, Mapping, Optional, Sequence, Union

from ._types import ChatResult, Message, Privacy, ReceiptLog, StreamChunk
from ._version import __version__
from .errors import APIConnectionError, IdemcoreError, InvalidRequestError, error_from
from . import verify as _verify

DEFAULT_BASE_URL = "https://api.idemcore.net"
_RECEIPT_ID = re.compile(r"^rcpt_[0-9a-f]{24}$")
MessagesLike = Union[str, Sequence[Mapping[str, str]]]


def _messages(m: MessagesLike) -> List[Message]:
    if isinstance(m, str):
        return [{"role": "user", "content": m}]
    out: List[Message] = []
    for x in m:
        out.append({"role": x["role"], "content": x["content"]})  # type: ignore[typeddict-item]
    return out


def _chat_body(messages: List[Message], *, model: Optional[str], max_tokens: Optional[int],
               privacy: Optional[str], temperature: Optional[float], stream: bool) -> Dict[str, Any]:
    if temperature not in (None, 0):
        raise InvalidRequestError("Idemcore uses greedy decoding: temperature is fixed at 0", status=None,
                                  type="invalid_request_error")
    if not 1 <= len(messages) <= 64:
        raise InvalidRequestError("messages must contain 1 to 64 items", type="invalid_request_error")
    body: Dict[str, Any] = {"messages": messages}
    if model is not None:
        body["model"] = model
    if max_tokens is not None:
        if isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or not 1 <= max_tokens <= 2048:
            raise InvalidRequestError("max_tokens must be an integer from 1 to 2048", type="invalid_request_error")
        body["max_tokens"] = max_tokens
    if privacy is not None:
        if privacy not in ("hash_only", "full"):
            raise InvalidRequestError("privacy must be 'hash_only' or 'full'", type="invalid_request_error")
        body["idemcore"] = {"privacy": privacy}
    if stream:
        body["stream"] = True
        body["stream_options"] = {"include_usage": True}
    return body


def _chat_result(data: Dict[str, Any], messages: List[Message], headers: Mapping[str, str]) -> ChatResult:
    choice = (data.get("choices") or [{}])[0]
    idem = data.get("idemcore") or {}
    receipt = data.get("idemcore_receipt") or idem.get("receipt") or {}
    disc = idem.get("disclosure") or {}
    rid = receipt.get("receipt_id") or headers.get("idemcore-receipt-id") or ""
    return ChatResult(
        text=(choice.get("message") or {}).get("content") or "",
        receipt_id=rid,
        receipt=receipt,
        id=data.get("id", ""),
        model=data.get("model", ""),
        finish_reason=choice.get("finish_reason"),
        usage=data.get("usage") or {},
        privacy=receipt.get("privacy", ""),
        salt=data.get("idemcore_salt") or disc.get("salt"),
        output_token_ids=disc.get("output_token_ids"),
        messages=messages,
        rate_limit={k: v for k, v in headers.items() if k.startswith("x-ratelimit-") or k == "retry-after"},
        raw=data,
    )


class ChatStream:
    """Iterate over :class:`StreamChunk` objects. After the stream ends, ``result``
    holds the full :class:`ChatResult` (text, receipt, salt, usage)."""

    def __init__(self, resp: Any, messages: List[Message], headers: Mapping[str, str]):
        self._resp = resp
        self._messages = messages
        self._headers = dict(headers)
        self.receipt_id: str = self._headers.get("idemcore-receipt-id", "")
        self.result: Optional[ChatResult] = None
        self._text: List[str] = []
        self._final: Dict[str, Any] = {}
        self._usage: Dict[str, Any] = {}
        self._done = False

    def __enter__(self) -> "ChatStream":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        try:
            self._resp.close()
        except Exception:
            pass

    def __iter__(self) -> Iterator[StreamChunk]:
        try:
            for ev in _sse_events(self._resp):
                if ev == "[DONE]":
                    break
                data = json.loads(ev)
                if "error" in data:
                    err = data["error"] or {}
                    raise error_from(None, err.get("type"), err.get("message", "stream error"), self._headers)
                if data.get("usage"):
                    self._usage = data["usage"]
                if "idemcore_receipt" in data:
                    self._final = data
                choices = data.get("choices") or []
                if not choices:
                    continue
                c = choices[0]
                delta = (c.get("delta") or {}).get("content") or ""
                if delta:
                    self._text.append(delta)
                yield StreamChunk(delta=delta, finish_reason=c.get("finish_reason"), raw=data)
        finally:
            self.close()
        self._finish()

    def _finish(self) -> None:
        if self._done:
            return
        self._done = True
        if not self._final:
            raise APIConnectionError("stream ended before the receipt arrived", headers=self._headers)
        final = dict(self._final)
        fc = (final.get("choices") or [{}])[0]
        final["choices"] = [{"index": 0, "message": {"role": "assistant", "content": "".join(self._text)},
                             "finish_reason": fc.get("finish_reason")}]
        final["usage"] = self._usage or final.get("usage") or {}
        self.result = _chat_result(final, self._messages, self._headers)

    def until_done(self) -> ChatResult:
        """Consume the rest of the stream and return the final result."""
        for _ in self:
            pass
        assert self.result is not None
        return self.result


def _sse_events(resp: Any) -> Iterator[str]:
    buf: List[str] = []
    for raw in resp:
        line = raw.decode("utf-8").rstrip("\r\n")
        if not line:
            if buf:
                yield "\n".join(buf)
                buf = []
            continue
        if line.startswith(":"):
            continue  # keep-alive comment
        if line.startswith("data:"):
            buf.append(line[5:].lstrip(" "))
    if buf:
        yield "\n".join(buf)


class Idemcore:
    """Synchronous client.

    >>> client = Idemcore()                     # reads IDEMCORE_API_KEY
    >>> r = client.chat("Name the three primary colours.")
    >>> r.text, r.receipt_id

    Decoding is greedy: temperature is fixed at 0, so the same request on the same
    model gives the same answer, and every answer carries a signed receipt.
    """

    def __init__(self, api_key: Optional[str] = None, *, base_url: Optional[str] = None,
                 timeout: float = 120.0, max_retries: int = 2, user_agent: Optional[str] = None):
        self._api_key = api_key if api_key is not None else os.environ.get("IDEMCORE_API_KEY")
        url = (base_url or os.environ.get("IDEMCORE_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        self.base_url = url[:-3] if url.endswith("/v1") else url
        self.timeout = timeout
        self.max_retries = max(0, int(max_retries))
        self.user_agent = user_agent or f"idemcore-python/{__version__}"

    def __repr__(self) -> str:  # never show the key
        return f"Idemcore(base_url={self.base_url!r}, api_key={'set' if self._api_key else 'missing'})"

    # ---------------------------------------------------------------- transport
    def _request(self, method: str, path: str, *, body: Any = None, query: Optional[Mapping[str, Any]] = None,
                 auth: bool = True, stream: bool = False, raw: bool = False):
        url = self.base_url + path
        if query:
            q = {k: v for k, v in query.items() if v is not None}
            if q:
                url += "?" + urllib.parse.urlencode(q)
        headers = {"User-Agent": self.user_agent, "Accept": "text/event-stream" if stream else "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if auth:
            if not self._api_key:
                raise error_from(401, "authentication_error",
                                 "no API key: pass api_key= or set IDEMCORE_API_KEY")
            headers["Authorization"] = "Bearer " + self._api_key
        retries = self.max_retries if method == "GET" else 0  # never repeat a chat call
        attempt = 0
        while True:
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
            try:
                resp = urllib.request.urlopen(req, timeout=self.timeout)
            except urllib.error.HTTPError as e:
                hdrs = {k.lower(): v for k, v in e.headers.items()}
                text = e.read().decode("utf-8", "replace")
                e.close()
                try:
                    err = (json.loads(text).get("error") or {})
                except (ValueError, AttributeError):
                    err = {}
                exc = error_from(e.code, err.get("type"), err.get("message") or f"HTTP {e.code}", hdrs)
                if attempt < retries and e.code in (429, 503) and exc.type != "insufficient_quota":
                    attempt += 1
                    time.sleep(min(float(hdrs.get("retry-after", "1") or 1), 20.0))
                    continue
                raise exc from None
            except (urllib.error.URLError, OSError) as e:
                if attempt < retries:
                    attempt += 1
                    time.sleep(0.5 * attempt)
                    continue
                raise APIConnectionError(f"could not reach {self.base_url}: {e}") from None
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            if stream:
                return resp, hdrs
            with resp:
                payload = resp.read()
            if raw:
                return payload.decode("utf-8"), hdrs
            try:
                return json.loads(payload), hdrs
            except ValueError:
                raise IdemcoreError("API returned a non-JSON response", status=resp.status, headers=hdrs) from None

    # ---------------------------------------------------------------- endpoints
    def health(self) -> Dict[str, Any]:
        """``GET /health`` (no API key needed)."""
        return self._request("GET", "/health", auth=False)[0]

    def models(self) -> List[Dict[str, Any]]:
        """``GET /v1/models``: the models this key can use."""
        return self._request("GET", "/v1/models")[0].get("data", [])

    def chat(self, messages: MessagesLike, *, model: Optional[str] = None, max_tokens: Optional[int] = None,
             privacy: Optional[Privacy] = None, temperature: Optional[float] = None) -> ChatResult:
        """``POST /v1/chat/completions``. ``messages`` may be a plain string (one user
        message). ``privacy="hash_only"`` (the default) stores only salted hashes;
        ``"full"`` also stores the conversation for server-side replay."""
        msgs = _messages(messages)
        body = _chat_body(msgs, model=model, max_tokens=max_tokens, privacy=privacy,
                          temperature=temperature, stream=False)
        data, hdrs = self._request("POST", "/v1/chat/completions", body=body)
        return _chat_result(data, msgs, hdrs)

    def chat_stream(self, messages: MessagesLike, *, model: Optional[str] = None, max_tokens: Optional[int] = None,
                    privacy: Optional[Privacy] = None, temperature: Optional[float] = None) -> ChatStream:
        """Streaming chat (server-sent events). The receipt is signed once the answer
        is complete and arrives with the last chunk; ``stream.result`` has it."""
        msgs = _messages(messages)
        body = _chat_body(msgs, model=model, max_tokens=max_tokens, privacy=privacy,
                          temperature=temperature, stream=True)
        resp, hdrs = self._request("POST", "/v1/chat/completions", body=body, stream=True)
        return ChatStream(resp, msgs, hdrs)

    def get_receipt(self, receipt_id: str) -> Dict[str, Any]:
        """``GET /v1/receipts/{id}``."""
        return self._request("GET", f"/v1/receipts/{_rid(receipt_id)}")[0]["receipt"]

    def get_receipt_log(self, receipt_id: str) -> ReceiptLog:
        """``GET /v1/receipts/{id}/log``: the receipt and its public token log."""
        d = self._request("GET", f"/v1/receipts/{_rid(receipt_id)}/log")[0]
        return ReceiptLog(d.get("receipt_id", receipt_id), d.get("receipt") or {}, d.get("log_format", ""),
                          d.get("log_text"), d)

    def keys(self) -> Dict[str, Any]:
        """``GET /v1/keys``: the receipt-signing public keys (JWKS)."""
        return self._request("GET", "/v1/keys")[0]

    def verify_remote(self, receipt: Mapping[str, Any], *, log_text: Optional[str] = None,
                      messages: Optional[MessagesLike] = None, salt: Optional[str] = None,
                      output_token_ids: Optional[Sequence[int]] = None,
                      output_text: Optional[str] = None) -> Dict[str, Any]:
        """``POST /v1/receipts/verify``: server-side L1, L2 and disclosure checks."""
        body: Dict[str, Any] = {"receipt": dict(receipt)}
        if log_text is not None:
            body["log_text"] = log_text
        disc: Dict[str, Any] = {}
        if messages is not None:
            disc["messages"] = _messages(messages)
        if salt is not None:
            disc["salt"] = salt
        if output_token_ids is not None:
            disc["output_token_ids"] = list(output_token_ids)
        if output_text is not None:
            disc["output_text"] = output_text
        if disc:
            body["disclosure"] = disc
        return self._request("POST", "/v1/receipts/verify", body=body)[0]

    def replay(self, receipt_id: str, *, messages: Optional[MessagesLike] = None, salt: Optional[str] = None,
               output_token_ids: Optional[Sequence[int]] = None, build: Optional[str] = None) -> Dict[str, Any]:
        """``POST /v1/receipts/replay`` (L3): re-run the answer on an independent
        build and compare chain digests. ``hash_only`` receipts need ``messages``
        and ``salt``; ``full`` receipts replay from the stored conversation."""
        body: Dict[str, Any] = {"receipt_id": _rid(receipt_id)}
        if messages is not None:
            body["messages"] = _messages(messages)
        if salt is not None:
            body["salt"] = salt
        if output_token_ids is not None:
            body["output_token_ids"] = list(output_token_ids)
        if build is not None:
            if build not in ("main", "alt"):
                raise InvalidRequestError("build must be 'main' or 'alt'", type="invalid_request_error")
            body["build"] = build
        return self._request("POST", "/v1/receipts/replay", body=body)[0]

    def replay_result(self, result: ChatResult, *, build: Optional[str] = None) -> Dict[str, Any]:
        """Replay a :class:`ChatResult` with its own disclosure (messages, salt, ids)."""
        if result.privacy == "full":
            return self.replay(result.receipt_id, build=build)
        return self.replay(result.receipt_id, messages=result.messages, salt=result.salt,
                           output_token_ids=result.output_token_ids, build=build)

    def audit_export(self, since: Optional[str] = None, until: Optional[str] = None, *,
                     include_logs: bool = False, format: str = "ndjson") -> Union[List[Dict[str, Any]], Dict[str, Any]]:
        """``POST /v1/audit/export``. ``since``/``until`` are ``YYYY-MM-DD`` (UTC days,
        ``until`` exclusive, at most 31 days). ``format="ndjson"`` returns the list of
        export lines (header, receipts, events, roots, logs); ``"json"`` one object."""
        body: Dict[str, Any] = {}
        if since:
            body["since"] = since
        if until:
            body["until"] = until
        if include_logs:
            body["include_logs"] = True
        if format == "json":
            body["format"] = "json"
            return self._request("POST", "/v1/audit/export", body=body)[0]
        if format != "ndjson":
            raise InvalidRequestError("format must be 'ndjson' or 'json'", type="invalid_request_error")
        text, _ = self._request("POST", "/v1/audit/export", body=body, raw=True)
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    # ---------------------------------------------------------------- local verification
    def verify_local(self, result: Union[ChatResult, Mapping[str, Any]], *, fetch_log: bool = True,
                     keys: _verify.KeysLike = None, check_signature: bool = True,
                     output_text: Optional[str] = None) -> _verify.VerificationResult:
        """Verify a receipt on this machine. For a :class:`ChatResult`, the disclosure
        (messages, salt, output ids, text) is checked too. With ``fetch_log=True`` the
        public token log is downloaded and L2 is run. ``keys`` defaults to the bundled
        Idemcore signing keys."""
        if isinstance(result, ChatResult):
            receipt = result.receipt
            kw: Dict[str, Any] = {"messages": result.messages, "salt": result.salt,
                                  "output_token_ids": result.output_token_ids,
                                  "output_text": output_text if output_text is not None else (
                                      result.text if "output_text_hash" in receipt else None)}
        else:
            receipt = dict(result)
            kw = {"output_text": output_text}
        log_text = None
        if fetch_log:
            log_text = self.get_receipt_log(receipt["receipt_id"]).log_text
        return _verify.verify_receipt(receipt, keys=keys, log_text=log_text,
                                      check_signature=check_signature, **kw)


def _rid(receipt_id: str) -> str:
    if not isinstance(receipt_id, str) or not _RECEIPT_ID.match(receipt_id):
        raise InvalidRequestError("receipt_id must look like rcpt_ followed by 24 hex digits",
                                  type="invalid_request_error")
    return receipt_id


class AsyncIdemcore:
    """Asyncio client with the same methods as :class:`Idemcore`. Each call runs the
    blocking request in a worker thread (``asyncio.to_thread``); no extra dependency."""

    def __init__(self, api_key: Optional[str] = None, **kw: Any):
        self._sync = Idemcore(api_key, **kw)

    def __repr__(self) -> str:
        return "Async" + repr(self._sync)

    @property
    def base_url(self) -> str:
        return self._sync.base_url

    async def health(self) -> Dict[str, Any]:
        return await asyncio.to_thread(self._sync.health)

    async def models(self) -> List[Dict[str, Any]]:
        return await asyncio.to_thread(self._sync.models)

    async def chat(self, messages: MessagesLike, **kw: Any) -> ChatResult:
        return await asyncio.to_thread(self._sync.chat, messages, **kw)

    async def chat_stream(self, messages: MessagesLike, **kw: Any) -> "AsyncChatStream":
        s = await asyncio.to_thread(self._sync.chat_stream, messages, **kw)
        return AsyncChatStream(s)

    async def get_receipt(self, receipt_id: str) -> Dict[str, Any]:
        return await asyncio.to_thread(self._sync.get_receipt, receipt_id)

    async def get_receipt_log(self, receipt_id: str) -> ReceiptLog:
        return await asyncio.to_thread(self._sync.get_receipt_log, receipt_id)

    async def keys(self) -> Dict[str, Any]:
        return await asyncio.to_thread(self._sync.keys)

    async def verify_remote(self, receipt: Mapping[str, Any], **kw: Any) -> Dict[str, Any]:
        return await asyncio.to_thread(self._sync.verify_remote, receipt, **kw)

    async def replay(self, receipt_id: str, **kw: Any) -> Dict[str, Any]:
        return await asyncio.to_thread(self._sync.replay, receipt_id, **kw)

    async def replay_result(self, result: ChatResult, **kw: Any) -> Dict[str, Any]:
        return await asyncio.to_thread(self._sync.replay_result, result, **kw)

    async def audit_export(self, since: Optional[str] = None, until: Optional[str] = None, **kw: Any):
        return await asyncio.to_thread(self._sync.audit_export, since, until, **kw)

    async def verify_local(self, result: Union[ChatResult, Mapping[str, Any]], **kw: Any) -> _verify.VerificationResult:
        return await asyncio.to_thread(self._sync.verify_local, result, **kw)


class AsyncChatStream:
    """Async iterator over :class:`StreamChunk`; ``result`` is set at the end."""

    _END = object()

    def __init__(self, s: ChatStream):
        self._s = s
        self._it = iter(s)

    @property
    def result(self) -> Optional[ChatResult]:
        return self._s.result

    @property
    def receipt_id(self) -> str:
        return self._s.receipt_id

    def __aiter__(self) -> AsyncIterator[StreamChunk]:
        return self

    async def __anext__(self) -> StreamChunk:
        v = await asyncio.to_thread(next, self._it, self._END)
        if v is self._END:
            raise StopAsyncIteration
        return v  # type: ignore[return-value]

    async def until_done(self) -> ChatResult:
        async for _ in self:
            pass
        assert self._s.result is not None
        return self._s.result

    async def aclose(self) -> None:
        self._s.close()

    async def __aenter__(self) -> "AsyncChatStream":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        self._s.close()
