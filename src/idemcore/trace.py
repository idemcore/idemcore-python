# SPDX-License-Identifier: Apache-2.0
"""Reproducible agent sessions: record, replay and verify (trace format ``idemcore-trace/r1``).

A *trace* is an ordered, hash-chained list of steps:

* ``model``: one chat completion: the exact request, the signed receipt, the salt,
  the output token ids and the text.
* ``tool``: one tool call made by your code: name, arguments and result, each kept
  as canonical JSON text with its hash.
* ``note``: free-form annotation (for example a human approval).

Every step commits to the previous step's hash, and the manifest commits to the
session id, the step count and the last hash (``head``). A trace can be signed
with an Ed25519 key you own. Three operations:

Command line: ``python -m idemcore trace verify|show|replay FILE`` (or ``idemcore-trace``).

* :func:`verify_trace`: offline. Recomputes the chain and the manifest hash, checks
  each receipt signature and its commitments (prompt, output tokens, text) and each
  tool hash. No network.
* :func:`replay`: re-runs the model calls against the API and checks that the output
  tokens are bit-identical. With ``agent=`` it re-runs *your agent code* and feeds
  it the recorded tool results instead of calling the tools again.
* :class:`Session`: records a trace while your agent runs.

Treat a trace like the conversation itself: it holds the prompts, the answers and the
salts that open the receipt commitments.
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import os
import secrets
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Sequence, Union

from ._types import ChatResult
from ._version import __version__
from . import verify as _verify

__all__ = [
    "TRACE_FORMAT", "Session", "ReplaySession", "ReplayDivergence", "StepReport", "ReplayReport",
    "TraceVerification", "record", "replay", "verify_trace", "load_trace", "save_trace", "dumps_trace",
    "trace_json", "generate_signing_key",
]

TRACE_FORMAT = "idemcore-trace/r1"
SIG_DOMAIN = b"idemcore-trace/r1\n"
STEP_TYPES = ("model", "tool", "note")
# Receipt fields that must match between a recorded answer and its replay.
# Each entry is r1 name first, optional r2 alias second; compare by value across versions.
_SAME = (("model_id",), ("weights_hash",), ("decoding",), ("seed", "variant"), ("prompt_tokens",),
         ("output_tokens",), ("chain_digest",), ("chain_fnv", "chain_check"), ("finish_reason",))
# Fields that may legitimately differ (new engine build); reported as notes.
_ENV = (("engine_build",), ("kernel_version", "engine_version"))


def _rf(r, names):
    for n in names:
        if n in r:
            return r.get(n)
    return None


def _rn(r, names):
    for n in names:
        if n in r:
            return n
    return names[0]


# ------------------------------------------------------------------ hashing
def trace_json(value: Any, *, sort_keys: bool = True) -> str:
    """JSON text for tool arguments, results and notes: no whitespace, non-ASCII
    literal, finite floats allowed. Keys are sorted, except for tool results,
    which keep the tool's key order so a replayed agent sees exactly the object
    the tool returned. The text is stored as is and hashed as bytes, so
    verification never re-serialises it."""
    try:
        return json.dumps(value, sort_keys=sort_keys, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as e:
        raise TypeError(f"tool arguments and results must be JSON-serialisable: {e}") from None


def _h(tag: str, *parts: bytes) -> str:
    return _verify.tagged_hash(tag, *parts)


def _u(s: str) -> bytes:
    return s.encode("utf-8")


def genesis_hash(session_id: str) -> str:
    return _h("trace-genesis", _u(session_id))


def step_hash(step: Mapping[str, Any]) -> str:
    body = {k: v for k, v in step.items() if k != "hash"}
    return _h("trace-step", _verify.canonical_json(body))


def manifest_hash(manifest: Mapping[str, Any]) -> str:
    return _h("trace-manifest", _verify.canonical_json(dict(manifest)))


def request_hash(request: Mapping[str, Any]) -> str:
    return _h("trace-request", _verify.canonical_json(dict(request)))


def text_sha(text: str) -> str:
    return _h("trace-text", _u(text))


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _int_dict(d: Optional[Mapping[str, Any]]) -> Dict[str, int]:
    return {k: v for k, v in (d or {}).items() if isinstance(v, int) and not isinstance(v, bool)}


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# ------------------------------------------------------------------ signing
def generate_signing_key() -> Dict[str, str]:
    """A new Ed25519 key as a private JWK (``d`` is secret; keep it out of the trace)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization as s
    k = Ed25519PrivateKey.generate()
    d = k.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption())
    x = k.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64u(x), "d": _b64u(d),
            "kid": "ed25519:" + hashlib.sha256(x).hexdigest()[:16]}


def _sign(manifest_h: str, jwk: Mapping[str, str]) -> Dict[str, str]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization as s
    k = Ed25519PrivateKey.from_private_bytes(_verify.b64u_decode(jwk["d"]))
    x = k.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
    sig = k.sign(SIG_DOMAIN + _u(manifest_h))
    return {"alg": "Ed25519", "kid": "ed25519:" + hashlib.sha256(x).hexdigest()[:16], "x": _b64u(x),
            "signature": _b64u(sig)}


# ------------------------------------------------------------------ recording
class Session:
    """Record an agent session.

    >>> s = Session(client, meta={"task": "weather"})
    >>> r = s.chat([{"role": "user", "content": "..."}], model="qwen2.5-7b-instruct-q4")
    >>> temp = s.tool("get_weather", {"city": "Paris"}, get_weather)
    >>> trace = s.finish(sign_with=my_private_jwk)   # dict, or s.save("run.trace.json")

    Model calls go through :meth:`chat` (or :meth:`record_model` for a streamed
    answer). Tool calls go through :meth:`tool` (runs the function) or
    :meth:`record_tool` (you ran it yourself).
    """

    def __init__(self, client: Any = None, *, meta: Optional[Mapping[str, Any]] = None,
                 session_id: Optional[str] = None):
        self.client = client
        self.session_id = session_id or "ses_" + secrets.token_hex(12)
        self.created_at = _now()
        self.meta_json = trace_json(dict(meta or {}))
        self.steps: List[Dict[str, Any]] = []
        self._head = genesis_hash(self.session_id)
        self._finished: Optional[Dict[str, Any]] = None

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc: Any) -> None:
        pass

    @property
    def head(self) -> str:
        return self._head

    def _append(self, typ: str, body: Dict[str, Any]) -> Dict[str, Any]:
        if self._finished is not None:
            raise RuntimeError("session already finished")
        step = {"index": len(self.steps), "type": typ, "prev": self._head, "body": body}
        step["hash"] = step_hash(step)
        self.steps.append(step)
        self._head = step["hash"]
        return step

    # -- model calls
    def chat(self, messages: Any, *, model: Optional[str] = None, max_tokens: Optional[int] = None,
             privacy: Optional[str] = None, **kw: Any) -> ChatResult:
        if self.client is None:
            raise RuntimeError("Session has no client; pass one or use record_model()")
        r = self.client.chat(messages, model=model, max_tokens=max_tokens, privacy=privacy, **kw)
        self.record_model(r, model=model, max_tokens=max_tokens, privacy=privacy)
        return r

    def record_model(self, result: ChatResult, *, model: Optional[str] = None, max_tokens: Optional[int] = None,
                     privacy: Optional[str] = None, streamed: bool = False) -> Dict[str, Any]:
        """Add a finished :class:`ChatResult` (for example ``stream.until_done()``).
        ``model``/``max_tokens``/``privacy`` must be what you sent."""
        request = {"messages": [dict(m) for m in result.messages], "model": model,
                   "max_tokens": max_tokens, "privacy": privacy}
        receipt = dict(result.receipt)
        body = {
            "request": request,
            "request_hash": request_hash(request),
            "receipt_id": result.receipt_id,
            "receipt": receipt,
            "receipt_hash": _h("trace-receipt", _verify.canonical_json(receipt)),
            "salt": result.salt,
            "output_token_ids": list(result.output_token_ids) if result.output_token_ids is not None else None,
            "output_text": result.text,
            "output_text_sha": text_sha(result.text),
            "finish_reason": result.finish_reason,
            "usage": _int_dict(result.usage),
            "streamed": bool(streamed),
        }
        return self._append("model", body)

    # -- tool calls
    def tool(self, name: str, args: Any, fn: Callable[..., Any], *, call_id: Optional[str] = None) -> Any:
        """Run ``fn`` (``fn(**args)`` for a dict, else ``fn(args)``) and record the call.
        An exception is recorded and re-raised."""
        args_json = trace_json(args)
        try:
            result = fn(**args) if isinstance(args, dict) else fn(args)
        except Exception as e:
            self.record_tool(name, args, error=f"{type(e).__name__}: {e}", call_id=call_id, _args_json=args_json)
            raise
        self.record_tool(name, args, result, call_id=call_id, _args_json=args_json)
        return result

    def record_tool(self, name: str, args: Any, result: Any = None, *, error: Optional[str] = None,
                    call_id: Optional[str] = None, _args_json: Optional[str] = None) -> Dict[str, Any]:
        """Record a tool call you executed yourself."""
        if not isinstance(name, str) or not name:
            raise ValueError("tool name must be a non-empty string")
        args_json = _args_json if _args_json is not None else trace_json(args)
        result_json = None if error is not None else trace_json(result, sort_keys=False)
        body = {
            "name": name,
            "call_id": call_id or f"call_{len(self.steps)}",
            "args_json": args_json,
            "args_hash": _h("trace-tool-args", _u(args_json)),
            "result_json": result_json,
            "result_hash": _h("trace-tool-result", _u(result_json if result_json is not None else "")),
            "error": error,
        }
        return self._append("tool", body)

    def note(self, kind: str, data: Any = None) -> Dict[str, Any]:
        """Free-form step, e.g. ``note("approval", {"by": "ops", "decision": "allow"})``."""
        data_json = trace_json(data)
        return self._append("note", {"kind": str(kind), "data_json": data_json,
                                     "data_hash": _h("trace-note", _u(data_json))})

    # -- finish
    def manifest(self) -> Dict[str, Any]:
        return {"format": TRACE_FORMAT, "session_id": self.session_id, "created_at": self.created_at,
                "sdk": f"idemcore-python/{__version__}", "meta_json": self.meta_json,
                "genesis": genesis_hash(self.session_id), "head": self._head, "step_count": len(self.steps)}

    def finish(self, *, sign_with: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
        """Close the session and return the trace (a JSON-ready dict)."""
        if self._finished is None:
            man = self.manifest()
            mh = manifest_hash(man)
            self._finished = {"manifest": man, "manifest_hash": mh, "steps": self.steps, "signatures": []}
        if sign_with is not None:
            self._finished["signatures"].append(_sign(self._finished["manifest_hash"], sign_with))
        return self._finished

    def save(self, path: str, **kw: Any) -> str:
        save_trace(self.finish(**kw), path)
        return path


def record(client: Any, **kw: Any) -> Session:
    """Start recording: ``with record(client) as s: ...``."""
    return Session(client, **kw)


def dumps_trace(trace: Mapping[str, Any]) -> str:
    return json.dumps(trace, ensure_ascii=False, indent=1) + "\n"


def save_trace(trace: Mapping[str, Any], path: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(dumps_trace(trace))
    os.replace(tmp, path)


def load_trace(path_or_text: str) -> Dict[str, Any]:
    if path_or_text.lstrip().startswith("{"):
        return json.loads(path_or_text)
    with open(path_or_text, encoding="utf-8") as f:
        return json.load(f)


# ------------------------------------------------------------------ verification
@dataclass
class TraceVerification:
    ok: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    steps: int = 0
    model_steps: int = 0
    tool_steps: int = 0
    signers: List[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.ok


def verify_trace(trace: Mapping[str, Any], *, keys: _verify.KeysLike = None, check_receipts: bool = True,
                 trusted_signers: Optional[Sequence[Union[str, Mapping[str, str]]]] = None,
                 require_signature: bool = False) -> TraceVerification:
    """Verify a trace offline (no network).

    Checks the step chain, step hashes, the manifest hash, each tool/note hash, each
    model step's request hash and text hash, and (``check_receipts``) each receipt's
    Ed25519 signature against ``keys`` (default: bundled Idemcore keys) plus its
    prompt / output-token / text commitments. ``trusted_signers`` is a list of key
    ids (``ed25519:...``) or public JWKs; with it, at least one valid signature from
    that list is required."""
    errs: List[str] = []
    warns: List[str] = []
    out = TraceVerification(False, errs, warns)
    try:
        man = trace["manifest"]
        steps = trace["steps"]
    except (KeyError, TypeError):
        errs.append("not a trace: manifest and steps are required")
        return out
    if man.get("format") != TRACE_FORMAT:
        errs.append(f"unsupported format {man.get('format')!r}")
        return out
    try:
        mh = manifest_hash(man)
    except ValueError as e:
        errs.append(f"manifest is not canonical: {e}")
        return out
    if mh != trace.get("manifest_hash"):
        errs.append("manifest_hash mismatch")
    sid = man.get("session_id")
    if not isinstance(sid, str) or genesis_hash(sid) != man.get("genesis"):
        errs.append("genesis does not match session_id")
    if man.get("step_count") != len(steps):
        errs.append(f"step_count {man.get('step_count')} != {len(steps)} steps")
    prev = genesis_hash(sid) if isinstance(sid, str) else ""
    trusted_keys = _verify.load_keys(keys) if check_receipts else []
    for i, st in enumerate(steps):
        p = f"step {i}"
        if not isinstance(st, Mapping):
            errs.append(f"{p}: not an object")
            continue
        if st.get("index") != i:
            errs.append(f"{p}: index {st.get('index')}")
        if st.get("prev") != prev:
            errs.append(f"{p}: prev does not link to the previous step")
        try:
            h = step_hash(st)
        except ValueError as e:
            errs.append(f"{p}: not canonical ({e})")
            h = None
        if h != st.get("hash"):
            errs.append(f"{p}: hash mismatch")
        prev = st.get("hash")
        typ, b = st.get("type"), st.get("body") or {}
        if typ == "model":
            out.model_steps += 1
            errs.extend(f"{p}: {e}" for e in _verify_model_step(b, check_receipts, trusted_keys))
        elif typ == "tool":
            out.tool_steps += 1
            if b.get("args_hash") != _h("trace-tool-args", _u(str(b.get("args_json")))):
                errs.append(f"{p}: args_hash mismatch")
            rj = b.get("result_json")
            if b.get("result_hash") != _h("trace-tool-result", _u(rj if isinstance(rj, str) else "")):
                errs.append(f"{p}: result_hash mismatch")
            for k in ("args_json", "result_json"):
                if isinstance(b.get(k), str):
                    try:
                        json.loads(b[k])
                    except ValueError:
                        errs.append(f"{p}: {k} is not JSON")
        elif typ == "note":
            if b.get("data_hash") != _h("trace-note", _u(str(b.get("data_json")))):
                errs.append(f"{p}: data_hash mismatch")
        else:
            errs.append(f"{p}: unknown step type {typ!r}")
    if prev != man.get("head") and steps:
        errs.append("head does not match the last step")
    if not steps and man.get("head") != man.get("genesis"):
        errs.append("empty trace: head must equal genesis")
    out.steps = len(steps)
    # signatures
    valid: List[str] = []
    for sg in trace.get("signatures") or []:
        try:
            raw = _verify.b64u_decode(sg["x"])
            kid = "ed25519:" + hashlib.sha256(raw).hexdigest()[:16]
            ok = sg.get("kid") == kid and _verify.TrustedKey(kid, raw).verify(
                _verify.b64u_decode(sg["signature"]), SIG_DOMAIN + _u(str(trace.get("manifest_hash"))))
        except Exception:
            ok, kid = False, str(sg.get("kid"))
        if ok:
            valid.append(kid)
        else:
            errs.append(f"signature {kid} invalid")
    out.signers = valid
    if trusted_signers is not None:
        pinned = {s if isinstance(s, str) else "ed25519:" + hashlib.sha256(_verify.b64u_decode(s["x"])).hexdigest()[:16]
                  for s in trusted_signers}
        if not pinned.intersection(valid):
            errs.append("no valid signature from a trusted signer")
    elif require_signature and not valid:
        errs.append("trace is not signed")
    elif valid:
        warns.append("signature valid but signer not pinned (pass trusted_signers)")
    out.ok = not errs
    return out


def _verify_model_step(b: Mapping[str, Any], check_receipts: bool, keys: List[Any]) -> List[str]:
    errs: List[str] = []
    req = b.get("request") or {}
    try:
        if b.get("request_hash") != request_hash(req):
            errs.append("request_hash mismatch")
    except ValueError as e:
        errs.append(f"request not canonical ({e})")
    rc = b.get("receipt") or {}
    if rc.get("receipt_id") != b.get("receipt_id"):
        errs.append("receipt_id mismatch")
    try:
        if b.get("receipt_hash") != _h("trace-receipt", _verify.canonical_json(dict(rc))):
            errs.append("receipt_hash mismatch")
    except ValueError as e:
        errs.append(f"receipt not canonical ({e})")
    text = b.get("output_text")
    if not isinstance(text, str) or b.get("output_text_sha") != text_sha(text):
        errs.append("output_text_sha mismatch")
    if check_receipts:
        ids = b.get("output_token_ids")
        res = _verify.verify_receipt(
            rc, keys=keys, messages=req.get("messages"), salt=b.get("salt"),
            output_token_ids=ids, output_text=text if "output_text_hash" in rc else None)
        for lv in res.levels.values():
            errs.extend(f"receipt {lv.level}: {e}" for e in lv.errors)
        if ids is None and rc.get("privacy") != "full":
            pass  # token ids not disclosed: commitment checked by replay only
    return errs


# ------------------------------------------------------------------ replay
@dataclass
class StepReport:
    index: int
    type: str
    identical: bool
    diffs: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    receipt_id: Optional[str] = None
    replay_receipt_id: Optional[str] = None


@dataclass
class ReplayReport:
    ok: bool
    steps: List[StepReport] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    model_calls: int = 0
    replay_trace: Optional[Dict[str, Any]] = None

    def __bool__(self) -> bool:
        return self.ok

    def summary(self) -> str:
        n = sum(1 for s in self.steps if s.type == "model")
        same = sum(1 for s in self.steps if s.type == "model" and s.identical)
        return (f"{'OK' if self.ok else 'DIVERGED'}: {same}/{n} model steps bit-identical, "
                f"{len(self.steps) - n} tool/note steps fed from the trace"
                + (f"; errors: {'; '.join(self.errors)}" if self.errors else ""))


class ReplayDivergence(Exception):
    def __init__(self, report: ReplayReport, message: str):
        super().__init__(message)
        self.report = report


def compare_model(rec: Mapping[str, Any], new: ChatResult) -> StepReport:
    """Compare a recorded model step body with a fresh :class:`ChatResult`."""
    a, b = rec.get("receipt") or {}, new.receipt or {}
    rep = StepReport(-1, "model", True, receipt_id=rec.get("receipt_id"), replay_receipt_id=new.receipt_id)
    ids_a, ids_b = rec.get("output_token_ids"), new.output_token_ids
    if ids_a is not None and ids_b is not None:
        if list(ids_a) != list(ids_b):
            n = next((i for i, (x, y) in enumerate(zip(ids_a, ids_b)) if x != y), min(len(ids_a), len(ids_b)))
            rep.diffs.append(f"output tokens differ at position {n} ({len(ids_a)} vs {len(ids_b)} tokens)")
    else:
        rep.notes.append("token ids not disclosed on one side; compared chain digest and text")
    if rec.get("output_text") != new.text:
        rep.diffs.append("output text differs")
    for names in _SAME:
        if _rf(a, names) != _rf(b, names):
            rep.diffs.append(f"receipt {_rn(a, names)} differs")
    if a.get("privacy") == b.get("privacy") == "full" and a.get("output_token_hash") != b.get("output_token_hash"):
        rep.diffs.append("receipt output_token_hash differs")
    for names in _ENV:
        if _rf(a, names) != _rf(b, names):
            rep.notes.append(f"{_rn(a, names)} changed: {_rf(a, names)} -> {_rf(b, names)}")
    rep.identical = not rep.diffs
    return rep


class ReplaySession(Session):
    """What your agent function receives during :func:`replay`. ``chat`` calls the
    API and checks the answer against the trace; ``tool`` returns the recorded
    result without running the tool."""

    def __init__(self, client: Any, trace: Mapping[str, Any], report: ReplayReport, strict: bool):
        super().__init__(client, meta={"replay_of": trace["manifest"]["session_id"],
                                       "replay_of_manifest_hash": trace["manifest_hash"]})
        self._trace_steps = list(trace["steps"])
        self._pos = 0
        self._report = report
        self._strict = strict

    def _next(self, typ: str) -> Mapping[str, Any]:
        if self._pos >= len(self._trace_steps):
            self._fail(f"agent made an extra {typ} call after the recorded session ended")
        st = self._trace_steps[self._pos]
        if st["type"] != typ:
            self._fail(f"step {self._pos}: agent made a {typ} call, trace has a {st['type']} step")
        self._pos += 1
        return st

    def _fail(self, msg: str) -> None:
        self._report.errors.append(msg)
        self._report.ok = False
        raise ReplayDivergence(self._report, msg)

    def chat(self, messages: Any, *, model: Optional[str] = None, max_tokens: Optional[int] = None,
             privacy: Optional[str] = None, **kw: Any) -> ChatResult:
        st = self._next("model")
        from .client import _messages
        req = {"messages": [dict(m) for m in _messages(messages)], "model": model,
               "max_tokens": max_tokens, "privacy": privacy}
        if request_hash(req) != st["body"]["request_hash"]:
            self._fail(f"step {st['index']}: the agent sent a different request than the trace")
        r = self.client.chat(messages, model=model, max_tokens=max_tokens, privacy=privacy, **kw)
        self.record_model(r, model=model, max_tokens=max_tokens, privacy=privacy)
        rep = compare_model(st["body"], r)
        rep.index = st["index"]
        self._report.steps.append(rep)
        self._report.model_calls += 1
        if not rep.identical:
            self._report.ok = False
            if self._strict:
                raise ReplayDivergence(self._report, f"step {st['index']}: " + "; ".join(rep.diffs))
        return r

    def tool(self, name: str, args: Any, fn: Optional[Callable[..., Any]] = None, *,
             call_id: Optional[str] = None) -> Any:
        st = self._next("tool")
        b = st["body"]
        aj = trace_json(args)
        same = b["args_hash"] == _h("trace-tool-args", _u(aj))
        if not same:  # a trace from another SDK may format numbers differently (1e-07 vs 1e-7)
            try:
                same = json.loads(b["args_json"]) == json.loads(aj)
            except ValueError:
                same = False
        if b["name"] != name or not same:
            self._fail(f"step {st['index']}: tool call {name} differs from the trace ({b['name']})")
        self._report.steps.append(StepReport(st["index"], "tool", True, notes=["result fed from trace"]))
        if b.get("error") is not None:
            self.record_tool(name, args, error=b["error"], call_id=b.get("call_id"), _args_json=aj)
            raise RuntimeError(f"recorded tool error: {b['error']}")
        result = json.loads(b["result_json"])
        self.record_tool(name, args, result, call_id=b.get("call_id"), _args_json=aj)
        return result

    def record_tool(self, name: str, args: Any, result: Any = None, **kw: Any) -> Dict[str, Any]:
        return Session.record_tool(self, name, args, result, **kw)

    def note(self, kind: str, data: Any = None) -> Dict[str, Any]:
        st = self._next("note")
        self._report.steps.append(StepReport(st["index"], "note", True))
        return super().note(kind, data)

    def finish_check(self) -> None:
        if self._pos != len(self._trace_steps):
            self._report.errors.append(f"agent stopped after {self._pos} of {len(self._trace_steps)} steps")
            self._report.ok = False


def replay(trace: Mapping[str, Any], client: Any, *, agent: Optional[Callable[[ReplaySession], Any]] = None,
           strict: bool = False, verify_first: bool = True, keys: _verify.KeysLike = None) -> ReplayReport:
    """Replay a recorded session against the API.

    Without ``agent``: re-send every recorded model request in order and check the
    answers are bit-identical (token ids, text, chain digest). Tool and note steps
    are taken from the trace.

    With ``agent``: call ``agent(session)`` with a :class:`ReplaySession`. Your code
    runs again; model calls go to the API and are checked, tool calls return the
    recorded results. Any change in the order or arguments of calls is a divergence.

    ``strict=True`` stops at the first divergence (raises :class:`ReplayDivergence`
    for agent replays). The new run is recorded in ``report.replay_trace``."""
    report = ReplayReport(True)
    if verify_first:
        v = verify_trace(trace, keys=keys)
        if not v.ok:
            report.ok = False
            report.errors.append("trace failed verification: " + "; ".join(v.errors[:5]))
            return report
    rs = ReplaySession(client, trace, report, strict)
    if agent is not None:
        try:
            agent(rs)
        except ReplayDivergence:
            pass
        else:
            rs.finish_check()
    else:
        for st in trace["steps"]:
            b = st["body"]
            if st["type"] == "model":
                q = b["request"]
                try:
                    rs.chat(q["messages"], model=q.get("model"), max_tokens=q.get("max_tokens"), privacy=q.get("privacy"))
                except ReplayDivergence:
                    break
            elif st["type"] == "tool":
                try:
                    rs.tool(b["name"], json.loads(b["args_json"]))
                except RuntimeError:
                    pass
            else:
                rs.note(b["kind"], json.loads(b["data_json"]))
    report.replay_trace = rs.finish()
    return report


# ------------------------------------------------------------------ CLI
def _cli(argv: Optional[Sequence[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="idemcore-trace",
                                 description="Verify, inspect or replay an Idemcore agent trace.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="offline check (no network)")
    v.add_argument("trace")
    v.add_argument("--signer", action="append", help="trusted signer key id (ed25519:...)")
    v.add_argument("--no-receipts", action="store_true", help="skip receipt signature checks")
    v.add_argument("--keys", help="JWKS file of trusted receipt keys (default: bundled Idemcore keys)")
    s = sub.add_parser("show", help="print the steps")
    s.add_argument("trace")
    r = sub.add_parser("replay", help="re-run the model calls (needs IDEMCORE_API_KEY)")
    r.add_argument("trace")
    r.add_argument("--out", help="write the replay's own trace here")
    a = ap.parse_args(argv)
    t = load_trace(a.trace)
    if a.cmd == "verify":
        keys = None
        if a.keys:
            with open(a.keys, encoding="utf-8") as f:
                keys = json.load(f)
        res = verify_trace(t, keys=keys, check_receipts=not a.no_receipts, trusted_signers=a.signer)
        print(("OK" if res.ok else "FAILED") + f": {res.steps} steps ({res.model_steps} model, {res.tool_steps} tool)"
              + (f", signed by {', '.join(res.signers)}" if res.signers else ""))
        for e in res.errors:
            print("  error:", e)
        for w in res.warnings:
            print("  note:", w)
        return 0 if res.ok else 1
    if a.cmd == "show":
        m = t["manifest"]
        print(f"{m['session_id']}  {m['created_at']}  {m['step_count']} steps  head {m['head'][:16]}")
        for st in t["steps"]:
            b = st["body"]
            if st["type"] == "model":
                txt = b["output_text"].replace("\n", " ")
                print(f"  #{st['index']} model {b['receipt_id']} {b['receipt'].get('output_tokens')} tok: {txt[:70]}")
            elif st["type"] == "tool":
                print(f"  #{st['index']} tool  {b['name']}({b['args_json'][:50]}) -> {(b['result_json'] or b['error'] or '')[:50]}")
            else:
                print(f"  #{st['index']} note  {b['kind']} {b['data_json'][:60]}")
        return 0
    from .client import Idemcore
    rep = replay(t, Idemcore())
    print(rep.summary())
    for s_ in rep.steps:
        if s_.type == "model":
            print(f"  #{s_.index} {'identical' if s_.identical else 'DIFFERENT'} {s_.receipt_id} -> {s_.replay_receipt_id}"
                  + "".join(f"\n      {d}" for d in s_.diffs + s_.notes))
    if a.out and rep.replay_trace:
        save_trace(rep.replay_trace, a.out)
    return 0 if rep.ok else 1


