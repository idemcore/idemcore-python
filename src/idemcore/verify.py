# SPDX-License-Identifier: Apache-2.0
"""Local (offline) verification of Idemcore receipts, format r1.

Levels:

* ``L1``: receipt format and Ed25519 signature against a trusted key set.
  Uses the ``cryptography`` package for Ed25519.
* ``L2``: the receipt's ``chain_digest`` and ``chain_fnv`` recomputed from the
  answer's public token log (``GET /v1/receipts/{id}/log``). Standard library only;
  the FNV-1a-64 chain comes from the ``idemcore-verify`` package.
* ``disclosure``: the prompt, output token ids and displayed text checked against the
  salted commitments in the receipt.

L3 (re-running the answer on an independent build) is a server operation:
see :meth:`idemcore.Idemcore.replay`.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import struct
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Union

from idemcore_verify.core import FNV_OFFSET, fnv1a64

__all__ = [
    "DEFAULT_TRUSTED_KEYS", "TrustedKey", "LevelResult", "VerificationResult",
    "canonical_json", "check_format", "verify_l1", "verify_l2", "verify_disclosure",
    "verify_receipt", "parse_public_log", "log_digests", "load_keys",
]

#: Idemcore receipt-signing public keys (public halves only), bundled so receipts
#: verify offline. The live set is published at ``GET /v1/keys``.
DEFAULT_TRUSTED_KEYS: List[Dict[str, str]] = [
    {"kty": "OKP", "crv": "Ed25519", "x": "AdQX-eipjpmqi4GDvqYHIep2Vb7l5Vas4xncNN453OY",
     "kid": "ed25519:2fab59995ac55e4f"},
]

RECEIPT_VERSION = "r1"
SIG_DOMAIN = b"idemcore-receipt/r1\n"
CHAIN_DOMAIN = b"idemcore/chain/r1\x00"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX16 = re.compile(r"^[0-9a-f]{16}$")
_HEXF = re.compile(r"^[0-9a-fA-F]{1,16}$")
_ISSUED = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,6})?Z$")
_REQUIRED = {
    "receipt_version": str, "receipt_id": str, "issued_at": str, "tenant_id": str,
    "model_id": str, "weights_hash": str, "kernel_version": str, "engine_build": str,
    "privacy": str, "prompt_hash": str, "params_hash": str, "seed": int, "decoding": str,
    "prompt_tokens": int, "output_tokens": int, "output_token_hash": str,
    "chain_digest": str, "chain_fnv": str, "log_ref": str, "key_id": str, "signature": str,
}
_OPTIONAL = {"finish_reason": str, "request_id": str, "output_text_hash": str}
_HASH_FIELDS = ("weights_hash", "prompt_hash", "params_hash", "output_token_hash", "chain_digest")
_SAFE_INT = 2 ** 53 - 1


# ------------------------------------------------------------------ encoding helpers
def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_decode(s: str) -> bytes:
    if not isinstance(s, str) or not re.match(r"^[A-Za-z0-9_-]*$", s):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _check_canonical(v: Any, path: str = "$") -> None:
    if isinstance(v, bool) or v is None or isinstance(v, str):
        return
    if isinstance(v, int):
        if not -_SAFE_INT <= v <= _SAFE_INT:
            raise ValueError(f"{path}: integer outside the safe range")
        return
    if isinstance(v, float):
        raise ValueError(f"{path}: only integers are allowed")
    if isinstance(v, (list, tuple)):
        for i, x in enumerate(v):
            _check_canonical(x, f"{path}[{i}]")
        return
    if isinstance(v, dict):
        for k, x in v.items():
            if not isinstance(k, str):
                raise ValueError(f"{path}: object keys must be strings")
            _check_canonical(x, f"{path}.{k}")
        return
    raise ValueError(f"{path}: unsupported type {type(v).__name__}")


def canonical_json(obj: Any) -> bytes:
    """Canonical JSON (receipts r1): keys sorted by code point, no whitespace,
    UTF-8 with non-ASCII literal, integers only."""
    _check_canonical(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def tagged_hash(tag: str, *parts: bytes) -> str:
    h = hashlib.sha256(f"idemcore/{tag}/r1".encode() + b"\x00")
    for p in parts:
        h.update(struct.pack("<Q", len(p)))
        h.update(p)
    return h.hexdigest()


_WS = re.compile("[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+")


def normalize_text(text: str) -> str:
    """Displayed-text normalisation: NFC, every whitespace run becomes one space, trimmed."""
    s = _WS.sub(" ", unicodedata.normalize("NFC", text))
    if s.startswith(" "):
        s = s[1:]
    if s.endswith(" "):
        s = s[:-1]
    return s


def prompt_hash(messages: Sequence[Mapping[str, Any]], salt: bytes) -> str:
    return tagged_hash("prompt", salt, canonical_json(list(messages)))


def token_hash(ids: Sequence[int], salt: bytes) -> str:
    for i, t in enumerate(ids):
        if not isinstance(t, int) or isinstance(t, bool) or not 0 <= t <= 0xFFFFFFFF:
            raise ValueError(f"token id out of range at {i}")
    return tagged_hash("tokens", salt, struct.pack(f"<{len(ids)}I", *ids))


def text_hash(text: str, salt: bytes) -> str:
    return tagged_hash("text", salt, normalize_text(text).encode("utf-8"))


# ------------------------------------------------------------------ public token log
@dataclass(frozen=True)
class LogLine:
    pi: int
    j: int
    h: int
    hc: int


def parse_public_log(text: str):
    """Parse a public token log (``idemcore-log/r1-public``: ``pi j h hc`` per line
    and an optional ``ALL <fnv>`` line). Returns ``(lines, all_value_or_None)``."""
    lines: List[LogLine] = []
    all_v: Optional[str] = None
    for n, raw in enumerate(text.splitlines(), 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        f = s.split()
        if f[0] == "ALL":
            if len(f) != 2 or not _HEXF.match(f[1]):
                raise ValueError(f"log line {n}: malformed ALL line")
            all_v = f[1].lower()
            continue
        if not (f[0].isdigit() and f[0].isascii()):
            continue  # reserved keyword lines
        if len(f) != 4:
            raise ValueError(f"log line {n}: not a public log line (expected 4 fields: pi j h hc)")
        if not (f[1].isdigit() and f[1].isascii() and _HEXF.match(f[2]) and _HEXF.match(f[3])):
            raise ValueError(f"log line {n}: malformed field")
        ln = LogLine(int(f[0]), int(f[1]), int(f[2], 16), int(f[3], 16))
        if ln.pi >= 2 ** 64 or ln.j >= 2 ** 64:
            raise ValueError(f"log line {n}: index out of range")
        lines.append(ln)
    return lines, all_v


def chain_fnv(lines: Iterable[LogLine]) -> str:
    a = FNV_OFFSET
    for ln in lines:
        a = fnv1a64(struct.pack("<Q", ln.h), a)
        a = fnv1a64(struct.pack("<Q", ln.hc), a)
    return f"{a:016x}"


def chain_digest(lines: Iterable[LogLine]) -> str:
    c = hashlib.sha256(CHAIN_DOMAIN).digest()
    for ln in lines:
        c = hashlib.sha256(c + struct.pack("<QQQQ", ln.pi, ln.j, ln.h, ln.hc)).digest()
    return c.hex()


def log_digests(text: str) -> Dict[str, Any]:
    lines, all_v = parse_public_log(text)
    return {"positions": len(lines), "chain_digest": chain_digest(lines),
            "chain_fnv": chain_fnv(lines), "all_line": all_v}


# ------------------------------------------------------------------ keys
@dataclass(frozen=True)
class TrustedKey:
    key_id: str
    raw: bytes
    source: str = "custom"

    @classmethod
    def from_jwk(cls, jwk: Mapping[str, Any], source: str = "custom") -> "TrustedKey":
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or not isinstance(jwk.get("x"), str):
            raise ValueError("not an Ed25519 public JWK")
        raw = b64u_decode(jwk["x"])
        if len(raw) != 32:
            raise ValueError("Ed25519 public key must be 32 bytes")
        kid = "ed25519:" + hashlib.sha256(raw).hexdigest()[:16]
        if jwk.get("kid") and jwk["kid"] != kid:
            raise ValueError(f"kid {jwk['kid']} does not match the key bytes ({kid})")
        return cls(kid, raw, source)

    def verify(self, sig: bytes, msg: bytes) -> bool:
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError as e:  # pragma: no cover - exercised only without the extra
            raise ImportError("signature checks need the 'cryptography' package: pip install cryptography") from e
        try:
            Ed25519PublicKey.from_public_bytes(self.raw).verify(sig, msg)
            return True
        except (InvalidSignature, ValueError):
            return False


KeysLike = Union[None, Mapping[str, Any], Sequence[Any]]


def load_keys(keys: KeysLike = None, source: str = "custom") -> List[TrustedKey]:
    """Accept ``None`` (bundled keys), a JWK, a list of JWKs/TrustedKeys, or a JWKS
    (``{"keys": [...]}``, as returned by ``GET /v1/keys``)."""
    if keys is None:
        return [TrustedKey.from_jwk(k, "bundled") for k in DEFAULT_TRUSTED_KEYS]
    if isinstance(keys, Mapping):
        keys = keys["keys"] if isinstance(keys.get("keys"), list) else [keys]
    return [k if isinstance(k, TrustedKey) else TrustedKey.from_jwk(k, source) for k in keys]


# ------------------------------------------------------------------ results
@dataclass
class LevelResult:
    level: str
    ok: bool
    errors: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VerificationResult:
    ok: bool
    levels: Dict[str, LevelResult]

    def __bool__(self) -> bool:
        return self.ok


def _res(level: str, errors: List[str], **details: Any) -> LevelResult:
    return LevelResult(level, not errors, errors, details)


# ------------------------------------------------------------------ checks
def check_format(r: Any) -> List[str]:
    if not isinstance(r, dict):
        return ["receipt is not an object"]
    errs: List[str] = []
    for k, t in _REQUIRED.items():
        if k not in r:
            errs.append(f"missing field {k}")
        elif not isinstance(r[k], t) or isinstance(r[k], bool):
            errs.append(f"field {k} must be {t.__name__}")
    for k in r:
        if k not in _REQUIRED and k not in _OPTIONAL:
            errs.append(f"unknown field {k}")
    for k, t in _OPTIONAL.items():
        if k in r and not isinstance(r[k], t):
            errs.append(f"field {k} must be {t.__name__}")
    if errs:
        return errs
    if r["receipt_version"] != RECEIPT_VERSION:
        errs.append(f"unsupported receipt_version {r['receipt_version']}")
    for k in _HASH_FIELDS:
        if not _HEX64.match(r[k]):
            errs.append(f"{k} must be 64 lowercase hex")
    if "output_text_hash" in r and not _HEX64.match(r["output_text_hash"]):
        errs.append("output_text_hash must be 64 lowercase hex")
    if not _HEX16.match(r["chain_fnv"]):
        errs.append("chain_fnv must be 16 lowercase hex")
    if r["privacy"] not in ("hash_only", "full"):
        errs.append("privacy must be hash_only or full")
    if r["prompt_tokens"] < 1 or r["output_tokens"] < 0:
        errs.append("token counts out of range")
    if not _ISSUED.match(r["issued_at"]):
        errs.append("issued_at must be RFC 3339 UTC (Z)")
    try:
        canonical_json(r)
    except ValueError as e:
        errs.append(str(e))
    return errs


def signing_payload(receipt: Mapping[str, Any]) -> bytes:
    return SIG_DOMAIN + canonical_json({k: v for k, v in receipt.items() if k != "signature"})


def verify_l1(receipt: Any, keys: KeysLike = None) -> LevelResult:
    errs = check_format(receipt)
    if errs:
        return _res("L1", errs)
    trusted = {k.key_id: k for k in load_keys(keys)}
    pk = trusted.get(receipt["key_id"])
    if pk is None:
        return _res("L1", [f"unknown key_id {receipt['key_id']} (not in the trusted key set)"])
    try:
        sig = b64u_decode(receipt["signature"])
    except ValueError:
        return _res("L1", ["signature is not base64url"])
    if len(sig) != 64 or not pk.verify(sig, signing_payload(receipt)):
        return _res("L1", ["signature does not verify"])
    return _res("L1", [], key_id=pk.key_id, key_source=pk.source)


def verify_l2(receipt: Mapping[str, Any], log_text: str) -> LevelResult:
    try:
        d = log_digests(log_text)
    except ValueError as e:
        return _res("L2", [f"log parse error: {e}"])
    errs: List[str] = []
    if d["chain_digest"] != receipt.get("chain_digest"):
        errs.append("chain_digest mismatch")
    if d["chain_fnv"] != receipt.get("chain_fnv"):
        errs.append("chain_fnv mismatch")
    if d["all_line"] is not None and d["all_line"] != d["chain_fnv"]:
        errs.append("log ALL line inconsistent with its own lines")
    want = int(receipt.get("prompt_tokens", 0)) + int(receipt.get("output_tokens", 0))
    if d["positions"] != want:
        errs.append(f"log covers {d['positions']} positions, receipt says {want}")
    return _res("L2", errs, positions=d["positions"])


def _salt_bytes(salt: Union[None, str, bytes]) -> Optional[bytes]:
    if salt is None or isinstance(salt, bytes):
        return salt
    return b64u_decode(salt)


def verify_disclosure(receipt: Mapping[str, Any], *, messages: Optional[Sequence[Mapping[str, Any]]] = None,
                      salt: Union[None, str, bytes] = None, output_token_ids: Optional[Sequence[int]] = None,
                      output_text: Optional[str] = None) -> LevelResult:
    """Check disclosed values against the receipt. ``salt`` is the base64url string
    returned with the answer (``idemcore_salt``) or raw bytes; ignored for ``full`` receipts."""
    s = b"" if receipt.get("privacy") == "full" else _salt_bytes(salt)
    if s is None:
        return _res("disclosure", ["salt required for hash_only receipts"])
    errs: List[str] = []
    checked: List[str] = []
    if messages is not None:
        checked.append("prompt_hash")
        if prompt_hash(messages, s) != receipt.get("prompt_hash"):
            errs.append("prompt_hash mismatch")
    if output_token_ids is not None:
        checked.append("output_token_hash")
        if token_hash(list(output_token_ids), s) != receipt.get("output_token_hash"):
            errs.append("output_token_hash mismatch")
    if output_text is not None:
        if not isinstance(receipt.get("output_text_hash"), str):
            errs.append("receipt has no output_text_hash; displayed text cannot be bound")
        else:
            checked.append("output_text_hash")
            if text_hash(output_text, s) != receipt["output_text_hash"]:
                errs.append("output_text_hash mismatch")
    return _res("disclosure", errs, checked=checked)


def verify_receipt(receipt: Mapping[str, Any], *, keys: KeysLike = None, log_text: Optional[str] = None,
                   messages: Optional[Sequence[Mapping[str, Any]]] = None, salt: Union[None, str, bytes] = None,
                   output_token_ids: Optional[Sequence[int]] = None, output_text: Optional[str] = None,
                   check_signature: bool = True) -> VerificationResult:
    """Run every level the inputs allow. L1 always (unless ``check_signature=False``);
    L2 when ``log_text`` is given; disclosure when any disclosed value is given."""
    levels: Dict[str, LevelResult] = {}
    if check_signature:
        levels["L1"] = verify_l1(dict(receipt), keys)
    else:
        errs = check_format(dict(receipt))
        levels["format"] = _res("format", errs)
    if log_text is not None:
        levels["L2"] = verify_l2(receipt, log_text)
    if any(v is not None for v in (messages, output_token_ids, output_text)):
        levels["disclosure"] = verify_disclosure(receipt, messages=messages, salt=salt,
                                                 output_token_ids=output_token_ids, output_text=output_text)
    return VerificationResult(all(lv.ok for lv in levels.values()), levels)
