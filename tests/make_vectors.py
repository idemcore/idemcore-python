# SPDX-License-Identifier: Apache-2.0
"""Regenerate tests/vectors.json: receipt format r2 test vectors.

Each run signs with a fresh throwaway Ed25519 key that is never written to disk,
and uses a synthetic public log (random digests). These are test vectors only;
they are not live receipts and say nothing about how live logs are produced.
"""
import json
import os
import secrets
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
from idemcore import verify as v  # noqa: E402

MESSAGES = [{"role": "user", "content": "What is the capital of France?"}]
OUTPUT_IDS = [785, 6722, 315, 9625, 374, 12095, 13]
OUTPUT_TEXT = "The capital of France is Paris."
PROMPT_TOKENS, OUTPUT_TOKENS = 20, 7
SALT = bytes(range(16))


def new_key():
    sk = Ed25519PrivateKey.generate()
    raw = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": v.b64u(raw)}
    jwk["kid"] = v.TrustedKey.from_jwk(jwk).key_id
    return sk, jwk


def synthetic_log(n):
    lines = [f"{i} 0 {secrets.token_hex(8)} {secrets.token_hex(8)}" for i in range(n)]
    return "\n".join(lines + [f"ALL {secrets.token_hex(8)}"]) + "\n"


def sign(sk, kid, body):
    r = dict(body, key_id=kid)
    r["signature"] = v.b64u(sk.sign(v.signing_payload(r)))
    return r


def main():
    sk, jwk = new_key()
    other_sk, other_jwk = new_key()
    log_text = synthetic_log(PROMPT_TOKENS + OUTPUT_TOKENS)
    lines = log_text.splitlines()
    f = lines[3].split()
    f[3] = f[3][:-1] + ("0" if f[3][-1] != "0" else "1")
    bad_log_text = "\n".join(lines[:3] + [" ".join(f)] + lines[4:]) + "\n"
    digest = v.log_digests(log_text)["chain_digest"]

    def body(n, privacy, with_text):
        salt = b"" if privacy == "full" else SALT
        b = {
            "receipt_version": "r2", "receipt_id": "rcpt_" + "%024x" % (0x7e57 + n),
            "issued_at": "2026-11-20T08:00:%02d.000Z" % n, "tenant_id": "tnt_test",
            "model_id": "qwen2.5-7b-instruct-q4", "weights_hash": "ab" * 32,
            "engine_version": "0.3.0", "engine_build": "test", "privacy": privacy,
            "prompt_hash": v.prompt_hash(MESSAGES, salt), "params_hash": "cd" * 32,
            "variant": 0, "decoding": "greedy", "prompt_tokens": PROMPT_TOKENS,
            "output_tokens": OUTPUT_TOKENS, "output_token_hash": v.token_hash(OUTPUT_IDS, salt),
            "chain_digest": digest, "chain_check": secrets.token_hex(8), "log_ref": "log_test_%04d" % n,
            "finish_reason": "stop",
        }
        if with_text:
            b["output_text_hash"] = v.text_hash(OUTPUT_TEXT, salt)
        return b

    kid = jwk["kid"]
    receipts = {
        "full": sign(sk, kid, body(1, "full", False)),
        "hash_only": sign(sk, kid, body(2, "hash_only", False)),
        "full_text": sign(sk, kid, body(3, "full", True)),
        "hash_only_text": sign(sk, kid, body(4, "hash_only", True)),
        "foreign_key": sign(other_sk, other_jwk["kid"], body(6, "full", False)),
    }
    tampered = dict(receipts["full_text"])
    tampered["model_id"] = "qwen2.5-7b-instruct-q8"
    receipts["tampered"] = tampered

    out = {
        "_note": "Test vectors only (receipt format r2). Throwaway signing key, never stored; synthetic log.",
        "keys": [jwk], "messages": MESSAGES, "output_ids": OUTPUT_IDS, "output_text": OUTPUT_TEXT,
        "salt_b64u": v.b64u(SALT), "log_text": log_text, "bad_log_text": bad_log_text,
        "receipts": receipts,
        "expect": {"full": {"l1": True, "l2": True}, "hash_only": {"l1": True}, "tampered": {"l1": False},
                   "foreign_key": {"l1": False}, "bad_log": {"l2": False}},
    }
    with open(os.path.join(HERE, "vectors.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print("ok")


if __name__ == "__main__":
    main()
