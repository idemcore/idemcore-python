# SPDX-License-Identifier: Apache-2.0
"""A tiny local stand-in for the Idemcore API, built from the receipt test vectors
(ephemeral key, not a production key). Records every request it receives."""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
V = json.load(open(os.path.join(HERE, "vectors.json"), encoding="utf-8"))
KEY = "ick_" + "A" * 43  # obviously fake test key


class State:
    def __init__(self):
        self.requests = []
        self.fail_next = []  # list of (status, type, headers)


def chat_body(receipt, salt=True):
    rid = receipt["receipt_id"]
    d = {"id": "chatcmpl-" + rid[5:], "object": "chat.completion", "created": 1, "model": receipt["model_id"],
         "choices": [{"index": 0, "message": {"role": "assistant", "content": V["output_text"]},
                      "finish_reason": "stop", "logprobs": None}],
         "usage": {"prompt_tokens": 20, "completion_tokens": 7, "total_tokens": 27},
         "idemcore_receipt": receipt, "idemcore": {"receipt": receipt}}
    if salt:
        d["idemcore_salt"] = V["salt_b64u"]
        d["idemcore_salt_warning"] = "keep the salt private"
        d["idemcore"]["disclosure"] = {"salt": V["salt_b64u"], "output_token_ids": V["output_ids"],
                                       "warning": "keep the salt private"}
    return d


def make_handler(state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, status, obj, headers=None, ctype="application/json"):
            body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _err(self, status, typ, msg, headers=None):
            self._send(status, {"error": {"type": typ, "message": msg}}, headers)

        def _handle(self, method):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            body = json.loads(raw) if raw else None
            state.requests.append({"method": method, "path": self.path, "headers": dict(self.headers), "body": body})
            path = self.path.split("?")[0]
            if path == "/health" and method == "GET":
                return self._send(200, {"ok": True, "service": "idemcore-receipts", "version": "0.1.0"})
            if self.headers.get("Authorization") != "Bearer " + KEY:
                return self._err(401, "authentication_error", "invalid or missing API key")
            if state.fail_next:
                st, typ, hd = state.fail_next.pop(0)
                return self._err(st, typ, "injected", hd)
            if method == "POST" and self.headers.get("Content-Type") != "application/json":
                return self._err(415, "invalid_request_error", "Content-Type must be application/json")
            if path == "/v1/models":
                return self._send(200, {"object": "list", "data": [{"id": "qwen2.5-7b-instruct-q4", "object": "model", "owned_by": "idemcore"}]})
            if path == "/v1/keys":
                return self._send(200, {"keys": V["keys"]})
            if path == "/v1/chat/completions":
                r = V["receipts"]["hash_only_text"]
                if body.get("stream"):
                    return self._stream(r, body)
                return self._send(200, chat_body(r), {"Idemcore-Receipt-Id": r["receipt_id"],
                                                      "x-ratelimit-limit-requests": "60"})
            if path.startswith("/v1/receipts/rcpt_"):
                rid = path.split("/")[3]
                rec = next((x for x in V["receipts"].values() if x["receipt_id"] == rid), None)
                if rec is None:
                    return self._err(404, "not_found_error", "receipt not found")
                if path.endswith("/log"):
                    return self._send(200, {"receipt_id": rid, "receipt": rec, "log_format": "idemcore-log/r1-public",
                                            "log_text": V["log_text"]})
                return self._send(200, {"receipt": rec})
            if path == "/v1/receipts/verify":
                return self._send(200, {"ok": True, "levels": {"L1": {"level": "L1", "ok": True, "errors": []}}})
            if path == "/v1/receipts/replay":
                return self._send(200, {"ok": True, "level": "L3", "errors": [], "mode": "score", "replay_build": "alt"})
            if path == "/v1/audit/export":
                if (body or {}).get("format") == "json":
                    return self._send(200, {"format": "idemcore-audit-export/r1", "receipts": [], "events": []})
                lines = [{"type": "header", "format": "idemcore-audit-export/r1"},
                         {"type": "receipt", "receipt": V["receipts"]["full"]}]
                return self._send(200, ("\n".join(json.dumps(x) for x in lines) + "\n").encode(),
                                  ctype="application/x-ndjson")
            return self._err(404, "not_found_error", "unknown endpoint")

        def _stream(self, r, body):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Idemcore-Receipt-Id", r["receipt_id"])
            self.end_headers()
            base = {"id": "chatcmpl-x", "object": "chat.completion.chunk", "created": 1, "model": r["model_id"]}
            def ev(obj):
                self.wfile.write(b"data: " + json.dumps(obj).encode() + b"\n\n")
                self.wfile.flush()
            ev({**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}, "finish_reason": None}]})
            self.wfile.write(b": keep-alive\n\n")
            if body.get("messages", [{}])[0].get("content") == "FAIL":
                ev({"error": {"type": "service_unavailable", "message": "inference backend unavailable"}})
                return
            text = V["output_text"]
            for part in (text[:10], text[10:]):
                ev({**base, "choices": [{"index": 0, "delta": {"content": part}, "finish_reason": None}]})
            fin = chat_body(r)
            ev({**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                "idemcore_receipt": r, "idemcore_salt": fin["idemcore_salt"], "idemcore": fin["idemcore"]})
            ev({**base, "choices": [], "usage": {"prompt_tokens": 20, "completion_tokens": 7, "total_tokens": 27}})
            self.wfile.write(b"data: [DONE]\n\n")

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

    return H


class MockAPI:
    def __enter__(self):
        self.state = State()
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.state))
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *a):
        self.srv.shutdown()
        self.srv.server_close()
