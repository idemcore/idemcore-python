# SPDX-License-Identifier: Apache-2.0
import asyncio
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from mock_api import KEY, V, MockAPI  # noqa: E402

import idemcore  # noqa: E402
from idemcore import (AsyncIdemcore, AuthenticationError, Idemcore, InvalidRequestError,  # noqa: E402
                      NotFoundError, RateLimitError, ServiceUnavailableError)


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.api = MockAPI().__enter__()
        self.c = Idemcore(KEY, base_url=self.api.url + "/v1", max_retries=1)

    def tearDown(self):
        self.api.__exit__()

    def last(self):
        return self.api.state.requests[-1]

    def test_health_needs_no_key(self):
        self.assertEqual(Idemcore(api_key="", base_url=self.api.url).health()["ok"], True)
        self.assertNotIn("Authorization", self.last()["headers"])

    def test_env_key_and_repr(self):
        os.environ["IDEMCORE_API_KEY"] = KEY
        try:
            c = Idemcore(base_url=self.api.url)
            self.assertEqual(c.models()[0]["id"], "qwen2.5-7b-instruct-q4")
            self.assertNotIn(KEY, repr(c))
            self.assertIn("set", repr(c))
        finally:
            del os.environ["IDEMCORE_API_KEY"]

    def test_missing_key(self):
        os.environ.pop("IDEMCORE_API_KEY", None)
        with self.assertRaises(AuthenticationError):
            Idemcore(base_url=self.api.url).models()
        with self.assertRaises(AuthenticationError):
            Idemcore("ick_" + "B" * 43, base_url=self.api.url).models()

    def test_chat(self):
        r = self.c.chat("What is the capital of France?", max_tokens=64, privacy="hash_only")
        req = self.last()
        self.assertEqual(req["path"], "/v1/chat/completions")
        self.assertEqual(req["headers"]["Authorization"], "Bearer " + KEY)
        self.assertEqual(req["body"], {"messages": [{"role": "user", "content": "What is the capital of France?"}],
                                       "max_tokens": 64, "idemcore": {"privacy": "hash_only"}})
        self.assertEqual(r.text, V["output_text"])
        self.assertTrue(r.receipt_id.startswith("rcpt_"))
        self.assertEqual(r.receipt["receipt_id"], r.receipt_id)
        self.assertEqual(r.salt, V["salt_b64u"])
        self.assertEqual(r.output_token_ids, V["output_ids"])
        self.assertEqual(r.usage["total_tokens"], 27)
        self.assertEqual(r.rate_limit["x-ratelimit-limit-requests"], "60")

    def test_chat_local_validation(self):
        for kw in ({"temperature": 0.7}, {"max_tokens": 0}, {"max_tokens": 4096}, {"privacy": "public"}):
            with self.assertRaises(InvalidRequestError):
                self.c.chat("hi", **kw)
        with self.assertRaises(InvalidRequestError):
            self.c.chat([])
        self.c.chat("hi", temperature=0)  # 0 is accepted and not sent
        self.assertNotIn("temperature", self.last()["body"])

    def test_verify_local_full_chain(self):
        r = self.c.chat(V["messages"])
        res = self.c.verify_local(r, keys=V["keys"])
        self.assertTrue(res.ok, {k: v.errors for k, v in res.levels.items()})
        self.assertEqual(set(res.levels), {"L1", "L2", "disclosure"})
        self.assertEqual(res.levels["disclosure"].details["checked"],
                         ["prompt_hash", "output_token_hash", "output_text_hash"])
        # the bundled keys are production keys; the test receipt is not signed by them
        bad = self.c.verify_local(r)
        self.assertFalse(bad.ok)
        self.assertIn("unknown key_id", bad.levels["L1"].errors[0])
        # a changed answer text is caught
        r.text = "The capital of France is Lyon."
        self.assertFalse(self.c.verify_local(r, keys=V["keys"], fetch_log=False).ok)

    def test_receipt_endpoints(self):
        rid = V["receipts"]["full"]["receipt_id"]
        self.assertEqual(self.c.get_receipt(rid), V["receipts"]["full"])
        log = self.c.get_receipt_log(rid)
        self.assertEqual(log.log_format, "idemcore-log/r1-public")
        self.assertEqual(log.log_text, V["log_text"])
        self.assertEqual(self.last()["path"], f"/v1/receipts/{rid}/log")
        with self.assertRaises(InvalidRequestError):
            self.c.get_receipt("rcpt_../admin")
        with self.assertRaises(NotFoundError):
            self.c.get_receipt("rcpt_" + "0" * 24)
        self.assertEqual(self.c.keys()["keys"], V["keys"])

    def test_verify_remote_replay_audit(self):
        r = self.c.chat(V["messages"])
        self.assertTrue(self.c.verify_remote(r.receipt, messages=r.messages, salt=r.salt,
                                             output_token_ids=r.output_token_ids)["ok"])
        b = self.last()["body"]
        self.assertEqual(b["disclosure"]["salt"], V["salt_b64u"])
        self.assertEqual(self.c.replay_result(r, build="alt")["level"], "L3")
        self.assertEqual(self.last()["body"]["receipt_id"], r.receipt_id)
        lines = self.c.audit_export("2026-10-01", "2026-10-31", include_logs=True)
        self.assertEqual(lines[0]["type"], "header")
        self.assertEqual(self.last()["body"], {"since": "2026-10-01", "until": "2026-10-31", "include_logs": True})
        self.assertEqual(self.c.audit_export(format="json")["format"], "idemcore-audit-export/r1")

    def test_errors_and_retries(self):
        st = self.api.state
        st.fail_next = [(429, "rate_limit_error", {"retry-after": "0"})]
        self.assertTrue(self.c.models())  # GET retried once
        st.fail_next = [(429, "rate_limit_error", {"retry-after": "0"})]
        with self.assertRaises(RateLimitError) as cm:
            self.c.chat("hi")  # chat is never retried
        self.assertEqual(cm.exception.status, 429)
        self.assertEqual(cm.exception.retry_after, 0.0)
        st.fail_next = [(429, "insufficient_quota", {})]
        with self.assertRaises(idemcore.InsufficientQuotaError):
            self.c.models()
        st.fail_next = [(503, "service_unavailable", {}), (503, "service_unavailable", {})]
        with self.assertRaises(ServiceUnavailableError):
            self.c.models()

    def test_stream(self):
        with self.c.chat_stream(V["messages"]) as s:
            parts = [ch.delta for ch in s]
        self.assertEqual("".join(parts), V["output_text"])
        self.assertTrue(s.receipt_id.startswith("rcpt_"))
        self.assertEqual(s.result.text, V["output_text"])
        self.assertEqual(s.result.receipt_id, s.receipt_id)
        self.assertEqual(s.result.usage["total_tokens"], 27)
        self.assertEqual(s.result.salt, V["salt_b64u"])
        self.assertEqual(self.last()["body"]["stream_options"], {"include_usage": True})
        self.assertTrue(self.c.verify_local(s.result, keys=V["keys"]).ok)

    def test_stream_error(self):
        with self.assertRaises(ServiceUnavailableError):
            self.c.chat_stream("FAIL").until_done()

    def test_async(self):
        async def run():
            a = AsyncIdemcore(KEY, base_url=self.api.url)
            r = await a.chat(V["messages"])
            s = await a.chat_stream(V["messages"])
            text = "".join([c.delta async for c in s])
            v = await a.verify_local(r, keys=V["keys"])
            return r, text, s.result, v
        r, text, sr, v = asyncio.run(run())
        self.assertEqual(r.text, text)
        self.assertEqual(sr.receipt_id, r.receipt_id)
        self.assertTrue(v.ok)


@unittest.skipUnless(os.environ.get("IDEMCORE_LIVE") == "1", "set IDEMCORE_LIVE=1 for the live /health smoke test")
class LiveSmoke(unittest.TestCase):
    def test_health(self):
        h = Idemcore(api_key="").health()
        self.assertTrue(h["ok"])


if __name__ == "__main__":
    unittest.main()
