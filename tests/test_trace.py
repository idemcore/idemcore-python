# SPDX-License-Identifier: Apache-2.0
import copy
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from mock_api import KEY, V, MockAPI  # noqa: E402

from idemcore import Idemcore  # noqa: E402
from idemcore import trace as T  # noqa: E402

KEYS = {"keys": V["keys"]}
Q = V["messages"]  # the mock's receipt commits to these messages


def weather(city):
    return {"city": city, "temp_c": 18.5, "sky": "cloudy"}


def agent(s):
    """Tiny agent: ask, call a tool, ask again."""
    a = s.chat(Q, max_tokens=16)
    w = s.tool("get_weather", {"city": "Paris"}, weather)
    s.note("approval", {"by": "ops", "ok": True})
    b = s.chat(Q, max_tokens=16)
    return a.text, w, b.text


class TraceTests(unittest.TestCase):
    def setUp(self):
        self.api = MockAPI().__enter__()
        self.c = Idemcore(KEY, base_url=self.api.url + "/v1", max_retries=1)

    def tearDown(self):
        self.api.__exit__()

    def rec(self, **kw):
        s = T.Session(self.c, meta={"task": "demo", "n": 1})
        agent(s)
        return s.finish(**kw)

    def test_tool_result_key_order_survives_replay(self):
        # A prompt built from json.dumps(result) must be byte-identical on replay.
        seen = []

        def ag(s):
            s.chat(Q, max_tokens=16)
            r = s.tool("t", {"q": 1}, lambda q: {"z": 1, "a": {"y": 2, "b": 3}})
            seen.append(json.dumps(r))
        s = T.Session(self.c)
        ag(s)
        t = s.finish()
        self.assertEqual(t["steps"][1]["body"]["result_json"], '{"z":1,"a":{"y":2,"b":3}}')
        self.assertEqual(t["steps"][1]["body"]["args_json"], '{"q":1}')
        rep = T.replay(t, self.c, agent=ag, keys=KEYS)
        self.assertTrue(rep.ok, rep.errors)
        self.assertEqual(seen[0], seen[1])

    def test_record_and_verify(self):
        t = self.rec()
        self.assertEqual(t["manifest"]["step_count"], 4)
        self.assertEqual([x["type"] for x in t["steps"]], ["model", "tool", "note", "model"])
        v = T.verify_trace(t, keys=KEYS)
        self.assertTrue(v.ok, v.errors)
        self.assertEqual((v.model_steps, v.tool_steps), (2, 1))
        # round trip through JSON text
        v2 = T.verify_trace(json.loads(T.dumps_trace(t)), keys=KEYS)
        self.assertTrue(v2.ok, v2.errors)
        # default (production) keys reject the test-key receipts
        self.assertFalse(T.verify_trace(t).ok)
        self.assertTrue(T.verify_trace(t, check_receipts=False).ok)

    def test_tamper_detection(self):
        t = self.rec()
        cases = {
            "tool result": lambda x: x["steps"][1]["body"].__setitem__("result_json", '{"temp_c":30}'),
            "output text": lambda x: x["steps"][0]["body"].__setitem__("output_text", "Lyon."),
            "drop step": lambda x: x["steps"].pop(2),
            "reorder": lambda x: x["steps"].reverse(),
            "receipt": lambda x: x["steps"][3]["body"]["receipt"].__setitem__("output_tokens", 8),
            "manifest meta": lambda x: x["manifest"].__setitem__("meta_json", "{}"),
            "truncate": lambda x: x["steps"].pop(),
        }
        for name, f in cases.items():
            bad = copy.deepcopy(t)
            f(bad)
            self.assertFalse(T.verify_trace(bad, keys=KEYS).ok, name)
        # an attacker who rehashes the edited tool step still breaks the chain
        bad = copy.deepcopy(t)
        b = bad["steps"][1]["body"]
        b["result_json"] = '{"temp_c":30}'
        b["result_hash"] = T._h("trace-tool-result", b["result_json"].encode())
        bad["steps"][1]["hash"] = T.step_hash(bad["steps"][1])
        v = T.verify_trace(bad, keys=KEYS)
        self.assertFalse(v.ok)
        self.assertTrue(any("prev" in e for e in v.errors), v.errors)

    def test_signatures(self):
        k = T.generate_signing_key()
        other = T.generate_signing_key()
        t = self.rec(sign_with=k)
        self.assertNotIn(k["d"], json.dumps(t))
        v = T.verify_trace(t, keys=KEYS, trusted_signers=[k["kid"]])
        self.assertTrue(v.ok, v.errors)
        self.assertEqual(v.signers, [k["kid"]])
        self.assertFalse(T.verify_trace(t, keys=KEYS, trusted_signers=[other["kid"]]).ok)
        self.assertTrue(T.verify_trace(t, keys=KEYS, trusted_signers=[{"x": k["x"]}]).ok)
        bad = copy.deepcopy(t)
        bad["manifest"]["created_at"] = "2020-01-01T00:00:00.000Z"
        bad["manifest_hash"] = T.manifest_hash(bad["manifest"])
        self.assertFalse(T.verify_trace(bad, keys=KEYS, trusted_signers=[k["kid"]]).ok)
        unsigned = self.rec()
        self.assertFalse(T.verify_trace(unsigned, keys=KEYS, require_signature=True).ok)

    def test_replay_model_only(self):
        t = self.rec()
        n = len(self.api.state.requests)
        r = T.replay(t, self.c, keys=KEYS)
        self.assertTrue(r.ok, r.summary())
        self.assertEqual(r.model_calls, 2)
        self.assertEqual(len(self.api.state.requests) - n, 2)  # tools are not re-run against anything
        self.assertTrue(T.verify_trace(r.replay_trace, keys=KEYS).ok)
        self.assertEqual(json.loads(r.replay_trace["manifest"]["meta_json"])["replay_of"], t["manifest"]["session_id"])

    def test_replay_agent_feeds_recorded_tools(self):
        t = self.rec()
        calls = []

        def agent2(s):
            a = s.chat(Q, max_tokens=16)
            w = s.tool("get_weather", {"city": "Paris"}, lambda city: calls.append(city))
            s.note("approval", {"by": "ops", "ok": True})
            s.chat(Q, max_tokens=16)
            self.assertEqual(w["temp_c"], 18.5)
        r = T.replay(t, self.c, agent=agent2, keys=KEYS)
        self.assertTrue(r.ok, r.summary())
        self.assertEqual(calls, [])  # the real tool never ran

    def test_replay_detects_agent_divergence(self):
        t = self.rec()

        def wrong_args(s):
            s.chat(Q, max_tokens=16)
            s.tool("get_weather", {"city": "Rome"})
        r = T.replay(t, self.c, agent=wrong_args, keys=KEYS)
        self.assertFalse(r.ok)
        self.assertIn("differs", r.errors[0])

        def stops_early(s):
            s.chat(Q, max_tokens=16)
        r = T.replay(t, self.c, agent=stops_early, keys=KEYS)
        self.assertFalse(r.ok)

        def other_prompt(s):
            s.chat([{"role": "user", "content": "hi"}], max_tokens=16)
        r = T.replay(t, self.c, agent=other_prompt, keys=KEYS)
        self.assertFalse(r.ok)

    def test_replay_detects_output_divergence(self):
        t = self.rec()
        real = self.c.chat

        def drift(*a, **k):
            r = real(*a, **k)
            r.output_token_ids = r.output_token_ids[:-1] + [r.output_token_ids[-1] + 1]
            r.receipt = dict(r.receipt, chain_digest="0" * 64, engine_build="other")
            return r
        self.c.chat = drift
        r = T.replay(t, self.c, keys=KEYS)
        self.assertFalse(r.ok)
        d = r.steps[0]
        self.assertFalse(d.identical)
        self.assertTrue(any("position 6" in x for x in d.diffs), d.diffs)
        self.assertTrue(any("chain_digest" in x for x in d.diffs))
        self.assertTrue(any("engine_build" in x for x in d.notes))
        r = T.replay(t, self.c, keys=KEYS, agent=agent, strict=True)
        self.assertFalse(r.ok)
        self.assertEqual(r.model_calls, 1)

    def test_replay_refuses_tampered_trace(self):
        t = self.rec()
        t["steps"][1]["body"]["result_json"] = "{}"
        r = T.replay(t, self.c, keys=KEYS)
        self.assertFalse(r.ok)
        self.assertEqual(r.model_calls, 0)

    def test_tool_errors_and_values(self):
        s = T.Session(self.c)

        def boom(**_):
            raise ValueError("nope")
        with self.assertRaises(ValueError):
            s.tool("boom", {"a": 1}, boom)
        s.record_tool("ext", [1, 2.5, "é"], {"ok": True})
        with self.assertRaises(TypeError):
            s.record_tool("bad", {"x": object()}, None)
        with self.assertRaises(TypeError):
            s.record_tool("nan", {"x": float("nan")}, None)
        t = s.finish()
        self.assertEqual(t["steps"][0]["body"]["error"], "ValueError: nope")
        self.assertEqual(t["steps"][1]["body"]["args_json"], '[1,2.5,"é"]')
        self.assertTrue(T.verify_trace(t, keys=KEYS).ok)
        with self.assertRaises(RuntimeError):
            s.note("late")

    def test_stream_record_model(self):
        s = T.Session()
        st = self.c.chat_stream(Q, max_tokens=16)
        res = st.until_done()
        s.record_model(res, max_tokens=16, streamed=True)
        t = s.finish()
        self.assertTrue(T.verify_trace(t, keys=KEYS).ok)
        self.assertTrue(T.replay(t, self.c, keys=KEYS).ok)

    def test_empty_and_garbage(self):
        t = T.Session().finish()
        self.assertTrue(T.verify_trace(t).ok)
        self.assertFalse(T.verify_trace({}).ok)
        self.assertFalse(T.verify_trace({"manifest": {"format": "x"}, "steps": []}).ok)

    def test_cli(self):
        t = self.rec(sign_with=T.generate_signing_key())
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "run.trace.json")
            T.save_trace(t, p)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = T._cli(["show", p])
            self.assertEqual(rc, 0)
            self.assertIn("tool  get_weather", buf.getvalue())
            with redirect_stdout(io.StringIO()):
                self.assertEqual(T._cli(["verify", p, "--no-receipts"]), 0)
            t["steps"][1]["body"]["result_json"] = "{}"
            T.save_trace(t, p)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(T._cli(["verify", p, "--no-receipts"]), 1)

    def test_cross_language_fixture(self):
        """A trace recorded by the JS SDK (test/fixtures) verifies here."""
        p = os.path.join(HERE, "fixtures", "js.trace.json")
        if not os.path.exists(p):
            self.skipTest("no JS fixture")
        t = T.load_trace(p)
        v = T.verify_trace(t, keys=KEYS)
        self.assertTrue(v.ok, v.errors)

        def agent_js(s):
            agent(s)
            s.tool("floats", {"x": 0.1, "y": [1e-7, 2.5]})  # JS wrote 1e-7: compared by value
        r = T.replay(t, self.c, agent=agent_js, keys=KEYS)
        self.assertTrue(r.ok, r.summary())


if __name__ == "__main__":
    unittest.main()
