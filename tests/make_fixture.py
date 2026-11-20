# SPDX-License-Identifier: Apache-2.0
"""Regenerate tests/fixtures/py.trace.json (used by the JS SDK's cross-language test)."""
import os
import sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from mock_api import KEY, MockAPI  # noqa: E402
from test_trace import agent  # noqa: E402
from idemcore import Idemcore, trace  # noqa: E402

with MockAPI() as api:
    s = trace.Session(Idemcore(KEY, base_url=api.url + "/v1"), meta={"fixture": "py", "unicode": "Hà Nội ✓"},
                      session_id="ses_000000000000000000000001")
    agent(s)
    s.record_tool("floats", {"x": 0.1, "y": [1e-7, 2.5]}, {"ok": True})
    s.created_at = "2026-11-01T00:00:00.000Z"
    trace.save_trace(s.finish(), os.path.join(HERE, "fixtures", "py.trace.json"))
print("ok")
