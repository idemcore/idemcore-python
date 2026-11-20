# SPDX-License-Identifier: Apache-2.0
"""Receipt format r2: field names and the reference vector."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from idemcore.verify import (
    RECEIPT_VERSION,
    RECEIPT_VERSIONS,
    TrustedKey,
    chain_check_field,
    check_format,
    receipt_field,
    verify_l1,
    verify_l2,
)

HERE = Path(__file__).parent
V = json.loads((HERE / "vectors.json").read_text(encoding="utf-8"))
V2 = json.loads((HERE / "fixtures" / "vectors_r2.json").read_text(encoding="utf-8"))


class ReceiptR2(unittest.TestCase):
    def test_versions(self):
        self.assertEqual(RECEIPT_VERSION, "r2")
        self.assertEqual(RECEIPT_VERSIONS, ("r1", "r2"))

    def test_reference_vector_signature(self):
        R = V2["receipt"]
        self.assertEqual(R["receipt_version"], "r2")
        self.assertEqual(chain_check_field(R), "chain_check")
        self.assertTrue(verify_l1(R, [TrustedKey.from_jwk(V2["public_jwk"], "test")]).ok)

    def test_r2_fields(self):
        r = dict(V["receipts"]["full"])
        keys = V["keys"]
        self.assertTrue(verify_l1(r, keys).ok)
        self.assertTrue(verify_l2(r, V["log_text"]).ok)
        self.assertEqual(receipt_field(r, "variant"), r["variant"])
        self.assertEqual(receipt_field(r, "engine_version"), r["engine_version"])
        self.assertIn("unknown field seed", check_format({**r, "seed": 0}))
        self.assertTrue(any("unsupported" in e for e in check_format({**r, "receipt_version": "r3"})))
        self.assertFalse(verify_l1({**r, "variant": 1}, keys).ok)
        self.assertTrue(verify_l2({**r, "chain_check": "0" * 16}, V["log_text"]).ok)  # chain_digest only
        self.assertIn("chain_digest mismatch", verify_l2({**r, "chain_digest": "0" * 64}, V["log_text"]).errors)
        self.assertFalse(verify_l2(r, V["bad_log_text"]).ok)


if __name__ == "__main__":
    unittest.main()
