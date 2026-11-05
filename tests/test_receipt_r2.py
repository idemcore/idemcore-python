# SPDX-License-Identifier: Apache-2.0
"""Reference vectors for receipt formats r1 and r2."""
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
    verify_l1,
    verify_l2,
)

FIX = Path(__file__).parent / "fixtures"
V1 = json.loads((FIX / "vectors_r1.json").read_text())
V2 = json.loads((FIX / "vectors_r2.json").read_text())


class ReceiptR2(unittest.TestCase):
    def test_versions(self):
        self.assertEqual(RECEIPT_VERSION, "r2")
        self.assertEqual(RECEIPT_VERSIONS, ("r1", "r2"))

    def test_r1_and_r2_verify(self):
        for name, R, jwk in (("r1", V1["receipt"], V1["public_jwk"]), ("r2", V2["receipt"], V2["public_jwk"])):
            keys = [TrustedKey.from_jwk(jwk, "test")]
            self.assertEqual(R["receipt_version"], name)
            self.assertEqual(chain_check_field(R), "chain_check" if name == "r2" else "chain_fnv")
            self.assertTrue(verify_l1(R, keys).ok, name)
            self.assertTrue(verify_l2(R, V1["log"]).ok, name)

    def test_r2_neutral_names(self):
        r = dict(V2["receipt"])
        for k in ("seed", "chain_fnv", "kernel_version"):
            self.assertNotIn(k, r)
        self.assertIn("unknown field seed", check_format({**r, "seed": 0}))
        self.assertTrue(any("unsupported" in e for e in check_format({**r, "receipt_version": "r3"})))
        keys = [TrustedKey.from_jwk(V2["public_jwk"], "test")]
        self.assertFalse(verify_l1({**r, "variant": 1}, keys).ok)
        self.assertIn("chain_check mismatch", verify_l2({**r, "chain_check": "0" * 16}, V1["log"]).errors)


if __name__ == "__main__":
    unittest.main()
