# SPDX-License-Identifier: Apache-2.0
import os
import unittest

from mock_api import V
from idemcore import verify as v


class VectorTests(unittest.TestCase):
    def test_expectations(self):
        for name, exp in V["expect"].items():
            r = V["receipts"]["full"] if name == "bad_log" else V["receipts"][name]
            if "l1" in exp:
                self.assertEqual(v.verify_l1(r, V["keys"]).ok, exp["l1"], name)
            if "l2" in exp:
                log = V["bad_log_text"] if name == "bad_log" else V["log_text"]
                self.assertEqual(v.verify_l2(r, log).ok, exp["l2"], name)

    def test_disclosure(self):
        salt = V["salt_b64u"]
        for name in ("hash_only", "hash_only_text", "full", "full_text"):
            r = V["receipts"][name]
            d = v.verify_disclosure(r, messages=V["messages"], salt=salt, output_token_ids=V["output_ids"],
                                    output_text=V["output_text"] if name.endswith("_text") else None)
            self.assertTrue(d.ok, (name, d.errors))
        r = V["receipts"]["hash_only"]
        self.assertFalse(v.verify_disclosure(r, messages=V["messages"]).ok)  # no salt
        self.assertFalse(v.verify_disclosure(r, salt=salt, output_token_ids=V["output_ids"][:-1]).ok)
        self.assertFalse(v.verify_disclosure(r, salt=salt, output_text="x").ok)  # no output_text_hash

    def test_text_normalisation(self):
        r = V["receipts"]["hash_only_text"]
        spaced = "  The capital\u00a0of France\n is   Paris. "
        self.assertTrue(v.verify_disclosure(r, salt=V["salt_b64u"], output_text=spaced).ok)

    def test_log_and_format(self):
        d = v.log_digests(V["log_text"])
        self.assertEqual(d["chain_fnv"], d["all_line"])
        six = V["log_text"].replace("\nALL", " 1 2\nALL", 1)
        self.assertFalse(v.verify_l2(V["receipts"]["full"], six).ok)
        r = dict(V["receipts"]["full"])
        r["extra"] = 1
        self.assertIn("unknown field extra", v.check_format(r))
        r = dict(V["receipts"]["full"])
        r["seed"] = 1.5
        self.assertTrue(v.check_format(r))

    def test_keys(self):
        ks = v.load_keys()
        self.assertEqual(ks[0].key_id, v.DEFAULT_TRUSTED_KEYS[0]["kid"])
        self.assertEqual(len(v.load_keys({"keys": V["keys"]})), 1)
        bad = dict(V["keys"][0], kid="ed25519:0000000000000000")
        with self.assertRaises(ValueError):
            v.load_keys([bad])

    def test_verify_receipt(self):
        res = v.verify_receipt(V["receipts"]["full"], keys=V["keys"], log_text=V["log_text"],
                               messages=V["messages"], output_token_ids=V["output_ids"])
        self.assertTrue(res)
        self.assertEqual(list(res.levels), ["L1", "L2", "disclosure"])
        res = v.verify_receipt(V["receipts"]["tampered"], keys=V["keys"])
        self.assertFalse(res)


if __name__ == "__main__":
    unittest.main()
