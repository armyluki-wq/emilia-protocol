# SPDX-License-Identifier: Apache-2.0
"""Separate opt-in profile; fixtures include valid and hostile signed receipts."""
import json
from pathlib import Path

import unittest
from emilia_verify import canonicalize, verify_resolution_receipt
from emilia_verify.resolution_bme04 import compute_bme04_digest, verify_bme04_resolution_receipt

ROOT = Path(__file__).resolve().parents[3]
SUITE = json.loads((ROOT / "conformance/vectors/resolution.bme04.v1.json").read_text())
OLD_SUITE = json.loads((ROOT / "conformance/vectors/resolution.v1.json").read_text())


def check_upstream_digest(case):
    assert compute_bme04_digest(case["json"]) == case["digest"]
    if "canonical_bytes" in case:
        assert len(canonicalize(json.loads(case["json"])).encode()) == case["canonical_bytes"]


def check_shared_vector(vector):
    before = json.dumps(vector)
    result = verify_bme04_resolution_receipt(vector["receipt_json"], vector["options"])
    for key, expected in vector["expected"].items():
        assert result[key] == expected, result
    assert json.dumps(vector) == before


def check_resource_boundary(case):
    count = case["count"]
    if case["kind"] == "depth":
        raw = '{"a":' + '[' * count + ']' * count + '}'
    elif case["kind"] == "nodes":
        raw = '{"a":[' + ','.join(['0'] * count) + ']}'
    else:
        raw = '{"a":"' + 'x' * (count - 8) + '"}'
    assert compute_bme04_digest(raw) == case["digest"]


def check_legacy_relabel_and_raw_input_refusals():
    vector = SUITE["vectors"][0]
    receipt = json.loads(vector["receipt_json"])
    assert not verify_resolution_receipt(receipt, vector["options"])["valid"]
    receipt["profile"] = "EP-RESOLUTION-v1"
    assert not verify_resolution_receipt(receipt, vector["options"])["valid"]
    legacy = next(v for v in OLD_SUITE["vectors"] if v["id"] == "accept_approved")["resolution_receipt"]
    assert not verify_bme04_resolution_receipt(json.dumps(legacy), vector["options"])["valid"]
    legacy = dict(legacy, profile=SUITE["profile"])
    assert not verify_bme04_resolution_receipt(json.dumps(legacy), vector["options"])["valid"]
    for raw in [None, {}, [], "", "{} trailing", "[]", "null", '{"x":NaN}']:
        assert not verify_bme04_resolution_receipt(raw, vector["options"])["valid"]
    assert not verify_bme04_resolution_receipt(vector["receipt_json"])["valid"]


class Bme04Tests(unittest.TestCase):
    def test_upstream(self):
        for case in SUITE["canonicalization"]:
            with self.subTest(id=case["id"]):
                check_upstream_digest(case)

    def test_vectors(self):
        for vector in SUITE["vectors"]:
            with self.subTest(id=vector["id"]):
                check_shared_vector(vector)

    def test_boundaries(self):
        for case in SUITE["digest_boundaries"]:
            with self.subTest(id=case["id"]):
                check_resource_boundary(case)

    def test_isolation(self):
        check_legacy_relabel_and_raw_input_refusals()


if __name__ == "__main__":
    unittest.main()
