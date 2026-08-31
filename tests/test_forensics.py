#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for forensic evidence module."""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lumenos_sandbox.forensics import (
    EvidenceItem, EvidenceChain, collect_evidence, export_evidence,
)


def _make_item(eid="e1", desc="test evidence"):
    payload = f"{eid}:{desc}:test_source".encode()
    return EvidenceItem(
        evidence_id=eid, bunker_id="b1", description=desc,
        source="test_source", sha256=hashlib.sha256(payload).hexdigest(),
    )


class TestEvidenceItem(unittest.TestCase):
    def test_auto_timestamp(self):
        item = _make_item()
        self.assertIn("2026", item.collected_at)

    def test_default_collector(self):
        item = _make_item()
        self.assertEqual(item.collector, "lumenos_sandbox")


class TestEvidenceChain(unittest.TestCase):
    def test_add_and_verify(self):
        chain = EvidenceChain(bunker_id="b1")
        chain.add(_make_item("e1", "alpha"))
        chain.add(_make_item("e2", "beta"))
        self.assertEqual(len(chain.items), 2)
        self.assertTrue(chain.verify())

    def test_tampered_item_fails_verify(self):
        chain = EvidenceChain(bunker_id="b1")
        item = _make_item("e1", "alpha")
        chain.add(item)
        # Tamper with description after hash was computed
        chain.items[0].description = "TAMPERED"
        self.assertFalse(chain.verify())

    def test_to_dict(self):
        chain = EvidenceChain(bunker_id="b1")
        chain.add(_make_item())
        d = chain.to_dict()
        self.assertEqual(d["bunker_id"], "b1")
        self.assertEqual(d["item_count"], 1)
        self.assertIn("items", d)

    def test_empty_chain_is_valid(self):
        chain = EvidenceChain(bunker_id="b1")
        self.assertTrue(chain.verify())


class TestCollectEvidence(unittest.TestCase):
    def setUp(self):
        self._orig = Path.cwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)

    def tearDown(self):
        os.chdir(self._orig)
        self._tmp.cleanup()

    def test_collect_empty(self):
        chain = collect_evidence("test_bunker")
        self.assertEqual(len(chain.items), 0)

    def test_collect_with_state_db(self):
        Path("lumenos_state.db").write_bytes(b"fake db")
        chain = collect_evidence("test_bunker")
        self.assertEqual(len(chain.items), 1)
        self.assertEqual(chain.items[0].source, "state_db")

    def test_collect_with_decon_report(self):
        logs = Path("logs")
        logs.mkdir()
        (logs / "test_bunker_decontamination_20260101.json").write_text("{}")
        chain = collect_evidence("test_bunker")
        self.assertEqual(len(chain.items), 1)
        self.assertEqual(chain.items[0].source, "decontamination_report")


class TestExportEvidence(unittest.TestCase):
    def test_export(self):
        chain = EvidenceChain(bunker_id="b1")
        chain.add(_make_item())
        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, "evidence", "b1.json")
            result = export_evidence(chain, out)
            self.assertTrue(os.path.exists(result))
            with open(result) as f:
                data = json.load(f)
            self.assertEqual(data["bunker_id"], "b1")
            self.assertEqual(data["item_count"], 1)


if __name__ == "__main__":
    unittest.main()
