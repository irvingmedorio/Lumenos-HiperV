#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for SQLite-backed state persistence."""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lumenos_sandbox.state import BunkerStateStore
from lumenos_sandbox.types import BunkerConfig, BunkerState
from lumenos_sandbox.bunker import Bunker, set_state_store, get_state_store


class TestBunkerStateStore(unittest.TestCase):
    """Tests for BunkerStateStore SQLite persistence."""

    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self.store = BunkerStateStore(self._tmp.name)

    def tearDown(self):
        self.store.close()
        os.unlink(self._tmp.name)

    def _sample_data(self, bunker_id="b1"):
        return {
            "config": {"id": bunker_id, "name": "Test", "memory_mb": 4096, "cpu_cores": 2,
                       "disk_gb": 50, "max_session_hours": 24, "decontamination_minutes": 30,
                       "snapshot_interval_minutes": 5, "enable_network_isolation": True,
                       "enable_memory_encryption": True, "enable_secure_boot": True,
                       "log_level": "VERBOSE", "guest_username": "Administrator",
                       "guest_password": "", "sysmon_installed": False, "sysmon_path": ""},
            "state": "READY",
            "vm_name": "vm_b1",
            "switch_name": "sw_b1",
            "created_at": "2026-01-01T00:00:00",
            "activated_at": None,
            "terminated_at": None,
        }

    def test_save_and_load(self):
        self.store.save("b1", self._sample_data())
        loaded = self.store.load("b1")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["state"], "READY")
        self.assertEqual(loaded["vm_name"], "vm_b1")
        self.assertEqual(loaded["config"]["id"], "b1")

    def test_load_nonexistent_returns_none(self):
        self.assertIsNone(self.store.load("nope"))

    def test_upsert_overwrites(self):
        data = self._sample_data()
        self.store.save("b1", data)
        data["state"] = "ACTIVE"
        self.store.save("b1", data)
        loaded = self.store.load("b1")
        self.assertEqual(loaded["state"], "ACTIVE")

    def test_list_all(self):
        self.store.save("a", self._sample_data("a"))
        self.store.save("b", self._sample_data("b"))
        items = self.store.list_all()
        self.assertEqual(len(items), 2)
        ids = {i["bunker_id"] for i in items}
        self.assertEqual(ids, {"a", "b"})

    def test_delete(self):
        self.store.save("b1", self._sample_data())
        self.assertTrue(self.store.delete("b1"))
        self.assertIsNone(self.store.load("b1"))

    def test_delete_nonexistent_returns_false(self):
        self.assertFalse(self.store.delete("nope"))

    def test_migrate_from_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write two JSON state files
            for bid in ("b1", "b2"):
                path = Path(tmpdir) / f"{bid}_state.json"
                path.write_text(json.dumps(self._sample_data(bid)))
            count = self.store.migrate_from_json(tmpdir)
            self.assertEqual(count, 2)
            self.assertIsNotNone(self.store.load("b1"))
            self.assertIsNotNone(self.store.load("b2"))

    def test_migrate_from_missing_dir(self):
        self.assertEqual(self.store.migrate_from_json("/nonexistent"), 0)

    def test_updated_at_set(self):
        self.store.save("b1", self._sample_data())
        loaded = self.store.load("b1")
        self.assertIsNotNone(loaded["updated_at"])
        # Should be a valid ISO timestamp
        datetime.fromisoformat(loaded["updated_at"])

    def test_delete_returns_count(self):
        self.store.save("b1", self._sample_data())
        self.assertTrue(self.store.delete("b1"))
        self.assertFalse(self.store.delete("b1"))


class TestBunkerStatePersistence(unittest.TestCase):
    """Tests that Bunker uses SQLite for state persistence."""

    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self._store = BunkerStateStore(self._tmp.name)
        set_state_store(self._store)

    def tearDown(self):
        set_state_store(None)
        self._store.close()
        os.unlink(self._tmp.name)

    @patch("lumenos_sandbox.bunker.Bunker._verify_system_requirements")
    @patch("lumenos_sandbox.bunker.Bunker._load_base_image")
    @patch("lumenos_sandbox.bunker.Bunker._allocate_resources")
    @patch("lumenos_sandbox.bunker.Bunker._initialize_integrity_baseline")
    @patch("lumenos_sandbox.bunker.Bunker._propagate_vm_credentials")
    def test_transition_persists_to_sqlite(self, *_mocks):
        config = BunkerConfig(id="persist_test", name="PT")
        bunker = Bunker(config)
        # transition_to calls _persist_state internally
        bunker.transition_to(BunkerState.INITIALIZING)
        loaded = self._store.load("persist_test")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["state"], "INITIALIZING")

    def test_load_from_store(self):
        self._store.save("restore_me", {
            "config": {"id": "restore_me", "name": "RM", "memory_mb": 8192, "cpu_cores": 4,
                       "disk_gb": 100, "max_session_hours": 24, "decontamination_minutes": 30,
                       "snapshot_interval_minutes": 5, "enable_network_isolation": True,
                       "enable_memory_encryption": True, "enable_secure_boot": True,
                       "log_level": "VERBOSE", "guest_username": "Administrator",
                       "guest_password": "", "sysmon_installed": False, "sysmon_path": ""},
            "state": "READY",
            "vm_name": "vm_restore",
            "switch_name": "sw_restore",
            "created_at": "2026-01-01T12:00:00",
            "activated_at": None,
            "terminated_at": None,
        })
        bunker = Bunker.load_from_store("restore_me")
        self.assertIsNotNone(bunker)
        self.assertEqual(bunker.state, BunkerState.READY)
        self.assertEqual(bunker._vm_name, "vm_restore")

    def test_load_from_store_nonexistent(self):
        self.assertIsNone(Bunker.load_from_store("nope"))


if __name__ == "__main__":
    unittest.main()
