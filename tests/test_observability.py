#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for observability module."""

import json
import logging
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lumenos_sandbox.observability import (
    JSONFormatter, MetricsCollector, check_health, setup_json_logging,
)
from lumenos_sandbox.state import BunkerStateStore


class TestJSONFormatter(unittest.TestCase):
    def test_formats_record(self):
        fmt = JSONFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="hello %s", args=("world",), exc_info=None,
        )
        out = fmt.format(record)
        data = json.loads(out)
        self.assertEqual(data["level"], "INFO")
        self.assertEqual(data["msg"], "hello world")
        self.assertIn("ts", data)

    def test_includes_exception(self):
        fmt = JSONFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            import sys
            exc_info = sys.exc_info()
        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname="", lineno=0,
            msg="error occurred", args=(), exc_info=exc_info,
        )
        out = fmt.format(record)
        data = json.loads(out)
        self.assertIn("exception", data)
        self.assertIn("ValueError", data["exception"])

    def test_setup_json_logging_adds_handler(self):
        handler = setup_json_logging(logging.WARNING)
        root = logging.getLogger()
        self.assertIn(handler, root.handlers)
        root.removeHandler(handler)


class TestMetricsCollector(unittest.TestCase):
    def test_inc(self):
        m = MetricsCollector()
        m.inc("req")
        m.inc("req")
        m.inc("req", 3)
        snap = m.snapshot()
        self.assertEqual(snap["counters"]["req"], 5)

    def test_set_gauge(self):
        m = MetricsCollector()
        m.set_gauge("cpu", 42.5)
        self.assertEqual(m.snapshot()["gauges"]["cpu"], 42.5)

    def test_record_time(self):
        m = MetricsCollector()
        m.record_time("deploy", 100.0)
        m.record_time("deploy", 200.0)
        timers = m.snapshot()["timers"]
        self.assertEqual(timers["deploy"]["count"], 2)
        self.assertAlmostEqual(timers["deploy"]["avg_ms"], 150.0)
        self.assertEqual(timers["deploy"]["max_ms"], 200.0)

    def test_timer_context_manager(self):
        m = MetricsCollector()
        with m.timer("fast"):
            pass
        snap = m.snapshot()
        self.assertIn("fast", snap["timers"])
        self.assertGreaterEqual(snap["timers"]["fast"]["count"], 1)

    def test_reset(self):
        m = MetricsCollector()
        m.inc("x")
        m.set_gauge("y", 1.0)
        m.reset()
        snap = m.snapshot()
        self.assertEqual(snap["counters"], {})
        self.assertEqual(snap["gauges"], {})

    def test_snapshot_isolation(self):
        m = MetricsCollector()
        m.inc("a")
        snap1 = m.snapshot()
        m.inc("b")
        snap2 = m.snapshot()
        self.assertIn("a", snap1["counters"])
        self.assertNotIn("b", snap1["counters"])
        self.assertIn("b", snap2["counters"])


class TestCheckHealth(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self.store = BunkerStateStore(self._tmp.name)

    def tearDown(self):
        self.store.close()
        os.unlink(self._tmp.name)

    def test_no_bunkers(self):
        h = check_health(self.store)
        self.assertEqual(h["status"], "ok")
        self.assertEqual(h["bunkers"], [])

    def test_healthy_bunker(self):
        self.store.save("b1", {"config": {}, "state": "READY"})
        h = check_health(self.store)
        self.assertEqual(h["status"], "ok")
        self.assertEqual(len(h["bunkers"]), 1)
        self.assertTrue(h["bunkers"][0]["healthy"])

    def test_degraded_on_error(self):
        self.store.save("b1", {"config": {}, "state": "ERROR"})
        h = check_health(self.store)
        self.assertEqual(h["status"], "degraded")
        self.assertFalse(h["bunkers"][0]["healthy"])

    def test_degraded_on_quarantine(self):
        self.store.save("b1", {"config": {}, "state": "QUARANTINE"})
        h = check_health(self.store)
        self.assertEqual(h["status"], "degraded")

    def test_filter_by_ids(self):
        self.store.save("a", {"config": {}, "state": "READY"})
        self.store.save("b", {"config": {}, "state": "ERROR"})
        h = check_health(self.store, bunker_ids=["a"])
        self.assertEqual(len(h["bunkers"]), 1)
        self.assertEqual(h["bunkers"][0]["bunker_id"], "a")


if __name__ == "__main__":
    unittest.main()
