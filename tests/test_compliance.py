#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for compliance module."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lumenos_sandbox.compliance import (
    Control, AuditLog, ComplianceReport, ControlStatus, DEFAULT_CONTROLS,
)


class TestControl(unittest.TestCase):
    def test_auto_timestamp(self):
        c = Control("X1", "Test", "desc")
        self.assertIn("2026", c.checked_at)

    def test_to_dict(self):
        c = Control("X1", "Test", "desc", ControlStatus.PASS, "evidence")
        d = c.to_dict()
        self.assertEqual(d["control_id"], "X1")
        self.assertEqual(d["status"], "pass")


class TestAuditLog(unittest.TestCase):
    def test_log_and_query(self):
        log = AuditLog()
        log.log("admin", "start", "bunker_1")
        log.log("admin", "stop", "bunker_1")
        log.log("user", "read", "report")
        self.assertEqual(len(log.query(actor="admin")), 2)
        self.assertEqual(len(log.query(action="stop")), 1)

    def test_to_list(self):
        log = AuditLog()
        log.log("admin", "start", "b1")
        entries = log.to_list()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["actor"], "admin")


class TestComplianceReport(unittest.TestCase):
    def test_default_controls(self):
        self.assertEqual(len(DEFAULT_CONTROLS), 10)

    def test_evaluate_all_pass(self):
        config = {
            "enable_network_isolation": True,
            "enable_process_monitoring": True,
            "enable_memory_encryption": True,
            "enable_hypervisor_monitoring": True,
        }
        report = ComplianceReport()
        result = report.evaluate(config)
        self.assertEqual(result["passed"], 10)
        self.assertEqual(result["failed"], 0)

    def test_evaluate_network_fail(self):
        config = {
            "enable_network_isolation": False,
            "enable_process_monitoring": True,
            "enable_memory_encryption": True,
            "enable_hypervisor_monitoring": True,
        }
        report = ComplianceReport()
        result = report.evaluate(config)
        self.assertEqual(result["failed"], 1)
        # Find the failed control
        failed = [c for c in result["controls"] if c["status"] == "fail"]
        self.assertEqual(failed[0]["control_id"], "SC-01")

    def test_audit_logged(self):
        report = ComplianceReport()
        report.evaluate({})
        entries = report.audit.query(action="compliance_eval")
        self.assertEqual(len(entries), 1)

    def test_pass_rate_format(self):
        report = ComplianceReport()
        result = report.evaluate({})
        self.assertIn("%", result["pass_rate"])


if __name__ == "__main__":
    unittest.main()
