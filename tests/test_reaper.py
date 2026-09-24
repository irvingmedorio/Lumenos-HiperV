#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the state-store reaper (follow-up #5).

The reaper deletes bookkeeping rows, so the contract is "leave nothing
ambiguous": a dry-run must be inert, an execute must clean the backend AND the
store, and anything not confirmed removed must be reported instead of vanishing
with its row.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta

import pytest

from lumenos_sandbox.bunker import get_state_store
from lumenos_sandbox.reaper import (
    DEFAULT_STATES,
    NEVER_REAP_STATES,
    reap,
    render_report,
    render_residuals,
    select_states,
)
from lumenos_sandbox.types import BunkerState

_TEARDOWNS = ("remove_vm", "remove_switch", "delete_file")


class _FakeBackend:
    """Records teardown calls; fails softly (False) or hard (raise)."""

    def __init__(self, soft=False, raises=()):
        self.calls, self.soft, self.raises = [], soft, set(raises)

    def __getattr__(self, name):
        if name not in _TEARDOWNS:
            raise AttributeError(name)

        def call(*a, **kw):
            self.calls.append((name, *a))
            if name in self.raises:
                raise RuntimeError("backend unavailable")
            return not self.soft

        return call


def _future(hours=100.0):
    """A clock far enough ahead that freshly written records look stale."""
    return datetime.now() + timedelta(hours=hours)


def _seed(bunker_id, state, vm=None, switch=None):
    get_state_store().save(bunker_id, {
        "config": {"id": bunker_id, "name": bunker_id},
        "state": state, "vm_name": vm, "switch_name": switch,
    })


def _args(**over):
    base = dict(states="", older_than_hours=24.0, execute=False,
                keep_on_failure=False)
    base.update(over)
    return argparse.Namespace(**base)


def test_dry_run_is_inert():
    _seed("reap_dry", "ERROR", "bunker_reap_dry", "lumenos_reap_dry_switch")
    backend = _FakeBackend()
    report = reap(get_state_store(), backend, execute=False, now=_future())
    assert backend.calls == []
    assert get_state_store().load("reap_dry") is not None
    assert report.candidates[0].row_deleted is False
    assert "would reap" in render_report(report)


def test_execute_cleans_backend_and_deletes_row(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "snapshots").mkdir()
    (tmp_path / "snapshots" / "reap_exec_system.vhdx").write_bytes(b"vhdx")
    _seed("reap_exec", "ERROR", "bunker_reap_exec", "lumenos_reap_exec_switch")
    backend = _FakeBackend()
    report = reap(get_state_store(), backend, execute=True, now=_future())
    assert ("remove_vm", "bunker_reap_exec") in backend.calls
    assert ("remove_switch", "lumenos_reap_exec_switch") in backend.calls
    assert any(c[0] == "delete_file" for c in backend.calls)
    assert report.candidates[0].row_deleted is True
    assert get_state_store().load("reap_exec") is None
    assert report.residuals == []


def test_backend_raise_deletes_row_and_reports_residual(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _seed("reap_fail", "ERROR", "bunker_reap_fail", "lumenos_reap_fail_switch")
    backend = _FakeBackend(raises=("remove_vm", "remove_switch"))
    report = reap(get_state_store(), backend, execute=True, now=_future())
    assert get_state_store().load("reap_fail") is None
    assert len(report.candidates[0].residual) == 2
    warning = render_residuals(report)
    assert "bunker_reap_fail" in warning and "WARNING" in warning


def test_soft_failure_is_reported_but_still_clears_the_row(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _seed("reap_gone", "ERROR", "bunker_reap_gone")
    report = reap(get_state_store(), _FakeBackend(soft=True),
                  execute=True, now=_future())
    assert report.candidates[0].row_deleted is True
    assert get_state_store().load("reap_gone") is None
    assert report.residuals, "an unconfirmed removal must be reported"


def test_keep_on_failure_leaves_the_row_for_a_retry(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _seed("reap_keep", "ERROR", "bunker_reap_keep")
    report = reap(get_state_store(), _FakeBackend(raises=("remove_vm",)),
                  execute=True, keep_on_failure=True, now=_future())
    assert report.candidates[0].row_deleted is False
    assert get_state_store().load("reap_keep") is not None
    assert "kept" in report.candidates[0].error


@pytest.mark.parametrize("state", sorted(s.name for s in NEVER_REAP_STATES))
def test_never_reap_states_are_refused(state):
    with pytest.raises(ValueError):
        select_states([state])


def test_live_records_are_never_selected(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for s in ("INITIALIZING", "READY", "ACTIVE", "QUARANTINE", "DESTROYED"):
        _seed(f"keep_{s.lower()}", s, f"bunker_keep_{s.lower()}")
    backend = _FakeBackend()
    report = reap(get_state_store(), backend, execute=True, now=_future())
    assert report.candidates == [] and backend.calls == []


def test_default_is_error_only_and_terminating_is_opt_in():
    assert select_states(None) == set(DEFAULT_STATES) == {BunkerState.ERROR}
    assert select_states(["TERMINATING"]) == {BunkerState.TERMINATING}


def test_recent_error_is_not_reaped(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _seed("reap_recent", "ERROR", "bunker_reap_recent")
    backend = _FakeBackend()
    report = reap(get_state_store(), backend, execute=True, now=datetime.now())
    assert report.candidates == [] and backend.calls == []
    assert get_state_store().load("reap_recent") is not None


def test_traversal_id_never_deletes_outside_snapshots(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    outside = tmp_path / "outside_system.vhdx"
    outside.write_bytes(b"important")
    _seed("../outside", "ERROR")
    backend = _FakeBackend()
    report = reap(get_state_store(), backend, execute=True, now=_future())
    assert outside.exists(), "reaper escaped the snapshots directory"
    assert not any(c[0] == "delete_file" for c in backend.calls)
    assert report.candidates[0].row_deleted is True


def test_cmd_reap_on_empty_store_exits_zero(capsys):
    from lumenos_sandbox.cli import cmd_reap
    assert cmd_reap(_args()) == 0
    assert "no records to reap" in capsys.readouterr().out.lower()


def test_cmd_reap_rejects_a_never_reap_state(capsys):
    from lumenos_sandbox.cli import cmd_reap
    assert cmd_reap(_args(states="ACTIVE")) == 1
    assert "never be reaped" in capsys.readouterr().err


def test_cmd_reap_reports_residuals_on_stderr(capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _seed("reap_cli", "ERROR", "bunker_reap_cli")
    monkeypatch.setattr("lumenos_sandbox.hypervisor.get_backend",
                        lambda: _FakeBackend(raises=("remove_vm",)))
    from lumenos_sandbox.cli import cmd_reap
    assert cmd_reap(_args(execute=True, older_than_hours=0)) == 0
    captured = capsys.readouterr()
    assert "reaped" in captured.out
    assert "bunker_reap_cli" in captured.err
