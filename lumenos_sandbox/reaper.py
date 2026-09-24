"""Reap orphaned state-store records and the host resources they point at.

The create path is atomic now, so the remaining orphans are records abandoned
mid-lifecycle: ERROR (a dead end in the API) and, opt-in, TERMINATING /
DECONTAMINATING (a teardown that died half-way). ``lumenos-sandbox reap`` drives
this in dry-run (default) or execute mode so every destructive action is
auditable. ``updated_at`` is a naive local stamp, as elsewhere in the codebase.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .types import BunkerState

logger = logging.getLogger("LUMENOS_SANDBOX")

DEFAULT_STATES: frozenset = frozenset({BunkerState.ERROR})
DEFAULT_OLDER_THAN_HOURS = 24.0
# Refused even when requested: a live lifecycle (INITIALIZING/READY/ACTIVE), a
# forensic hold (QUARANTINE), and DESTROYED -- not an orphan, since `start`
# revives it (DESTROYED -> INITIALIZING).
NEVER_REAP_STATES: frozenset = frozenset({
    BunkerState.INITIALIZING, BunkerState.READY, BunkerState.ACTIVE,
    BunkerState.QUARANTINE, BunkerState.DESTROYED,
})


def select_states(names):
    """Resolve ``--states`` into a validated set; empty means the default.

    A never-reap state is refused rather than dropped, so the operator finds out
    the command will not do what they asked instead of getting a silent no-op.
    """
    if not names:
        return set(DEFAULT_STATES)
    requested = set()
    for raw in names:
        try:
            requested.add(BunkerState[raw.strip().upper()])
        except KeyError:
            raise ValueError(f"unknown bunker state: {raw!r}")
    forbidden = requested & NEVER_REAP_STATES
    if forbidden:
        raise ValueError("refusing states that must never be reaped: "
                         + ", ".join(sorted(s.name for s in forbidden)))
    return requested


def _age_hours(updated_at, now):
    """Age in hours, or None when the stamp is missing or unparseable."""
    if not updated_at:
        return None
    try:
        return (now - datetime.fromisoformat(updated_at)).total_seconds() / 3600.0
    except (TypeError, ValueError):
        return None


@dataclass
class ReapOutcome:
    """What the reaper did, or would do, to one record."""

    bunker_id: str
    state: str
    updated_at: str
    age_hours: float
    removed: list = field(default_factory=list)
    residual: list = field(default_factory=list)
    row_deleted: bool = False
    error: str = ""


@dataclass
class ReapReport:
    """Aggregate result of one reap pass."""

    dry_run: bool
    scanned: int = 0
    skipped_state: int = 0
    skipped_recent: int = 0
    candidates: list = field(default_factory=list)

    @property
    def residuals(self):
        return [c for c in self.candidates if c.residual]


def _step(outcome, label, action):
    """One teardown step; a raise or a False return both become a residual.

    Either way the resource was not confirmed removed, and its row is about to
    be deleted, so the residual report is its only remaining trace.
    """
    try:
        if action():
            outcome.removed.append(label)
        else:
            outcome.residual.append(f"{label} not removed")
    except Exception as exc:
        outcome.residual.append(f"{label} raised: {exc}")


def _teardown(backend, record, bunker_id, outcome):
    """Best-effort removal of the VM, the switch and the differencing disk."""
    vm, sw = record.get("vm_name"), record.get("switch_name")
    if vm:
        _step(outcome, f"remove_vm({vm})", lambda: backend.remove_vm(vm, force=True))
    if sw:
        _step(outcome, f"remove_switch({sw})", lambda: backend.remove_switch(sw))
    snapshots = Path("snapshots").resolve()
    disk = (snapshots / f"{bunker_id}_system.vhdx").resolve()
    # Confined to snapshots/, mirroring Bunker._cleanup_on_failure: a legacy
    # traversal-shaped id must never become an arbitrary-file delete.
    if disk.parent == snapshots and disk.exists():
        _step(outcome, f"delete_file({disk.name})",
              lambda: backend.delete_file(str(disk)))


def reap(store, backend, *, execute=False, states=None,
         older_than_hours=DEFAULT_OLDER_THAN_HOURS, keep_on_failure=False,
         now=None):
    """Scan the store and, when ``execute``, reap eligible records.

    Dry-run by default: with ``execute=False`` the backend is never called and
    no row removed. ``states`` is the raw selection; empty means the default.
    """
    now = now or datetime.now()
    report = ReapReport(dry_run=not execute)
    selected = select_states(states)
    for entry in store.list_all():
        report.scanned += 1
        bid, name = entry["bunker_id"], entry.get("state") or ""
        try:
            state = BunkerState[name]
        except KeyError:
            report.skipped_state += 1
            continue
        if state in NEVER_REAP_STATES or state not in selected:
            report.skipped_state += 1
            continue
        age = _age_hours(entry.get("updated_at"), now)
        if older_than_hours > 0 and (age is None or age < older_than_hours):
            report.skipped_recent += 1
            continue
        outcome = ReapOutcome(bunker_id=bid, state=name,
                              updated_at=entry.get("updated_at") or "",
                              age_hours=age if age is not None else -1.0)
        if execute:
            _teardown(backend, store.load(bid) or {}, bid, outcome)
            if outcome.residual and keep_on_failure:
                outcome.error = "row kept: cleanup left residuals (--keep-on-failure)"
            else:
                try:
                    outcome.row_deleted = bool(store.delete(bid))
                except Exception as exc:
                    outcome.error = f"could not delete row: {exc}"
        report.candidates.append(outcome)
    return report


def render_report(report):
    """Human-readable summary for stdout."""
    verb = "would reap" if report.dry_run else "reaped"
    lines = [f"reaper [{'DRY-RUN' if report.dry_run else 'EXECUTE'}]: "
             f"{report.scanned} scanned, {len(report.candidates)} candidate(s), "
             f"{report.skipped_state} skipped (state), "
             f"{report.skipped_recent} skipped (too recent)"]
    if not report.candidates:
        lines.append("No records to reap.")
        return "\n".join(lines)
    for c in report.candidates:
        lines.append(f"  - {c.bunker_id}  state={c.state}  "
                     f"age={c.age_hours:.1f}h  -> "
                     f"{verb if (report.dry_run or c.row_deleted) else 'kept'}")
        lines += [f"      cleaned: {s}" for s in c.removed]
        if c.error:
            lines.append(f"      note: {c.error}")
    return "\n".join(lines)


def render_residuals(report):
    """Residual warning for stderr; "" when clean.

    Always emitted: once the row is deleted this is the only remaining trace of
    a resource that may still be alive.
    """
    if not report.residuals:
        return ""
    lines = [f"WARNING: {len(report.residuals)} reaped record(s) left residuals:"]
    for c in report.residuals:
        lines += [f"  - {c.bunker_id}: {s}" for s in c.residual]
    return "\n".join(lines)
