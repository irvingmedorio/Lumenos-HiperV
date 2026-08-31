#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Observability: structured logging, metrics, and health checks."""

import json
import logging
import time
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Structured JSON Log Formatter
# ---------------------------------------------------------------------------

class JSONFormatter(logging.Formatter):
    """Emit log records as single-line JSON for aggregation pipelines."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def setup_json_logging(level: int = logging.INFO) -> logging.Handler:
    """Configure root logger with JSON output. Returns the handler for cleanup."""
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(level)
    return handler


# ---------------------------------------------------------------------------
# Metrics Collector
# ---------------------------------------------------------------------------

class MetricsCollector:
    """Thread-safe in-process metrics counter.

    Stores counters and gauges in a dict. No external dependencies.
    Call `snapshot()` to get a point-in-time read.
    """

    def __init__(self):
        self._counters: Dict[str, int] = {}
        self._gauges: Dict[str, float] = {}
        self._timers: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def inc(self, name: str, value: int = 1) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + value

    def set_gauge(self, name: str, value: float) -> None:
        with self._lock:
            self._gauges[name] = value

    def record_time(self, name: str, elapsed_ms: float) -> None:
        with self._lock:
            self._timers.setdefault(name, []).append(elapsed_ms)

    def timer(self, name: str):
        """Context manager that records elapsed time."""
        return _TimerCtx(self, name)

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            timers_summary = {}
            for name, samples in self._timers.items():
                timers_summary[name] = {
                    "count": len(samples),
                    "avg_ms": sum(samples) / len(samples) if samples else 0,
                    "max_ms": max(samples) if samples else 0,
                }
            return {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "timers": timers_summary,
            }

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._timers.clear()


class _TimerCtx:
    """Context manager for MetricsCollector.timer()."""

    def __init__(self, collector: MetricsCollector, name: str):
        self._collector = collector
        self._name = name
        self._start: float = 0

    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *_):
        elapsed = (time.perf_counter() - self._start) * 1000
        self._collector.record_time(self._name, elapsed)


# ---------------------------------------------------------------------------
# Health Check
# ---------------------------------------------------------------------------

def check_health(store=None, bunker_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    """Aggregate health status.

    Args:
        store: BunkerStateStore instance (optional).
        bunker_ids: specific bunkers to check (None = all).

    Returns:
        {"status": "ok"|"degraded"|"error", "bunkers": [...], "timestamp": ...}
    """
    result: Dict[str, Any] = {
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "bunkers": [],
    }

    if store is None:
        return result

    rows = store.list_all() if bunker_ids is None else [
        store.load(bid) for bid in bunker_ids
    ]

    for row in rows:
        if row is None:
            continue
        bid = row.get("bunker_id", "unknown")
        state = row.get("state", "UNKNOWN")
        info = {"bunker_id": bid, "state": state}

        # Flag non-terminal unhealthy states
        if state in ("ERROR", "QUARANTINE"):
            info["healthy"] = False
            result["status"] = "degraded"
        else:
            info["healthy"] = True

        result["bunkers"].append(info)

    return result
