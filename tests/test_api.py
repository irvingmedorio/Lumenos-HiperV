#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""API-boundary validation for ``BunkerCreate.id`` (and its path-param guard).

A bunker id is not just a label: it is propagated into VM/switch names, host
filesystem paths (``evidence/<id>``, ``snapshots/<id>_system.vhdx``) and glob
patterns (``<id>_decontamination_*.json``). These tests pin the charset guard
that stops traversal and glob injection at the API boundary.

They are also the regression proof for the unvalidated-id finding: with the
guard absent, ``id="*"`` returned 201 and created a real VM/switch/disk, and a
traversal-shaped id wrote a disk outside ``snapshots/``.

Backend note: ``tests/conftest.py`` forces ``MockBackend`` (autouse) unless
``LUMENOS_HYPERVISOR`` is set, so nothing here touches live VMs.
"""

from __future__ import annotations

import re

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from lumenos_sandbox.api import (  # noqa: E402
    _BUNKER_ID_PATTERN,
    BunkerCreate,
    app,
)
from lumenos_sandbox.bunker import get_state_store  # noqa: E402

# Vectors that must never reach a VM name, a path component or a glob.
TRAVERSAL_AND_INJECTION_VECTORS = [
    "*",                 # glob metachar: matched every decontamination report
    "?",
    "[a]",
    "a*b",
    "../../etc/pwned",   # POSIX traversal
    "a/b",
    "..\\..\\windows",   # Windows traversal
    "..",
    ".",
    ".hidden",
    "",
    "a" * 65,            # over the length bound
    "_leading",
    "a b",
    "a;b",
]

LEGITIMATE_IDS = [
    "dl",
    "test_1",
    "custom_1",
    "escape_test",
    "inspect-abc123",    # the shape inspect.py generates
    "lumenos_prod",
    "x",
    "123",
    "a" * 64,            # exactly at the bound
]


def _payload(bunker_id: str) -> dict:
    return {
        "id": bunker_id,
        "name": "n",
        "memory_mb": 512,
        "cpu_cores": 1,
        "disk_gb": 10,
    }


@pytest.fixture(autouse=True)
def _isolate_registry():
    """``_bunkers`` is a module-level dict that conftest does not reset.

    Snapshot and restore it so accepted creates here never leak entries into
    the rest of the suite.
    """
    import lumenos_sandbox.api as api_mod

    saved = dict(api_mod._bunkers)
    yield
    api_mod._bunkers.clear()
    api_mod._bunkers.update(saved)


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# POST /bunkers — the create boundary
# ---------------------------------------------------------------------------

class TestBunkerIdValidation:

    @pytest.mark.parametrize("bad_id", TRAVERSAL_AND_INJECTION_VECTORS)
    def test_rejects_traversal_and_injection_vectors(self, client, bad_id):
        r = client.post("/bunkers", json=_payload(bad_id))
        assert r.status_code == 422, (
            f"{bad_id!r} was accepted by the API boundary: {r.status_code}"
        )

    def test_rejected_create_persists_nothing(self, client):
        """A refused id must not leave a record behind (the pre-fix traversal
        id was persisted with state ERROR even though the endpoint 500'd)."""
        client.post("/bunkers", json=_payload("*"))
        client.post("/bunkers", json=_payload("../../etc/pwned"))
        assert get_state_store().list_all() == []

    @pytest.mark.parametrize("good_id", LEGITIMATE_IDS)
    def test_accepts_legitimate_ids(self, client, good_id):
        r = client.post("/bunkers", json=_payload(good_id))
        assert r.status_code == 201, r.text
        assert r.json()["data"]["config"]["id"] == good_id

    def test_create_and_model_share_one_charset(self):
        """The model constraint must reference the same constant ``_get_bunker``
        enforces, so the two guard sites cannot drift apart."""
        metadata = BunkerCreate.model_fields["id"].metadata
        patterns = [getattr(m, "pattern", None) for m in metadata]
        assert _BUNKER_ID_PATTERN in patterns, (
            f"BunkerCreate.id no longer uses _BUNKER_ID_PATTERN: {patterns}"
        )
        assert re.fullmatch(_BUNKER_ID_PATTERN, "dl")
        assert not re.fullmatch(_BUNKER_ID_PATTERN, "*")


# ---------------------------------------------------------------------------
# Path-param guard — ids that reached the handler (old records, %5C, glob')
# ---------------------------------------------------------------------------

# ``%2e`` is used for the dotted ids because httpx normalises literal ``..``
# dot-segments out of a URL before sending it.
DIRTY_PATH_IDS = ["*", "%2e%2e", "..%5C..%5Cetc", "a" * 65]


class TestBunkerIdPathParamGuard:

    @pytest.mark.parametrize("bad", DIRTY_PATH_IDS)
    def test_read_routes_reject_dirty_path_params(self, client, bad):
        for route in (f"/bunkers/{bad}", f"/bunkers/{bad}/report",
                      f"/bunkers/{bad}/metrics"):
            r = client.get(route)
            assert r.status_code == 400, f"{route} -> {r.status_code}"

    @pytest.mark.parametrize("bad", DIRTY_PATH_IDS)
    def test_state_changing_routes_reject_dirty_path_params(self, client, bad):
        r = client.post(f"/bunkers/{bad}/stop")
        assert r.status_code == 400, f"/bunkers/{bad}/stop -> {r.status_code}"

    def test_evidence_route_never_reaches_forensics(self, client, monkeypatch):
        """The glob-injection vector: ``id='*'`` must be refused *before*
        ``collect_evidence`` can glob every decontamination report."""
        import lumenos_sandbox.api as api_mod

        called = []
        monkeypatch.setattr(
            api_mod, "collect_evidence",
            lambda *a, **k: called.append(a) or {},
        )

        r = client.get("/evidence/*")

        assert r.status_code == 400, r.text
        assert called == [], "collect_evidence was reached with a dirty id"
