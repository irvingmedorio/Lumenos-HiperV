#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""API-boundary tests: bunker-id validation and bearer-token authentication.

Two concerns live here.

**Bunker-id validation.** A bunker id is not just a label: it is propagated
into VM/switch names, host filesystem paths (``evidence/<id>``,
``snapshots/<id>_system.vhdx``) and glob patterns
(``<id>_decontamination_*.json``). These tests pin the charset guard that stops
traversal and glob injection at the API boundary. They are also the regression
proof for the unvalidated-id finding: with the guard absent, ``id="*"``
returned 201 and created a real VM/switch/disk, and a traversal-shaped id wrote
a disk outside ``snapshots/``.

**Authentication.** Every endpoint except POST /analyze-sync and GET /health
requires a bearer token (``LUMENOS_API_TOKEN``) through a router-level
dependency. POST /analyze-sync authenticates inside its own handler, so its
401/403/503 coverage lives in test_inspect.py; GET /health is deliberately
unauthenticated for liveness probes.

Backend note: ``tests/conftest.py`` forces ``MockBackend`` (autouse) unless
``LUMENOS_HYPERVISOR`` is set, so nothing here touches live VMs.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from lumenos_sandbox.api import (  # noqa: E402
    _BUNKER_ID_PATTERN,
    BunkerCreate,
    app,
    protected,
)
from lumenos_sandbox.bunker import Bunker, get_state_store  # noqa: E402
from lumenos_sandbox.hypervisor.mock_backend import MockBackend  # noqa: E402
from lumenos_sandbox.types import BunkerConfig  # noqa: E402

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

TEST_TOKEN = "test-token"

# The eleven endpoints on the protected router. Two endpoints are deliberately
# NOT here: POST /analyze-sync authenticates inside its own handler (via
# _authorize_and_resolve), and GET /health stays open for liveness probes.
#
# Paths are kept templated so they can be compared against the router's own
# route table; PROTECTED_ROUTES below substitutes the sample id to actually
# call them.
SAMPLE_BUNKER_ID = "dl"

PROTECTED_ROUTE_TEMPLATES = [
    ("GET", "/bunkers", None),
    ("POST", "/bunkers", {"id": SAMPLE_BUNKER_ID, "name": "n", "memory_mb": 512,
                          "cpu_cores": 1, "disk_gb": 10}),
    ("GET", "/bunkers/{bunker_id}", None),
    ("POST", "/bunkers/{bunker_id}/start", None),
    ("POST", "/bunkers/{bunker_id}/stop", None),
    ("POST", "/bunkers/{bunker_id}/activate", None),
    ("GET", "/bunkers/{bunker_id}/metrics", None),
    ("POST", "/bunkers/{bunker_id}/analyze", {"sample_path": "x"}),
    ("GET", "/bunkers/{bunker_id}/report", None),
    ("GET", "/evidence/{bunker_id}", None),
    ("GET", "/compliance", None),
]

PROTECTED_ROUTES = [
    (method, path.replace("{bunker_id}", SAMPLE_BUNKER_ID), body)
    for method, path, body in PROTECTED_ROUTE_TEMPLATES
]

_ROUTE_IDS = [f"{method} {path}" for method, path, _ in PROTECTED_ROUTE_TEMPLATES]


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
def client(monkeypatch):
    """Authenticated client for the protected routes.

    Every endpoint except POST /analyze-sync requires the bearer token, so the
    id-validation tests below must authenticate. The token is set through
    monkeypatch, so it is reverted automatically after each test.
    """
    monkeypatch.setenv("LUMENOS_API_TOKEN", TEST_TOKEN)
    with TestClient(app) as c:
        c.headers["Authorization"] = f"Bearer {TEST_TOKEN}"
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

# An id the pre-guard code accepted and persisted, but the charset rejects.
# URL-safe on purpose, so the test exercises resolution and not URL encoding.
LEGACY_ID = "_legacy_bunker"


class TestBunkerIdPathParamGuard:
    """The charset is enforced at the path sink, not at resolution.

    Resolving a dirty id must stay possible, because a legacy record has to
    remain manageable; a dirty id that matches no record is therefore simply
    not found. Only the route that turns the id into a filesystem path refuses
    it outright.
    """

    @pytest.mark.parametrize("bad", DIRTY_PATH_IDS)
    def test_dirty_ids_do_not_resolve(self, client, bad):
        for route in (f"/bunkers/{bad}", f"/bunkers/{bad}/report",
                      f"/bunkers/{bad}/metrics"):
            r = client.get(route)
            assert r.status_code == 404, f"{route} -> {r.status_code}"

    @pytest.mark.parametrize("bad", DIRTY_PATH_IDS)
    def test_state_changing_routes_do_not_resolve_dirty_ids(self, client, bad):
        r = client.post(f"/bunkers/{bad}/stop")
        assert r.status_code == 404, f"/bunkers/{bad}/stop -> {r.status_code}"

    @pytest.mark.parametrize("bad", DIRTY_PATH_IDS)
    def test_evidence_route_refuses_dirty_ids(self, client, bad):
        r = client.get(f"/evidence/{bad}")
        assert r.status_code == 400, f"/evidence/{bad} -> {r.status_code}"

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

    def test_persisted_legacy_id_stays_manageable(self, client):
        """Regression for R4-legacy-id-lockout.

        A record written before the charset guard existed must still resolve.
        Refusing it would strand its VM, switch and disk with no way to stop,
        decontaminate or decommission them — the lockout the review found.
        """
        assert not re.fullmatch(_BUNKER_ID_PATTERN, LEGACY_ID)

        get_state_store().save(LEGACY_ID, {
            "config": {"id": LEGACY_ID, "name": "legacy"},
            "state": "ACTIVE",
            "vm_name": "bunker_legacy",
            "switch_name": "lumenos_legacy_switch",
        })

        # Resolution and the lifecycle routes keep working...
        assert client.get(f"/bunkers/{LEGACY_ID}").status_code == 200
        assert client.get(f"/bunkers/{LEGACY_ID}/metrics").status_code == 200

        # The stop route resolves the record and starts the lifecycle
        # transition. Whether termination runs to completion is a pre-existing
        # property of the restore path, not what this finding is about: what
        # matters is that the id is no longer refused with a lockout.
        assert client.post(f"/bunkers/{LEGACY_ID}/stop").status_code != 400

        # ...while the path-turning route still refuses it.
        assert client.get(f"/evidence/{LEGACY_ID}").status_code == 400


# ---------------------------------------------------------------------------
# Authentication on the eleven protected routes
# ---------------------------------------------------------------------------

class TestProtectedRouteAuth:
    """The eleven protected endpoints require the bearer token.

    Two endpoints are excluded on purpose and are not on the protected router:

    - POST /analyze-sync authenticates inside its own handler
      (``_authorize_and_resolve``); its 401/403/503 tests live in test_inspect.py.
    - GET /health is unauthenticated so liveness probes work without
      credentials; see ``test_health_is_open_without_auth``.
    """

    @pytest.mark.parametrize("method,path,body", PROTECTED_ROUTES, ids=_ROUTE_IDS)
    def test_missing_token_is_401(self, client, method, path, body):
        r = client.request(method, path, json=body,
                           headers={"Authorization": ""})
        assert r.status_code == 401, f"{method} {path} -> {r.status_code}"

    @pytest.mark.parametrize("method,path,body", PROTECTED_ROUTES, ids=_ROUTE_IDS)
    def test_wrong_token_is_401(self, client, method, path, body):
        r = client.request(method, path, json=body,
                           headers={"Authorization": "Bearer wrong"})
        assert r.status_code == 401, f"{method} {path} -> {r.status_code}"

    def test_unconfigured_token_fails_closed_with_503(self, client, monkeypatch):
        """Fail-closed: an unconfigured token must refuse, never fall open."""
        monkeypatch.delenv("LUMENOS_API_TOKEN", raising=False)
        r = client.get("/bunkers")
        assert r.status_code == 503
        assert "not configured" in r.json()["detail"]

    def test_unconfigured_token_fails_closed_on_a_state_changing_route(
            self, client, monkeypatch):
        monkeypatch.delenv("LUMENOS_API_TOKEN", raising=False)
        r = client.post("/bunkers/dl/stop")
        assert r.status_code == 503

    def test_valid_token_reaches_the_handler(self, client):
        r = client.get("/bunkers")
        assert r.status_code == 200
        assert r.json() == []

    def test_valid_token_creates_a_bunker_with_the_mock_backend(self, client):
        r = client.post("/bunkers", json=_payload("auth_ok"))
        assert r.status_code == 201, r.text
        assert r.json()["ok"] is True

    def test_health_is_open_without_auth(self, client, monkeypatch):
        """Liveness probes must reach /health with no credentials — and it must
        keep answering even when the token is not configured at all."""
        assert client.get(
            "/health", headers={"Authorization": ""}
        ).status_code == 200

        monkeypatch.delenv("LUMENOS_API_TOKEN", raising=False)
        r = client.get("/health", headers={"Authorization": ""})
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    # --- structural guards: these fail if a future route skips the guard ----

    def test_router_covers_exactly_the_eleven_protected_endpoints(self):
        actual = {(m, r.path) for r in protected.routes for m in r.methods}
        expected = {(method, path) for method, path, _ in PROTECTED_ROUTE_TEMPLATES}
        assert actual == expected

    def test_no_route_escapes_the_auth_guard(self):
        """A route added to ``app`` instead of ``protected`` would slip past the
        token check. The OpenAPI document is the authoritative inventory of
        published endpoints, so it catches that mistake.

        Every documented endpoint must be either on the protected router or on
        the explicit unauthenticated allowlist below.
        """
        documented = {
            (method.upper(), path)
            for path, operations in app.openapi()["paths"].items()
            for method in operations
        }
        guarded = {(m, r.path) for r in protected.routes for m in r.methods}
        deliberately_unauthenticated = {
            ("POST", "/analyze-sync"),   # authenticates inside its handler
            ("GET", "/health"),          # open for liveness probes
        }

        assert documented - guarded - deliberately_unauthenticated == set()

    def test_analyze_sync_authenticates_itself_not_via_the_router(self, client):
        assert not any(r.path == "/analyze-sync" for r in protected.routes)
        r = client.post("/analyze-sync", json={"sample_path": "/tmp/x"},
                        headers={"Authorization": "Bearer wrong"})
        assert r.status_code == 401

    def test_router_path_delegates_to_the_shared_verifier(self, client, monkeypatch):
        """Anti-regression for the auth debt: the router dependency must call
        ``_require_bearer_token`` instead of re-inlining the token check."""
        import lumenos_sandbox.api as api_mod

        calls = []
        real = api_mod._require_bearer_token

        def spy(authorization):
            calls.append(authorization)
            return real(authorization)

        monkeypatch.setattr(api_mod, "_require_bearer_token", spy)
        r = client.get("/bunkers")
        assert r.status_code == 200
        assert calls == [f"Bearer {TEST_TOKEN}"]


# ---------------------------------------------------------------------------
# Atomic create — a failed initialize() must leave nothing behind
# ---------------------------------------------------------------------------

class _RecordingBackend(MockBackend):
    """MockBackend that records the teardown calls it receives."""

    def __init__(self):
        super().__init__()
        self.calls = []

    def remove_vm(self, vm_name, force=True):
        self.calls.append(("remove_vm", vm_name))
        return True

    def remove_switch(self, switch_name):
        self.calls.append(("remove_switch", switch_name))
        return True

    def delete_file(self, path):
        self.calls.append(("delete_file", path))
        try:
            Path(path).unlink(missing_ok=True)
        except OSError:
            pass
        return True


class TestCreateBunkerAtomicity:
    """POST /bunkers is atomic (follow-up #2).

    ``Bunker.initialize()`` persists INITIALIZING and then ERROR through
    ``transition_to`` -> ``_persist_state``, so before the fix a failed create
    returned 500 and left an orphan ``ERROR`` row behind. These tests pin the
    rollback: no store row, no leaked host resources, and the id free for a
    retry. The backend is the autouse MockBackend from conftest, patched per
    test so nothing touches a live hypervisor.
    """

    def test_failed_create_leaves_no_store_row(self, client, monkeypatch):
        monkeypatch.setattr(
            "lumenos_sandbox.hypervisor.mock_backend.MockBackend.check_available",
            lambda self: False,
        )
        r = client.post("/bunkers", json=_payload("atomic_early"))
        assert r.status_code == 500, r.text
        assert get_state_store().list_all() == []

    def test_failed_create_leaves_no_registry_entry(self, client, monkeypatch):
        import lumenos_sandbox.api as api_mod

        monkeypatch.setattr(
            "lumenos_sandbox.hypervisor.mock_backend.MockBackend.check_available",
            lambda self: False,
        )
        client.post("/bunkers", json=_payload("atomic_registry"))
        assert "atomic_registry" not in api_mod._bunkers

    def test_failed_create_frees_the_id_for_retry(self, client, monkeypatch):
        """The proof the row is really gone: the same id must be creatable
        again instead of coming back as a 409 on a phantom record."""
        available = {"ok": False}
        monkeypatch.setattr(
            "lumenos_sandbox.hypervisor.mock_backend.MockBackend.check_available",
            lambda self: available["ok"],
        )

        assert client.post(
            "/bunkers", json=_payload("atomic_retry")
        ).status_code == 500
        assert get_state_store().list_all() == []

        available["ok"] = True
        r = client.post("/bunkers", json=_payload("atomic_retry"))
        assert r.status_code == 201, r.text
        assert r.json()["data"]["config"]["id"] == "atomic_retry"

    def test_failed_create_removes_vm_and_switch(self, client, monkeypatch):
        """A failure *after* resources were allocated must still tear them
        down (that part is Bunker._cleanup_on_failure)."""
        calls = []

        def _boom(self, vm_name):
            raise RuntimeError("guest integration failed")

        monkeypatch.setattr(
            "lumenos_sandbox.hypervisor.mock_backend.MockBackend.enable_guest_integration",
            _boom,
        )
        monkeypatch.setattr(
            "lumenos_sandbox.hypervisor.mock_backend.MockBackend.remove_vm",
            lambda self, vm, force=True: calls.append(("remove_vm", vm)) or True,
        )
        monkeypatch.setattr(
            "lumenos_sandbox.hypervisor.mock_backend.MockBackend.remove_switch",
            lambda self, sw: calls.append(("remove_switch", sw)) or True,
        )

        r = client.post("/bunkers", json=_payload("atomic_late"))
        assert r.status_code == 500, r.text
        assert get_state_store().list_all() == []
        assert ("remove_vm", "bunker_atomic_late") in calls
        assert ("remove_switch", "lumenos_atomic_late_switch") in calls


class TestCleanupOnFailureRemovesDisk:
    """The differencing disk is a host resource that VM removal does not cover
    on Hyper-V (``Remove-VM`` detaches the VHD but leaves the file). The
    cleanup must delete it explicitly, and must never escape ``snapshots/``.
    """

    def test_removes_the_differencing_disk(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "snapshots").mkdir()
        disk = tmp_path / "snapshots" / "atomic_disk_system.vhdx"
        disk.write_bytes(b"vhdx")

        backend = _RecordingBackend()
        bunker = Bunker(BunkerConfig(id="atomic_disk", name="n"), backend=backend)
        bunker._cleanup_on_failure()

        assert not disk.exists()
        assert any(
            call[0] == "delete_file" and Path(call[1]).name == disk.name
            for call in backend.calls
        )

    def test_never_deletes_outside_the_snapshots_dir(self, tmp_path, monkeypatch):
        """A legacy traversal-shaped id must not turn the cleanup into an
        arbitrary-file delete."""
        monkeypatch.chdir(tmp_path)
        outside = tmp_path / "outside_system.vhdx"
        outside.write_bytes(b"important")

        backend = _RecordingBackend()
        bunker = Bunker(BunkerConfig(id="../outside", name="n"), backend=backend)
        bunker._cleanup_on_failure()

        assert outside.exists(), "cleanup escaped the snapshots directory"
        assert not any(call[0] == "delete_file" for call in backend.calls)
