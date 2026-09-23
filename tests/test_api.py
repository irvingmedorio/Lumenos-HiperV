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

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from lumenos_sandbox.api import (  # noqa: E402
    _BUNKER_ID_PATTERN,
    BunkerCreate,
    app,
    protected,
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
