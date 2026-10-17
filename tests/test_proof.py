"""/proof/run logic, proven with fake Entra tokens before the tenant exists.

run_proof makes real HTTP requests (httpx) — here against the ASGI app via TestClient,
in production against the running server on 127.0.0.1.
"""

import json

import pytest

from app import auth, proof, rbac
from app.config import EXPECTED_ROLE
from app.data import ROWS
from app.main import create_app
from conftest import ORIGIN, UPNS, local_client, make_settings, token_for

EXPECTED_GRID = {
    # action id: (alice/Support.Agent, bob/Finance.Analyst, carol/Tenant.Admin), True = allowed
    "me":                    (True, True, True),
    "read:kb_public":        (True, True, True),
    "read:support_tickets":  (True, False, True),
    "read:finance_revenue":  (False, True, True),
    "read:audit_log":        (False, False, True),
    "ask:kb_public":         (True, True, True),
    "ask:support_tickets":   (True, False, True),
    "ask:finance_revenue":   (False, True, True),
    "ask:audit_log":         (False, False, True),
    "inject":                (True, True, True),
    "admin":                 (False, False, True),
}
USERS = ("alice", "bob", "carol")
CELLS = len(EXPECTED_GRID) * len(USERS)  # 33
NEGATIVES = 9
NEEDS_TOKEN = 7  # negatives that are built from a signed-in user's token


def run(settings, provider=None):
    tokens = {k: token_for(k) for k in USERS}
    provider = provider or (lambda k: (tokens[k], None))
    with local_client(create_app(settings, token_provider=provider)) as c:
        return proof.run_proof(settings, c, provider, "testclient", c.app.state.started_at), tokens


@pytest.fixture
def ai_on(settings, claude):
    return settings


def test_full_grid_passes_and_matches_contract(ai_on):
    result, tokens = run(ai_on)
    assert [a["id"] for a in result["actions"]] == list(EXPECTED_GRID)
    for action, expected in EXPECTED_GRID.items():
        for user, exp in zip(USERS, expected):
            cell = result["cells"][action][user]
            assert cell["expected_allow"] is exp, (action, user)
            assert cell["allowed"] is exp, (action, user, cell)
            assert cell["status"] == (200 if exp else 403), (action, user, cell)
            assert cell["passed"] is True, (action, user, cell)
            assert cell["leaks"] == []
    assert all(n["passed"] for n in result["negatives"])
    assert len(result["negatives"]) == NEGATIVES
    s = result["summary"]
    assert s == {"passed": 42, "total": 42, "skipped": 0, "ai_not_configured": 0,
                 "verdict": "PASS", "missing_users": []}
    assert result["cells"]["inject"]["alice"]["note"] == (
        "server reports 5 rows from ['kb_public']; no forbidden canary in response")
    blob = json.dumps(result)
    for t in tokens.values():
        assert t not in blob and t.split(".")[2] not in blob


def test_ai_not_configured_marked_separately(settings):
    result, _ = run(settings)  # no Claude stub, no key -> 503 on allowed asks
    s = result["summary"]
    assert s["passed"] == s["total"] == 42
    # alice: kb, tickets, inject; bob: kb, finance, inject; carol: 4 asks + inject
    assert s["ai_not_configured"] == 3 + 3 + 5
    cell = result["cells"]["ask:kb_public"]["alice"]
    assert cell["status"] == 503 and cell["ai"] == "not configured" and cell["passed"]
    assert result["cells"]["ask:finance_revenue"]["alice"]["status"] == 403


def test_signed_out_user_is_skipped_not_passed(ai_on):
    tokens = {k: token_for(k) for k in ("alice", "carol")}
    result, _ = run(ai_on, lambda k: (tokens.get(k), None if k in tokens else "not signed in"))
    assert all(result["cells"][a]["bob"].get("skipped") for a in EXPECTED_GRID)
    assert result["summary"]["skipped"] == len(EXPECTED_GRID)
    assert result["summary"]["passed"] == result["summary"]["total"] == 2 * 11 + NEGATIVES
    assert result["summary"]["verdict"] == "INCOMPLETE"
    assert result["summary"]["missing_users"] == [UPNS["bob"]]


def test_no_users_signed_in(ai_on):
    result, _ = run(ai_on, lambda k: (None, "not signed in"))
    s = result["summary"]
    assert s["total"] == 2 and s["passed"] == 2  # the two no-token checks
    assert s["skipped"] == CELLS + NEEDS_TOKEN
    assert s["verdict"] == "INCOMPLETE"  # never PASS with nobody signed in
    assert s["missing_users"] == [UPNS[k] for k in USERS]


def _page(settings, result) -> str:
    proof.write_result(settings.proof_output, result)
    with local_client(create_app(settings, token_provider=lambda k: (None, "not signed in"))) as c:
        return c.get("/proof").text


def test_page_is_amber_incomplete_not_green_when_users_missing(ai_on):
    """Reviewer's case: 2/2 with nobody signed in used to render green."""
    html = _page(ai_on, run(ai_on, lambda k: (None, "not signed in"))[0])
    assert 'class="summary warn">INCOMPLETE · 2/2 checks passed' in html
    assert "summary good" not in html
    assert "Not run for: " + ", ".join(UPNS[k] for k in USERS) in html


def test_page_is_red_on_any_failure_even_if_users_missing(ai_on):
    result, _ = run(ai_on, lambda k: (None, "not signed in"))
    result["negatives"][0]["passed"] = False
    result["summary"]["verdict"] = "FAIL"
    html = _page(ai_on, result)
    assert 'class="summary bad">FAIL' in html


def test_page_never_green_for_a_result_without_verdict(ai_on):
    result, _ = run(ai_on)
    del result["summary"]["verdict"]  # a latest.json written before verdicts existed
    html = _page(ai_on, result)
    assert 'class="summary warn">INCOMPLETE' in html and "summary good" not in html


def test_proof_detects_a_broken_server(ai_on, monkeypatch):
    """If RBAC were wrong, the proof must say FAIL and flag the leak."""
    broken = dict(rbac.ROLE_PERMISSIONS)
    broken["Support.Agent"] = broken["Support.Agent"] | {"read:finance_revenue"}
    monkeypatch.setattr(rbac, "ROLE_PERMISSIONS", broken)
    result, _ = run(ai_on)
    cell = result["cells"]["read:finance_revenue"]["alice"]
    assert cell["passed"] is False and cell["allowed"] is True
    fin_rows = {m for r in ROWS if r["collection"] == "finance_revenue" for m in proof._row_markers(r)}
    assert cell["leaks"] and set(cell["leaks"]) <= fin_rows
    assert {r["canary"] for r in ROWS if r["collection"] == "finance_revenue"} <= set(cell["leaks"])
    assert result["cells"]["ask:finance_revenue"]["alice"]["passed"] is False
    assert result["summary"]["passed"] < result["summary"]["total"]
    assert result["summary"]["verdict"] == "FAIL"


def test_wrong_role_in_token_fails_me_row(ai_on):
    tokens = {k: token_for(k) for k in USERS}
    tokens["alice"] = token_for("alice", roles=["Support.Agent", "Tenant.Admin"])
    result, _ = run(ai_on, lambda k: (tokens[k], None))
    assert result["cells"]["me"]["alice"]["passed"] is False
    assert result["cells"]["admin"]["alice"]["passed"] is False


def test_write_and_read_result(tmp_path, ai_on):
    result, tokens = run(ai_on)
    proof.write_result(ai_on.proof_output, result)
    saved = proof.read_result(ai_on.proof_output)
    assert saved["summary"]["total"] == 42
    git = saved["git"]
    assert set(git) == {"sha", "porcelain_count"} and git["sha"]
    assert git["porcelain_count"] is None or git["porcelain_count"] >= 0
    assert saved["server_started_at"] and saved["ran_at"] and saved["duration_seconds"] >= 0
    text = ai_on.proof_output.read_text()
    assert all(t not in text and t.split(".")[2] not in text for t in tokens.values())


def test_proof_page_renders_result(ai_on):
    result, _ = run(ai_on)
    proof.write_result(ai_on.proof_output, result)
    provider = lambda k: (token_for(k), None)
    with local_client(create_app(ai_on, token_provider=provider)) as c:
        html = c.get("/proof").text
    assert 'class="summary good">PASS · 42/42 checks passed' in html
    for upn in ai_on.users.values():
        assert upn in html
    for role in EXPECTED_ROLE.values():
        assert role in html
    assert "FAIL" not in html.replace("PASS/FAIL", "")
    for k in USERS:
        assert provider(k)[0] not in html


def test_proof_run_endpoint_guards(tmp_path):
    s = make_settings(tmp_path)
    with local_client(create_app(s, token_provider=lambda k: (None, "x"))) as c:
        assert c.post("/proof/run", headers={"Origin": ORIGIN}).status_code == 400  # no X-Proof-Run header
    s = make_settings(tmp_path, missing=("ENTRA_TENANT_ID",))
    with local_client(create_app(s)) as c:
        # 503 = got past the header and Origin guards (unconfigured, so nothing runs).
        assert c.post("/proof/run", headers={"X-Proof-Run": "1", "Origin": ORIGIN}).status_code == 503
        assert c.post("/proof/run", headers={"X-Proof-Run": "1",
                                             "Origin": "http://127.0.0.1:8000"}).status_code == 503


@pytest.mark.parametrize("origin", [None, "null", "http://evil.example", "http://localhost:8001",
                                    "http://localhost.evil.example:8000", "https://localhost:8000"])
def test_proof_run_rejects_missing_or_foreign_origin(tmp_path, origin):
    s = make_settings(tmp_path, missing=("ENTRA_TENANT_ID",))
    headers = {"X-Proof-Run": "1", **({"Origin": origin} if origin else {})}
    with local_client(create_app(s)) as c:
        r = c.post("/proof/run", headers=headers)
    assert r.status_code == 403 and r.json()["detail"] == "Origin not allowed"


def test_origin_port_comes_from_redirect_uri(tmp_path):
    s = make_settings(tmp_path, missing=("ENTRA_TENANT_ID",), redirect_uri="http://localhost:9123/auth/callback")
    with local_client(create_app(s)) as c:
        h = {"X-Proof-Run": "1"}
        assert c.post("/proof/run", headers={**h, "Origin": "http://localhost:9123"}).status_code == 503
        assert c.post("/proof/run", headers={**h, "Origin": ORIGIN}).status_code == 403


@pytest.mark.parametrize("host", ["evil.example", "evil.example:8000", "testserver", "localhost.evil.example"])
def test_dns_rebinding_foreign_host_rejected(tmp_path, host):
    """A rebinding page reaches 127.0.0.1 but its requests carry the attacker's Host header."""
    s = make_settings(tmp_path)
    with local_client(create_app(s, token_provider=lambda k: (token_for(k), None))) as c:
        for method, path, extra in (("POST", "/proof/run", {"X-Proof-Run": "1", "Origin": f"http://{host}"}),
                                    ("GET", "/proof", {}), ("GET", "/api/me", {})):
            r = c.request(method, path, headers={"Host": host, **extra})
            assert r.status_code == 400 and r.text == "Invalid host header", (method, path, host)


@pytest.mark.parametrize("host", ["localhost:8000", "127.0.0.1:8000", "localhost", "127.0.0.1:8001"])
def test_local_hosts_allowed(tmp_path, host):
    s = make_settings(tmp_path)
    with local_client(create_app(s, token_provider=lambda k: (None, "x"))) as c:
        assert c.get("/proof", headers={"Host": host}).status_code == 200


def test_negatives_all_401_with_names(ai_on):
    result, _ = run(ai_on)
    labels = [n["label"] for n in result["negatives"]]
    for want in ("alg \"none\"", "HS256", "attacker key, real kid", "Wrong audience", "Expired"):
        assert any(want in label for label in labels), want
    for n in result["negatives"]:
        assert n["status"] == 401 and n["passed"] is True and n["leaks"] == [], n


def test_negatives_fail_if_server_skips_verification(ai_on, monkeypatch):
    """The forged-token negatives must catch a server that stops verifying tokens."""
    import jwt

    def no_verify(token, settings):
        c = jwt.decode(token, options={"verify_signature": False})
        return auth.Principal(c["oid"], c["preferred_username"], None, c["tid"], tuple(c.get("roles", [])), ("access_as_user",))

    monkeypatch.setattr(auth, "validate_access_token", no_verify)
    result, _ = run(ai_on)
    by_label = {n["label"]: n for n in result["negatives"]}
    failed = [label for label, n in by_label.items() if not n["passed"]]
    assert len(failed) == NEEDS_TOKEN, failed  # every token-based negative now FAILs
    assert result["summary"]["verdict"] == "FAIL"
