"""/playground and the request trace: who can turn tracing on, what the trace may contain,
and that the trace matches what the server actually decided."""

import json
import re
import time

import pytest

from app import auth, playground, proof, rbac, trace
from app.config import EXPECTED_ROLE
from app.main import create_app
from conftest import (CLIENT_ID, ORIGIN, TENANT_ID, UPNS, entra_claims, local_client, make_settings, mint,
                      token_for)

USERS = ("alice", "bob", "carol")
TRACE_KEY = "known-test-trace-key-0123456789abcdef"
MODES = ("real", "none", "tampered", "forged_roles", "alg_none", "hs256", "attacker_rsa", "aud", "expired")
# Where each token mode must stop, as the server's own checks run.
FAILS_AT = {"tampered": "signature", "forged_roles": "signature", "alg_none": "alg", "hs256": "alg",
            "attacker_rsa": "signature", "aud": "signature", "expired": "signature"}
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.")
SEND = {"Origin": ORIGIN, "X-Playground-Send": "1"}

ENTRA = {
    "tenant_id": TENANT_ID,
    "app": {"displayName": "Gatekeeper AI", "appId": CLIENT_ID, "objectId": "app-object-id"},
    "service_principal": {"id": "sp-object-id", "appRoleAssignmentRequired": True},
    "scope": {"value": "access_as_user", "id": "scope-id"},
    "app_roles": {"Support.Agent": {"id": "role-sa", "displayName": "Support Agent"},
                  "Finance.Analyst": {"id": "role-fa", "displayName": "Finance Analyst"},
                  "Tenant.Admin": {"id": "role-ta", "displayName": "Tenant Admin"}},
    "users": {k: {"upn": UPNS[k], "objectId": f"oid-{k}", "role": EXPECTED_ROLE[k], "assignmentId": f"asg-{k}"}
              for k in USERS},
}


@pytest.fixture
def tokens():
    return {k: token_for(k) for k in USERS}


@pytest.fixture
def pg(tmp_path, tokens, claude, monkeypatch):
    monkeypatch.setattr(trace, "new_key", lambda: TRACE_KEY)
    (tmp_path / "entra-objects.json").write_text(json.dumps(ENTRA))
    s = make_settings(tmp_path, entra_objects=tmp_path / "entra-objects.json")
    app = create_app(s, token_provider=lambda k: (tokens[k], None))
    app.state.api_client = lambda base: local_client(app)
    with local_client(app) as c:
        yield c


def send(c, **body):
    return c.post("/playground/send", json=body, headers=SEND)


def steps(result, kind):
    return [s for s in result["trace"] if s["kind"] == kind]


# ---------------------------------------------------------------- turning the trace on


@pytest.mark.parametrize("extra", [
    {"X-Gatekeeper-Trace": "1"},
    {"X-Gatekeeper-Trace": "1", "X-Gatekeeper-Trace-Id": "a" * 32},
    {"X-Gatekeeper-Trace": "1", "X-Gatekeeper-Trace-Key": "guess", "X-Gatekeeper-Trace-Id": "a" * 32},
    {"X-Gatekeeper-Trace": "1", "X-Gatekeeper-Trace-Key": TRACE_KEY[:-1], "X-Gatekeeper-Trace-Id": "a" * 32},
    {"X-Gatekeeper-Trace": "0", "X-Gatekeeper-Trace-Key": TRACE_KEY, "X-Gatekeeper-Trace-Id": "a" * 32},
    {"X-Gatekeeper-Trace": "1", "X-Gatekeeper-Trace-Key": TRACE_KEY, "X-Gatekeeper-Trace-Id": "../../x"},
])
def test_outside_caller_cannot_enable_trace(pg, tokens, extra):
    plain = pg.get("/api/data/finance_revenue", headers={"Authorization": f"Bearer {tokens['alice']}"})
    traced = pg.get("/api/data/finance_revenue", headers={"Authorization": f"Bearer {tokens['alice']}", **extra})
    assert (traced.status_code, traced.json()) == (plain.status_code, plain.json()) == (403, {"denied": ["finance_revenue"]})
    assert not any(k.lower().startswith("x-gatekeeper") for k in traced.headers)
    assert len(pg.app.state.traces) == 0


def test_with_the_key_the_trace_is_stored_not_returned(pg, tokens):
    tid = "b" * 32
    h = {"Authorization": f"Bearer {tokens['bob']}", "X-Gatekeeper-Trace": "1",
         "X-Gatekeeper-Trace-Key": TRACE_KEY, "X-Gatekeeper-Trace-Id": tid}
    r = pg.get("/api/data/finance_revenue", headers=h)
    assert r.status_code == 200 and set(r.json()) == {"collection", "rows"}  # body unchanged
    stored = pg.app.state.traces.pop(tid)
    assert [s["kind"] for s in stored][:2] == ["request", "auth_header"]


def test_trace_is_off_for_ordinary_calls(pg, tokens):
    assert not trace.active()
    pg.post("/api/ask", json={"question": "q", "collections": ["kb_public"]},
            headers={"Authorization": f"Bearer {tokens['alice']}"})
    assert len(pg.app.state.traces) == 0 and not trace.active()


# ---------------------------------------------------------------- no token material


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("user", USERS)
def test_result_has_no_token_or_secret(pg, tokens, user, mode):
    for call, extra in (("me", {}), ("ask", {"body": json.dumps({"question": "q", "collections": ["kb_public"]})})):
        r = send(pg, user=user, call=call, token_mode=mode, **extra)
        assert r.status_code == 200, r.text
        blob = json.dumps(r.json())
        for t in tokens.values():
            assert t not in blob
            assert t.split(".")[2] not in blob
        assert not JWT_RE.search(blob), "something token-shaped is in the result"
        assert "test-secret-not-real" not in blob and TRACE_KEY not in blob
        if mode != "none":
            auth_shown = dict(r.json()["request"]["headers"])["Authorization"]
            assert auth_shown.startswith("Bearer <") and auth_shown.endswith("redacted>")


def test_trace_rows_are_ids_only(pg):
    r = send(pg, user="carol", call="ask", body=json.dumps({"question": "q", "collections": ["audit_log", "kb_public"]}))
    res = r.json()
    trace_blob = json.dumps(res["trace"])
    assert "CANARY-" not in trace_blob and "admin.ops@example.com" not in trace_blob
    f = steps(res, "filter")[0]
    assert f["passed"] == {"kb_public": [f"kb-00{i}" for i in range(1, 6)], "audit_log": [f"aud-00{i}" for i in range(1, 6)]}
    assert f["excluded"] == {"support_tickets": "not requested", "finance_revenue": "not requested"}


# ---------------------------------------------------------------- trace == real outcome

CALLS = {
    "me": {},
    "data_fin": {"call": "data", "collection": "finance_revenue"},
    "data_bad": {"call": "data", "collection": "FINANCE_revenue"},
    "ask_tickets": {"call": "ask", "body": json.dumps({"question": "q", "collections": ["support_tickets"]})},
    "admin": {"call": "admin", "body": "{}"},
}


def contract_allows(role, call_id):
    if call_id == "me":
        return True
    if call_id == "data_bad":
        return False
    if call_id == "admin":
        return proof.CONTRACT_TABLE["admin:manage_roles"][role]
    col = "finance_revenue" if call_id == "data_fin" else "support_tickets"
    return proof.CONTRACT_TABLE[f"read {col}"][role]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("user", USERS)
def test_trace_matches_real_outcome(pg, user, mode):
    for call_id, spec in CALLS.items():
        body = {"call": "me", **spec}
        res = send(pg, user=user, token_mode=mode, forged_role="Tenant.Admin", **body).json()
        status = res["response"]["status"]
        claims = steps(res, "claims")
        ah = steps(res, "auth_header")[0]
        assert steps(res, "response")[0]["status"] == status
        if mode == "none":
            assert status == 401 and ah["ok"] is False and not claims
            assert res["response"]["body"]["detail"] == "missing bearer token"
            continue
        assert ah["ok"] is True and len(claims) == 1
        cl = claims[0]
        results = [c["result"] for c in cl["checks"]]
        no_op = mode == "forged_roles" and EXPECTED_ROLE[user] == "Tenant.Admin"  # same bytes, still valid
        if no_op:
            assert "byte-identical" in steps(res, "forge")[0]["note"]
        if mode in FAILS_AT and not no_op:
            assert status == 401, (call_id, res["response"])
            assert cl["outcome"] == "fail"
            assert res["response"]["body"]["detail"] == f"invalid token: {cl['error']}"
            failed = [c["check"] for c in cl["checks"] if c["result"] == "fail"]
            assert failed == [FAILS_AT[mode]]
            i = results.index("fail")  # passes before it, nothing evaluated after it
            assert set(results[:i]) <= {"pass"} and set(results[i + 1:]) <= {"not reached"}
            assert not steps(res, "rbac") and not steps(res, "principal") and not steps(res, "decision")
            continue
        # real token: validation passed, RBAC decided
        assert cl["outcome"] == "pass" and set(results) == {"pass"}
        assert steps(res, "principal")[0]["roles"] == [EXPECTED_ROLE[user]]
        allowed = contract_allows(EXPECTED_ROLE[user], call_id)
        assert status == (200 if allowed else 403), (user, call_id, status)
        dec = steps(res, "decision")[0]
        assert dec["status"] == status
        rb = steps(res, "rbac")
        if call_id == "me":
            assert rb == []
        else:
            assert rb[0]["allowed"] is allowed and rb[0]["token_roles"] == [EXPECTED_ROLE[user]]
            assert all(s["allowed"] for s in rb) is allowed
        if call_id == "ask_tickets" and allowed:
            assert steps(res, "filter")[0]["passed"].keys() == {"support_tickets"}
            assert steps(res, "ai_call")[0]["rows_sent"] == 5


@pytest.mark.parametrize("overrides, failed, message", [
    ({"exp": int(time.time()) - 3600}, "exp/nbf/iat", "token expired"),
    ({"nbf": int(time.time()) + 3600}, "exp/nbf/iat", "token not yet valid"),
    ({"iss": "https://login.microsoftonline.com/other/v2.0"}, "iss", "wrong issuer"),
    ({"aud": "api://someone-else"}, "aud", "wrong audience"),
    ({"tid": "00000000-0000-0000-0000-000000000000"}, "tid", "wrong tenant"),
    ({"scp": "User.Read"}, "scp", "missing scope access_as_user"),
    ({"oid": None}, "required claims", "missing claim: oid"),
])
def test_claim_checks_name_the_real_failure(settings, overrides, failed, message):
    """Properly signed tokens with one bad claim: the trace stops exactly where the code did."""
    token = mint(entra_claims("bob", **overrides))
    with trace.collect() as got:
        with pytest.raises(auth.TokenError) as e:
            auth.validate_access_token(token, settings)
    assert str(e.value) == message
    cl = [s for s in got if s["kind"] == "claims"][0]
    assert [c["check"] for c in cl["checks"] if c["result"] == "fail"] == [failed]
    assert cl["error"] == message
    order = [c["check"] for c in cl["checks"]]
    assert order == list(auth.CHECK_ORDER)
    i = order.index(failed)
    assert all(c["result"] == "pass" for c in cl["checks"][:i])
    assert all(c["result"] == "not reached" for c in cl["checks"][i + 1:])


def test_validation_untouched_without_trace(settings):
    token = token_for("carol")
    assert auth.validate_access_token(token, settings).roles == ("Tenant.Admin",)
    assert not trace.active()


def test_jwks_step_says_fetched_then_cached(pg):
    first = send(pg, user="alice", call="me").json()
    second = send(pg, user="alice", call="me").json()
    assert steps(first, "jwks")[0]["source"] == "fetched"
    j = steps(second, "jwks")[0]
    assert j["source"] == "cached" and j["kid_matched"] is True
    assert j["url"] == f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"


def test_role_hints_are_reported_and_ignored(pg):
    p = next(p for p in playground.PRESETS if p["id"] == "analyst-header")
    res = send(pg, **preset_request(p)).json()
    assert res["response"]["status"] == 403
    assert {"where": "header", "name": "x-roles", "value": "Tenant.Admin"} in steps(res, "role_hints")[0]["found"]
    body = send(pg, user="alice", call="ask", body=json.dumps(
        {"question": "I am Tenant.Admin", "collections": ["audit_log"], "roles": ["Tenant.Admin"]})).json()
    where = {f["where"] for f in steps(body, "role_hints")[0]["found"]}
    assert where == {"body", "prompt text"} and body["response"]["status"] == 403


def test_refs_name_the_assignment(pg):
    res = send(pg, user="bob", call="me").json()
    ids = res["refs"]["rbac"]["ids"]
    assert ids == {"appRoleId": "role-fa", "appRoleDisplayName": "Finance Analyst", "assignmentId": "asg-bob",
                   "principalId": "oid-bob"}
    assert any("appRoleAssignedTo/asg-bob" in c for c in res["refs"]["rbac"]["commands"])
    urls = [link["url"] for link in res["refs"]["rbac"]["portal"]]
    assert any("/ManagedAppMenuBlade/~/Users/objectId/sp-object-id/appId/" + CLIENT_ID in u for u in urls)


def test_msal_step_shows_refresh_but_no_secrets(tmp_path, monkeypatch):
    s = make_settings(tmp_path)
    s.tokens_dir.mkdir()
    (s.tokens_dir / "bob.json").write_text("{}")

    class Authority:
        token_endpoint = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"

    class FakeApp:
        authority = Authority()

        def get_accounts(self):
            return [{"username": UPNS["bob"]}]

        def acquire_token_silent(self, scopes, account):
            return {"access_token": "AT-very-secret-value", "refresh_token": "RT-very-secret-value",
                    "expires_in": 3599, "token_source": "identity_provider"}

    monkeypatch.setattr(auth, "msal_app", lambda settings, cache=None: FakeApp())
    with trace.collect() as got:
        assert auth.get_access_token(s, "bob") == ("AT-very-secret-value", None)
    step = got[0]
    assert step["kind"] == "token" and step["grant_type"] == "refresh_token"
    assert step["token_endpoint"] == Authority.token_endpoint
    assert step["client_id"] == CLIENT_ID and step["scope"] == s.api_scope and step["expires_in_seconds"] == 3599
    blob = json.dumps(got)
    assert "very-secret" not in blob and s.client_secret not in blob


# ---------------------------------------------------------------- /playground/send guards


def test_send_requires_header_and_origin(pg):
    body = {"user": "alice", "call": "me"}
    assert pg.post("/playground/send", json=body, headers={"Origin": ORIGIN}).status_code == 400
    for origin in (None, "null", "http://evil.example", "http://localhost:8001", "https://localhost:8000"):
        h = {"X-Playground-Send": "1", **({"Origin": origin} if origin else {})}
        r = pg.post("/playground/send", json=body, headers=h)
        assert r.status_code == 403 and r.json()["detail"] == "Origin not allowed", origin
    assert pg.post("/playground/send", json=body, headers=SEND).status_code == 200


@pytest.mark.parametrize("host", ["evil.example", "evil.example:8000", "localhost.evil.example"])
def test_send_rejects_foreign_host(pg, host):
    r = pg.post("/playground/send", json={"user": "alice", "call": "me"},
                headers={**SEND, "Host": host, "Origin": f"http://{host}"})
    assert r.status_code == 400 and r.text == "Invalid host header"


@pytest.mark.parametrize("body", [
    {"user": "mallory", "call": "me"},
    {"user": "Alice", "call": "me"},
    {"user": "alice", "call": "delete_everything"},
    {"user": "alice", "call": "me", "url": "http://evil.example/"},
    {"user": "alice", "call": "me", "token_mode": "steal"},
    {"user": "alice", "call": "me", "forged_role": "Global.Admin"},
    {"user": "alice", "call": "data", "collection": "../me"},
    {"user": "alice", "call": "data", "collection": "kb_public/../../x"},
    {"user": "alice", "call": "data", "collection": "http://evil.example"},
    {"user": "alice", "call": "me", "headers": [{"name": "Authorization", "value": "Bearer x"}]},
    {"user": "alice", "call": "me", "headers": [{"name": "Host", "value": "evil.example"}]},
    {"user": "alice", "call": "me", "headers": [{"name": "X-Gatekeeper-Trace-Key", "value": "x"}]},
    {"user": "alice", "call": "me", "headers": [{"name": "X-Bad", "value": "a\r\nInjected: 1"}]},
    {"user": "alice", "call": "me", "headers": [{"name": "Bad Name", "value": "x"}]},
    {"user": "alice", "call": "ask", "body": "x" * 9000},
    [],
])
def test_send_rejects_bad_input(pg, body):
    r = pg.post("/playground/send", json=body, headers=SEND)
    assert r.status_code == 400, (body, r.text)
    assert len(pg.app.state.traces) == 0


def test_send_not_signed_in_is_409_but_no_token_mode_works(tmp_path, claude):
    s = make_settings(tmp_path)
    app = create_app(s, token_provider=lambda k: (None, "not signed in"))
    app.state.api_client = lambda base: local_client(app)
    with local_client(app) as c:
        r = send(c, user="bob", call="me")
        assert r.status_code == 409 and "not signed in" in r.json()["detail"]
        r = send(c, user="bob", call="me", token_mode="none")
        assert r.status_code == 200 and r.json()["response"]["status"] == 401


def test_send_unconfigured(tmp_path):
    s = make_settings(tmp_path, missing=("ENTRA_TENANT_ID",))
    with local_client(create_app(s)) as c:
        assert send(c, user="alice", call="me").status_code == 503


def test_invalid_json_body_reaches_api_and_gets_400(pg):
    res = send(pg, user="alice", call="ask", body="{not json").json()
    assert res["response"]["status"] == 400
    assert res["request"]["body"] == "{not json"


# ---------------------------------------------------------------- presets and page


def preset_request(p):
    out = {k: p[k] for k in ("user", "call") if k in p}
    if "collection" in p:
        out["collection"] = p["collection"]
    if "body" in p:
        out["body"] = json.dumps(p["body"])
    elif p["call"] in playground.DEFAULT_BODIES:
        out["body"] = json.dumps(playground.DEFAULT_BODIES[p["call"]])
    for k in ("headers", "token_mode", "forged_role"):
        if k in p:
            out[k] = p[k]
    return out


def test_presets_cover_each_role():
    roles = {p["role"] for p in playground.PRESETS}
    assert set(rbac.ROLE_PERMISSIONS) <= roles
    for role in rbac.ROLE_PERMISSIONS:  # each role has an allowed and a refused preset
        assert {p["expect"] for p in playground.PRESETS if p["role"] == role} & {200}
        assert {p["expect"] for p in playground.PRESETS if p["role"] == role} & {401, 403}
    for p in playground.PRESETS:
        assert EXPECTED_ROLE[p["user"]] == p["role"] or p["role"] is None
        playground.SendRequest.model_validate(preset_request(p))


@pytest.mark.parametrize("preset", playground.PRESETS, ids=lambda p: p["id"])
def test_preset_gives_its_expected_status(pg, preset):
    res = send(pg, **preset_request(preset))
    assert res.status_code == 200, res.text
    assert res.json()["response"]["status"] == preset["expect"]


def test_playground_page(pg, tokens):
    r = pg.get("/playground")
    assert r.status_code == 200
    html = r.text
    for upn in UPNS.values():
        assert upn in html
    for t in tokens.values():
        assert t not in html and t.split(".")[2] not in html
    assert not JWT_RE.search(html)
    data = json.loads(re.search(r'<script type="application/json" id="pg-data">(.*?)</script>', html, re.S).group(1))
    alice = next(u for u in data["user_cards"] if u["key"] == "alice")
    assert alice["signed_in"] and alice["roles"] == ["Support.Agent"]
    assert alice["claims"]["payload"]["preferred_username"] == UPNS["alice"]
    assert set(alice["claims"]["payload"]) >= {"iss", "aud", "tid", "oid", "roles", "scp", "exp"}
    assert data["role_objects"]["Tenant.Admin"]["id"] == "role-ta"
    assert 'href="/proof"' in html and "/static/playground.js" in html


def test_preset_labels_name_the_configured_users(pg):
    html = pg.get("/playground").text
    data = json.loads(re.search(r'<script type="application/json" id="pg-data">(.*?)</script>', html, re.S).group(1))
    labels = {p["id"]: p["label"] for p in data["presets"]}
    assert labels["agent-finance"] == "agent.ada tries finance"
    assert labels["forged-admin"] == "forged admin role (agent.ada)"
    assert labels["admin-roles"] == "admin.cy admin roles"
    assert not any("{" in label for label in labels.values())


def test_playground_page_without_entra_objects(tmp_path, tokens):
    s = make_settings(tmp_path, entra_objects=tmp_path / "missing.json")
    with local_client(create_app(s, token_provider=lambda k: (tokens[k], None))) as c:
        html = c.get("/playground").text
    assert "docs/entra-objects.json not found" in html


def test_entra_objects_for_another_tenant_are_ignored(tmp_path):
    (tmp_path / "e.json").write_text(json.dumps({**ENTRA, "tenant_id": "someone-else"}))
    s = make_settings(tmp_path, entra_objects=tmp_path / "e.json")
    objs, problem = playground.load_entra_objects(s)
    assert objs is None and "different tenant" in problem


def test_pages_link_to_playground(client):
    for path in ("/", "/proof"):
        assert 'href="/playground"' in client.get(path).text


def test_committed_entra_objects_have_no_secrets():
    path = playground.Path(__file__).resolve().parent.parent / "docs" / "entra-objects.json"
    if not path.exists():
        pytest.skip("docs/entra-objects.json not written yet")
    data = json.loads(path.read_text())
    assert set(data) >= {"tenant_id", "app", "service_principal", "app_roles", "users"}
    blob = json.dumps(data).lower()
    for word in ("secret", "password", "token", "credential"):
        assert word not in blob
