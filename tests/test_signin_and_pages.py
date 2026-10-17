"""Sign-in bridge (MSAL faked at the network boundary) and the unconfigured state."""

import stat
from urllib.parse import parse_qs, urlparse

import msal
import pytest

from app import auth
from app.config import load_settings
from app.main import create_app
from conftest import TENANT_ID, UPNS, local_client, make_settings


class FakeMsalApp:
    """Replaces msal.ConfidentialClientApplication (which needs the network)."""

    last_flow_kwargs: dict = {}
    id_claims: dict = {}

    def __init__(self, cache):
        self.cache = cache

    def initiate_auth_code_flow(self, **kw):
        FakeMsalApp.last_flow_kwargs = kw
        return {"state": "st-123", "code_verifier": "v" * 43, "nonce": "n-1", "redirect_uri": kw["redirect_uri"],
                "scope": kw["scopes"],
                "auth_uri": f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize"
                            f"?state=st-123&code_challenge=abc&code_challenge_method=S256&login_hint={kw['login_hint']}"
                            f"&prompt={kw['prompt']}"}

    def acquire_token_by_auth_code_flow(self, flow, auth_response):
        if flow["state"] != auth_response.get("state"):
            raise ValueError("state mismatch")
        # Put something in the cache so a save would be visible.
        self.cache.add({"client_id": "c", "scope": ["s"], "token_endpoint": "https://login.microsoftonline.com/t/oauth2/v2.0/token",
                        "response": {"access_token": "AT-not-real", "token_type": "Bearer", "expires_in": 3600}})
        return {"access_token": "AT-not-real", "id_token_claims": FakeMsalApp.id_claims}


@pytest.fixture
def signin(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "msal_app", lambda settings, cache=None: FakeMsalApp(cache or msal.SerializableTokenCache()))
    s = make_settings(tmp_path)
    with local_client(create_app(s), follow_redirects=False) as c:
        yield s, c


def test_login_uses_pkce_login_hint_and_prompt_login(signin):
    s, c = signin
    r = c.get("/auth/login?user=bob")
    assert r.status_code == 302
    kw = FakeMsalApp.last_flow_kwargs
    assert kw["login_hint"] == UPNS["bob"] and kw["prompt"] == "login"
    assert kw["scopes"] == [s.api_scope] and kw["redirect_uri"] == s.redirect_uri
    assert "gk_session" in r.cookies or "gk_session" in c.cookies


def test_login_rejects_unknown_user(signin):
    _, c = signin
    assert c.get("/auth/login?user=mallory").status_code == 400


def test_callback_stores_cache_with_0600(signin):
    s, c = signin
    FakeMsalApp.id_claims = {"preferred_username": UPNS["carol"].upper(), "tid": TENANT_ID}
    c.get("/auth/login?user=carol")
    r = c.get("/auth/callback?code=abc&state=st-123")
    assert r.status_code == 302 and r.headers["location"] == "/proof"
    path = s.tokens_dir / "carol.json"
    assert path.exists()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(s.tokens_dir.stat().st_mode) == 0o700


def test_callback_rejects_wrong_account_and_stores_nothing(signin):
    s, c = signin
    FakeMsalApp.id_claims = {"preferred_username": UPNS["carol"], "tid": TENANT_ID}  # carol signed into bob's slot
    c.get("/auth/login?user=bob")
    r = c.get("/auth/callback?code=abc&state=st-123")
    assert r.status_code == 403
    assert "nothing was stored" in r.text
    assert not (s.tokens_dir / "bob.json").exists()
    assert "AT-not-real" not in r.text


def test_callback_rejects_wrong_tenant(signin):
    s, c = signin
    FakeMsalApp.id_claims = {"preferred_username": UPNS["alice"], "tid": "someone-else"}
    c.get("/auth/login?user=alice")
    assert c.get("/auth/callback?code=abc&state=st-123").status_code == 403
    assert not (s.tokens_dir / "alice.json").exists()


def test_callback_state_mismatch_and_no_flow(signin):
    s, c = signin
    assert c.get("/auth/callback?code=abc&state=st-123").status_code == 400  # no flow in session
    FakeMsalApp.id_claims = {"preferred_username": UPNS["alice"], "tid": TENANT_ID}
    c.get("/auth/login?user=alice")
    assert c.get("/auth/callback?code=abc&state=forged").status_code == 403
    assert not (s.tokens_dir / "alice.json").exists()
    # the flow is single-use: replaying the right state afterwards fails too
    assert c.get("/auth/callback?code=abc&state=st-123").status_code == 400


def test_get_access_token_without_cache(tmp_path):
    s = make_settings(tmp_path)
    assert auth.get_access_token(s, "alice") == (None, "not signed in")
    assert auth.get_access_token(make_settings(tmp_path, missing=("X",)), "alice") == (None, "not configured")


# ---------------------------------------------------------------- unconfigured state


@pytest.fixture
def unconfigured(tmp_path):
    s = load_settings(tmp_path / "no.env")
    with local_client(create_app(s), follow_redirects=False) as c:
        yield c


def test_unconfigured_pages_render(unconfigured):
    for path in ("/", "/proof"):
        r = unconfigured.get(path)
        assert r.status_code == 200
        assert "Not configured" in r.text and "scripts/provision.sh" in r.text
        assert "AI not configured" in r.text
    assert "disabled" in unconfigured.get("/proof").text


def test_unconfigured_api_and_auth(unconfigured):
    assert unconfigured.get("/api/me").status_code == 401
    assert unconfigured.get("/auth/login?user=alice").status_code == 503
    assert unconfigured.get("/auth/callback").status_code == 503
