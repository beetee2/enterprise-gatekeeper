"""Test harness: a fake Entra tenant.

Generates an RSA key, serves it as the tenant JWKS (monkeypatched fetch), and mints
tokens shaped like real Entra v2 access tokens for this app's API.
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app import ai, auth
from app.config import EXPECTED_ROLE, Settings
from app.main import create_app

TENANT_ID = "8f3a2c1e-5b7d-4e9f-a1c3-2d4e6f8a0b1c"
CLIENT_ID = "3c9e1f2a-7b4d-4a6e-9c8b-1f2e3d4c5b6a"
KID = "test-kid-1"
# A made-up tenant. The local parts are deliberately not user1/2/3, so nothing can
# depend on the owner's naming.
DOMAIN = "fabrikam-test.onmicrosoft.com"
UPNS = {"alice": f"agent.ada@{DOMAIN}", "bob": f"analyst.ben@{DOMAIN}", "carol": f"admin.cy@{DOMAIN}"}
OIDS = {k: str(uuid.uuid5(uuid.NAMESPACE_DNS, k)) for k in UPNS}


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


SIGNING_KEY = _key()
OTHER_KEY = _key()  # an attacker's key


def jwk_for(private_key, kid: str) -> dict:
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    jwk.update({"kid": kid, "use": "sig", "kty": "RSA"})
    return jwk


def make_settings(tmp_path: Path, **overrides) -> Settings:
    base = dict(
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        client_secret="test-secret-not-real",
        api_scope=f"api://{CLIENT_ID}/access_as_user",
        redirect_uri="http://localhost:8000/auth/callback",
        users=dict(UPNS),
        session_secret="test-session-secret",
        anthropic_api_key="",
        missing=(),
        tokens_dir=tmp_path / ".tokens",
        proof_output=tmp_path / "proof" / "latest.json",
    )
    base.update(overrides)
    return Settings(**base)


def entra_claims(user: str | None = "alice", **overrides) -> dict:
    """Claims of an Entra ID v2 access token issued to this app's API."""
    now = int(time.time())
    claims = {
        "aud": CLIENT_ID,
        "iss": f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
        "iat": now - 10,
        "nbf": now - 10,
        "exp": now + 3600,
        "aio": "AWQAm/8YAAAA-fake",
        "azp": CLIENT_ID,
        "azpacr": "1",
        "name": f"GK {user}",
        "oid": OIDS.get(user, str(uuid.uuid4())),
        "preferred_username": UPNS.get(user, f"someone@{DOMAIN}"),
        "rh": "0.fake.",
        "roles": [EXPECTED_ROLE[user]] if user in EXPECTED_ROLE else [],
        "scp": "access_as_user",
        "sub": "fake-pairwise-sub",
        "tid": TENANT_ID,
        "uti": "fakeUti",
        "ver": "2.0",
    }
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


def mint(claims: dict, key=SIGNING_KEY, kid: str = KID, alg: str = "RS256") -> str:
    return jwt.encode(claims, key, algorithm=alg, headers={"kid": kid, "typ": "JWT"})


def token_for(user: str, **overrides) -> str:
    return mint(entra_claims(user, **overrides))


# The app only serves Host localhost/127.0.0.1 (TrustedHostMiddleware), so tests talk to
# it as the browser does, instead of TestClient's default "testserver" host.
BASE_URL = "http://localhost:8000"
ORIGIN = BASE_URL  # what a browser on the /proof page sends with POST /proof/run


def local_client(app, **kw) -> TestClient:
    return TestClient(app, base_url=BASE_URL, **kw)


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def fake_jwks(monkeypatch):
    calls = []

    def fetch(url):
        calls.append(url)
        assert url == f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"
        return {"keys": [jwk_for(SIGNING_KEY, KID)]}

    monkeypatch.setattr(auth, "fetch_jwks", fetch)
    auth.reset_jwks_cache()
    yield calls
    auth.reset_jwks_cache()


class ClaudeStub:
    """Stands in for the Claude call; records exactly which rows the model would see."""

    def __init__(self):
        self.calls: list[dict] = []

    def __call__(self, settings, question, rows):
        self.calls.append({"question": question, "rows": rows})
        ids = ", ".join(r["id"] for r in rows)
        return f"stub answer citing [{ids}]"

    @property
    def seen_ids(self) -> set[str]:
        return {r["id"] for c in self.calls for r in c["rows"]}


@pytest.fixture
def claude(monkeypatch):
    stub = ClaudeStub()
    monkeypatch.setattr(ai, "answer", stub)
    return stub


@pytest.fixture
def settings(tmp_path):
    return make_settings(tmp_path)


@pytest.fixture
def client(settings):
    with local_client(create_app(settings, token_provider=lambda k: (token_for(k), None))) as c:
        yield c
