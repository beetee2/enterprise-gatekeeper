"""Every token validation rule from CONTRACT.md. Any failure must be a 401."""

import time

import jwt
import pytest

from app.main import create_app
from conftest import (
    CLIENT_ID, KID, OTHER_KEY, SIGNING_KEY, TENANT_ID, UPNS, bearer, entra_claims, local_client, make_settings, mint,
    token_for,
)


def test_valid_token_for_each_role(client):
    for user, role in (("alice", "Support.Agent"), ("bob", "Finance.Analyst"), ("carol", "Tenant.Admin")):
        r = client.get("/api/me", headers=bearer(token_for(user)))
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["roles"] == [role]
        assert body["tid"] == TENANT_ID
        assert body["preferred_username"] == UPNS[user]


def test_missing_token(client):
    r = client.get("/api/me")
    assert r.status_code == 401
    assert r.headers["www-authenticate"].startswith("Bearer")


@pytest.mark.parametrize("header", ["Bearer", "Bearer ", "Basic abc", "token-without-scheme", "Bearer not.a.jwt"])
def test_malformed_authorization(client, header):
    assert client.get("/api/me", headers={"Authorization": header}).status_code == 401


now = int(time.time())

BAD_CLAIMS = {
    "expired": {"exp": now - 3600, "iat": now - 7200, "nbf": now - 7200},
    "not_yet_valid": {"nbf": now + 3600},
    "wrong_aud_other_app": {"aud": "00000000-1111-2222-3333-444444444444"},
    "wrong_aud_v1_style_uri": {"aud": f"api://{CLIENT_ID}"},
    "wrong_aud_graph": {"aud": "00000003-0000-0000-c000-000000000000"},
    "wrong_iss_v1": {"iss": f"https://sts.windows.net/{TENANT_ID}/"},
    "wrong_iss_other_tenant": {"iss": "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"},
    "wrong_tid_claim": {"tid": "11111111-2222-3333-4444-555555555555"},
    "missing_scp": {"scp": None},
    "wrong_scp": {"scp": "User.Read"},
    "missing_exp": {"exp": None},
    "missing_oid": {"oid": None},
    "missing_tid": {"tid": None},
}


@pytest.mark.parametrize("case", sorted(BAD_CLAIMS))
def test_bad_claims_rejected(client, case):
    token = mint(entra_claims("carol", **BAD_CLAIMS[case]))  # carol = admin, so a pass would be loud
    r = client.get("/api/me", headers=bearer(token))
    assert r.status_code == 401, (case, r.text)
    r = client.post("/api/admin/roles", headers=bearer(token))
    assert r.status_code == 401, case


def test_signed_by_another_key_with_same_kid(client):
    token = mint(entra_claims("carol"), key=OTHER_KEY, kid=KID)
    r = client.get("/api/me", headers=bearer(token))
    assert r.status_code == 401
    assert "bad signature" in r.json()["detail"]


def test_unknown_kid(client):
    assert client.get("/api/me", headers=bearer(mint(entra_claims("carol"), kid="nope"))).status_code == 401


def test_tampered_payload_keeps_signature(client):
    from app.proof import forge_roles, tamper_signature

    good = token_for("alice")
    assert client.get("/api/me", headers=bearer(tamper_signature(good))).status_code == 401
    forged = forge_roles(good, ["Tenant.Admin"])
    assert client.post("/api/admin/roles", headers=bearer(forged)).status_code == 401


def test_alg_none_and_hs256_confusion_rejected(client):
    claims = entra_claims("carol")
    none_token = jwt.encode(claims, None, algorithm="none", headers={"kid": KID})
    assert client.get("/api/me", headers=bearer(none_token)).status_code == 401
    # HS256 signed with the public key bytes (classic key-confusion attack)
    from cryptography.hazmat.primitives import serialization

    pub = SIGNING_KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    import hmac, hashlib, base64, json

    def b64(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    head = b64(json.dumps({"alg": "HS256", "kid": KID, "typ": "JWT"}).encode())
    body = b64(json.dumps(claims).encode())
    sig = b64(hmac.new(pub, f"{head}.{body}".encode(), hashlib.sha256).digest())
    assert client.get("/api/me", headers=bearer(f"{head}.{body}.{sig}")).status_code == 401


def test_roles_in_body_and_query_are_ignored(client, claude):
    alice = bearer(token_for("alice"))
    r = client.post("/api/admin/roles?roles=Tenant.Admin", headers=alice, json={"roles": ["Tenant.Admin"]})
    assert r.status_code == 403
    r = client.post("/api/ask?roles=Finance.Analyst", headers=alice,
                    json={"question": "revenue?", "collections": ["finance_revenue"], "roles": ["Tenant.Admin"]})
    assert r.status_code == 403
    assert r.json() == {"denied": ["finance_revenue"]}
    r = client.get("/api/data/audit_log?roles=Tenant.Admin", headers={**alice, "X-Roles": "Tenant.Admin"})
    assert r.status_code == 403
    assert claude.calls == []


def test_unauthenticated_bad_body_is_401_not_400(client):
    r = client.post("/api/ask", content=b"{not json")
    assert r.status_code == 401


def test_unconfigured_server_rejects_even_a_valid_looking_token(tmp_path):
    s = make_settings(tmp_path, missing=("ENTRA_TENANT_ID",))
    with local_client(create_app(s)) as c:
        r = c.get("/api/me", headers=bearer(token_for("carol")))
        assert r.status_code == 401
        assert "not configured" in r.json()["detail"]


def test_token_never_echoed_in_errors(client):
    token = mint(entra_claims("carol", aud="wrong"))
    r = client.get("/api/me", headers=bearer(token))
    assert token not in r.text
    assert token.split(".")[1] not in r.text
