"""RBAC: the server's behaviour must match the CONTRACT.md permission table exactly."""

import re
from pathlib import Path

import pytest

from app import rbac
from app.config import EXPECTED_ROLE
from app.data import ROWS
from app.proof import CONTRACT_TABLE
from conftest import bearer, entra_claims, mint, token_for

ROLES = ("Support.Agent", "Finance.Analyst", "Tenant.Admin")


def parse_contract_table() -> dict[str, dict[str, bool]]:
    text = (Path(__file__).resolve().parent.parent / "CONTRACT.md").read_text()
    table = {}
    for line in text.splitlines():
        m = re.match(r"\|\s*(read `(\w+)`|`admin:manage_roles`)\s*\|(.+)\|\s*$", line)
        if not m:
            continue
        cells = [c.strip() for c in m.group(3).split("|")]
        name = f"read {m.group(2)}" if m.group(2) else "admin:manage_roles"
        table[name] = {role: cell == "✅" for role, cell in zip(ROLES, cells)}
    return table


def test_contract_table_parsed_and_transcribed_correctly():
    parsed = parse_contract_table()
    assert len(parsed) == 5
    assert parsed == CONTRACT_TABLE  # the proof's copy matches the written contract


def test_rbac_module_matches_contract():
    for name, by_role in parse_contract_table().items():
        perm = name.replace("read ", "read:")
        for role, allowed in by_role.items():
            assert rbac.can([role], perm) is allowed, (name, role)


@pytest.mark.parametrize("user", ["alice", "bob", "carol"])
def test_http_matrix_matches_contract(client, claude, user):
    role = EXPECTED_ROLE[user]
    h = bearer(token_for(user))
    table = parse_contract_table()
    for c in rbac.COLLECTIONS:
        allowed = table[f"read {c}"][role]
        r = client.get(f"/api/data/{c}", headers=h)
        assert r.status_code == (200 if allowed else 403), (user, c)
        if allowed:
            assert r.json()["rows"] and all(row["collection"] == c for row in r.json()["rows"])
        else:
            assert r.json() == {"denied": [c]}
        r = client.post("/api/ask", headers=h, json={"question": "summarize", "collections": [c]})
        assert r.status_code == (200 if allowed else 403), (user, c)
    r = client.post("/api/admin/roles", headers=h, json={})
    assert r.status_code == (200 if table["admin:manage_roles"][role] else 403)
    if r.status_code == 200:
        assert r.json()["dry_run"] is True


@pytest.mark.parametrize("roles", [[], ["Some.Other.Role"], ["support.agent"], ["Tenant.Admin "], None])
def test_deny_by_default(client, claude, roles):
    token = mint(entra_claims("carol", roles=roles))  # carol's identity, but no recognised role
    h = bearer(token)
    me = client.get("/api/me", headers=h)
    assert me.status_code == 200
    for c in rbac.COLLECTIONS:
        assert client.get(f"/api/data/{c}", headers=h).status_code == 403
        assert client.post("/api/ask", headers=h, json={"question": "q", "collections": [c]}).status_code == 403
    assert client.post("/api/admin/roles", headers=h).status_code == 403
    assert claude.calls == []


def test_roles_claim_not_a_list_grants_nothing(client):
    h = bearer(mint(entra_claims("carol", roles="Tenant.Admin")))
    assert client.get("/api/data/audit_log", headers=h).status_code == 403


def test_unknown_collection_denied_even_for_admin(client, claude):
    h = bearer(token_for("carol"))
    assert client.get("/api/data/payroll", headers=h).status_code == 403
    r = client.post("/api/ask", headers=h, json={"question": "q", "collections": ["payroll"]})
    assert r.status_code == 403 and r.json() == {"denied": ["payroll"]}


def test_strict_multi_collection_ask(client, claude):
    h = bearer(token_for("alice"))
    r = client.post("/api/ask", headers=h,
                    json={"question": "q", "collections": ["kb_public", "finance_revenue", "audit_log"]})
    assert r.status_code == 403
    assert r.json() == {"denied": ["finance_revenue", "audit_log"]}
    assert claude.calls == []  # nothing reached the model


def test_sample_data_shape():
    by_col = {}
    for r in ROWS:
        assert re.fullmatch(r"(kb|tkt|fin|aud)-\d{3}", r["id"])
        by_col.setdefault(r["collection"], []).append(r)
    assert set(by_col) == set(rbac.COLLECTIONS)
    assert all(4 <= len(v) <= 6 for v in by_col.values())
    assert len({r["id"] for r in ROWS}) == len(ROWS)
