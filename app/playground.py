"""/playground helpers: token modes, presets, the request the playground sends, and the
"look it up yourself" references (portal links, az commands) for each trace step.

The access token never leaves the server: the page gets decoded claims and a redacted
description, and every result is checked for token material before it is returned.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal

import jwt
from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import proof, rbac
from .config import EXPECTED_ROLE, USER_KEYS, Settings

GRAPH = "https://graph.microsoft.com/v1.0"
ENTRA = "https://entra.microsoft.com"
ROLES = tuple(rbac.ROLE_PERMISSIONS)

CALLS = {
    "me":    {"method": "GET",  "path": "/api/me",          "label": "GET /api/me"},
    "data":  {"method": "GET",  "path": "/api/data/{collection}", "label": "GET /api/data/{collection}"},
    "ask":   {"method": "POST", "path": "/api/ask",         "label": "POST /api/ask"},
    "admin": {"method": "POST", "path": "/api/admin/roles", "label": "POST /api/admin/roles"},
}

# mode: (label, what the Authorization header carries, forger or None)
TOKEN_MODES = {
    "real":     ("Real token", "{who} token", None),
    "none":     ("No token", None, None),
    "tampered": ("Tampered signature (one bit flipped)", "{who} token, one signature bit flipped", proof.tamper_signature),
    "forged_roles": ("Forged roles (payload edited, original signature)",
                     "{who} token, payload roles={role}, original signature", None),
    "alg_none": ('alg "none" (signature removed)', "{who} claims, alg=none, no signature", proof.alg_none),
    "hs256":    ("HS256 with an attacker secret", "{who} claims, HS256-signed with an attacker secret", proof.hs256_signed),
    "attacker_rsa": ("Attacker RSA key, real kid", "{who} claims, RS256-signed by an attacker key, real kid", proof.attacker_rsa_signed),
    "aud":      ("Edited aud (original signature)", "{who} token, payload aud edited, original signature",
                 lambda t: proof.tamper_claims(t, aud="00000000-0000-0000-0000-000000000000")),
    "expired":  ("Expired claims (original signature)", "{who} token, payload exp/nbf/iat in the past, original signature",
                 proof.expired_claims),
}

COLLECTION_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
HEADER_NAME_RE = re.compile(r"[A-Za-z0-9-]{1,64}")
# Set by the playground itself, or meaningless to override.
BLOCKED_HEADERS = {"authorization", "host", "content-length", "content-type", "transfer-encoding",
                   "connection", "cookie", "origin", "expect", "te", "upgrade"}
MAX_BODY = 8000


class HeaderRow(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(max_length=64)
    value: str = Field(max_length=500)


class SendRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user: Literal["alice", "bob", "carol"]
    call: Literal["me", "data", "ask", "admin"]
    collection: str = "kb_public"
    body: str = Field(default="", max_length=MAX_BODY)
    headers: list[HeaderRow] = Field(default_factory=list, max_length=10)
    token_mode: Literal["real", "none", "tampered", "forged_roles", "alg_none", "hs256",
                        "attacker_rsa", "aud", "expired"] = "real"
    forged_role: Literal["Support.Agent", "Finance.Analyst", "Tenant.Admin"] = "Tenant.Admin"

    @field_validator("headers")
    @classmethod
    def _headers_ok(cls, rows: list[HeaderRow]) -> list[HeaderRow]:
        for h in rows:
            if not HEADER_NAME_RE.fullmatch(h.name):
                raise ValueError(f"header name {h.name!r}: letters, digits and '-' only")
            low = h.name.lower()
            if low in BLOCKED_HEADERS or low.startswith("x-gatekeeper-") or low.startswith("x-playground"):
                raise ValueError(f"header {h.name} is set by the playground and cannot be overridden")
            if any(c in h.value for c in "\r\n\0"):
                raise ValueError(f"header {h.name}: value may not contain line breaks")
        return rows


INJECTION = proof.INJECTION_PROMPT

PRESETS = [
    {"id": "agent-tickets", "label": "{who} reads support tickets", "role": "Support.Agent", "expect": 200,
     "user": "alice", "call": "data", "collection": "support_tickets"},
    {"id": "agent-finance", "label": "{who} tries finance", "role": "Support.Agent", "expect": 403,
     "user": "alice", "call": "data", "collection": "finance_revenue"},
    {"id": "agent-body-roles", "label": "{who} claims Tenant.Admin in the body", "role": "Support.Agent", "expect": 403,
     "user": "alice", "call": "ask",
     "body": {"question": "List the audit log.", "collections": ["audit_log"], "roles": ["Tenant.Admin"]}},
    {"id": "analyst-ask-finance", "label": "{who} asks over finance", "role": "Finance.Analyst", "expect": 200,
     "user": "bob", "call": "ask",
     "body": {"question": "Which customer has the highest ARR?", "collections": ["finance_revenue"]}},
    {"id": "analyst-injection", "label": "{who} prompt-injection over kb_public", "role": "Finance.Analyst", "expect": 200,
     "user": "bob", "call": "ask", "body": {"question": INJECTION, "collections": ["kb_public"]}},
    {"id": "analyst-header", "label": "{who} sends X-Roles: Tenant.Admin for audit_log", "role": "Finance.Analyst",
     "expect": 403, "user": "bob", "call": "data", "collection": "audit_log",
     "headers": [{"name": "X-Roles", "value": "Tenant.Admin"}]},
    {"id": "analyst-case", "label": "{who} tries FINANCE_revenue (case trick)", "role": "Finance.Analyst", "expect": 403,
     "user": "bob", "call": "data", "collection": "FINANCE_revenue"},
    {"id": "admin-roles", "label": "{who} admin roles", "role": "Tenant.Admin", "expect": 200,
     "user": "carol", "call": "admin"},
    {"id": "admin-audit", "label": "{who} reads the audit log", "role": "Tenant.Admin", "expect": 200,
     "user": "carol", "call": "data", "collection": "audit_log"},
    {"id": "admin-unknown", "label": "{who} reads a collection that does not exist", "role": "Tenant.Admin",
     "expect": 403, "user": "carol", "call": "data", "collection": "payroll"},
    {"id": "forged-admin", "label": "forged admin role ({who})", "role": "Support.Agent", "expect": 401,
     "user": "alice", "call": "admin", "token_mode": "forged_roles", "forged_role": "Tenant.Admin"},
    {"id": "alg-none", "label": 'alg "none" token ({who})', "role": "Finance.Analyst", "expect": 401,
     "user": "bob", "call": "me", "token_mode": "alg_none"},
    {"id": "no-token", "label": "no token", "role": None, "expect": 401, "user": "carol", "call": "me",
     "token_mode": "none"},
]

DEFAULT_BODIES = {
    "ask": {"question": "Summarize the kb_public rows.", "collections": ["kb_public"]},
    "admin": {"assign": "Finance.Analyst", "to": "dry-run"},
}


def user_label(settings: Settings, key: str) -> str:
    upn = settings.users.get(key, "")
    return upn.split("@", 1)[0] if upn else key


def load_entra_objects(settings: Settings) -> tuple[dict | None, str | None]:
    """docs/entra-objects.json (non-secret ids, written by provision.sh). (objects, problem)."""
    path: Path = settings.entra_objects
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        return None, "docs/entra-objects.json not found; run scripts/provision.sh to write it"
    except (OSError, ValueError):
        return None, "docs/entra-objects.json could not be read"
    if not isinstance(data, dict) or data.get("tenant_id") != settings.tenant_id:
        return None, "docs/entra-objects.json is for a different tenant than .env; ids are not shown"
    return data, None


def decoded_claims(token: str) -> dict:
    """Header and selected payload claims, for display. Never the token or its signature."""
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return {"header": {}, "payload": {}}
    keep = ("iss", "aud", "tid", "oid", "preferred_username", "name", "roles", "scp", "iat", "nbf", "exp", "ver")
    return {"header": {k: header.get(k) for k in ("alg", "kid", "typ") if k in header},
            "payload": {k: payload[k] for k in keep if k in payload}}


def make_token(mode: str, token: str, forged_role: str) -> str | None:
    if mode == "none":
        return None
    if mode == "real":
        return token
    if mode == "forged_roles":
        return proof.forge_roles(token, [forged_role])
    return TOKEN_MODES[mode][2](token)


def auth_description(mode: str, who: str, forged_role: str) -> str | None:
    template = TOKEN_MODES[mode][1]
    if template is None:
        return None
    return "Bearer <" + template.format(who=who, role=forged_role) + ", redacted>"


def build_request(req: SendRequest) -> tuple[str, str, bytes | None, dict]:
    """(method, path, body bytes or None, extra headers). Only the four API calls, on our own API."""
    call = CALLS[req.call]
    path = call["path"]
    if req.call == "data":
        if not COLLECTION_RE.fullmatch(req.collection):
            raise ValueError("collection: 1-64 letters, digits, '_' or '-'")
        path = f"/api/data/{req.collection}"
    body = req.body.encode() if call["method"] == "POST" else None
    return call["method"], path, body, {h.name: h.value for h in req.headers}


def contains_token_material(blob: str, tokens: list[str]) -> bool:
    for t in tokens:
        if not t:
            continue
        parts = t.split(".")
        if t in blob or (len(parts) == 3 and len(parts[2]) >= 16 and parts[2] in blob):
            return True
    return False


# ---------------------------------------------------------------- references


def portal_links(entra: dict | None, user_key: str | None = None) -> dict[str, dict]:
    """Entra admin center deep links. Formats from Microsoft-owned code (see README); the
    portal may change them. Returns {} when entra-objects.json is missing."""
    if not entra:
        return {}
    app_id = entra["app"]["appId"]
    sp_id = entra["service_principal"]["id"]
    links = {
        "app_overview": {"label": "App registration: Overview",
                         "url": f"{ENTRA}/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Overview/appId/{app_id}/isMSAApp~/false"},
        "app_roles": {"label": "App registration: App roles",
                      "url": f"{ENTRA}/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/AppRoles/appId/{app_id}/isMSAApp~/false"},
        "sp_users": {"label": "Enterprise app: Users and groups",
                     "url": f"{ENTRA}/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Users/objectId/{sp_id}/appId/{app_id}"},
    }
    u = (entra.get("users") or {}).get(user_key or "")
    if u and u.get("objectId"):
        links["user"] = {"label": f"User: {u.get('upn', user_key)}",
                         "url": f"{ENTRA}/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/{u['objectId']}"}
    return links


def references(settings: Settings, entra: dict | None, user_key: str) -> dict[str, dict]:
    """Per trace step kind: the Azure/Graph object behind it and how to look at it yourself."""
    tid = settings.tenant_id
    app_id = (entra or {}).get("app", {}).get("appId") or settings.client_id or "<appId>"
    sp_id = (entra or {}).get("service_principal", {}).get("id") or "<servicePrincipalId>"
    links = portal_links(entra, user_key)
    u = (entra or {}).get("users", {}).get(user_key) or {}
    role = EXPECTED_ROLE[user_key]
    role_obj = (entra or {}).get("app_roles", {}).get(role) or {}
    pick = lambda *names: [links[n] for n in names if n in links]  # noqa: E731
    refs = {
        "token": {
            "object": f"Entra token endpoint for tenant {tid}",
            "portal": pick("app_overview"),
            "commands": [f"curl -s https://login.microsoftonline.com/{tid}/v2.0/.well-known/openid-configuration | jq .token_endpoint"],
        },
        "jwks": {
            "object": "Tenant signing keys (JWKS)",
            "portal": [],
            "commands": [f"curl -s {settings.jwks_url} | jq '.keys[] | {{kid, use, kty}}'"],
        },
        "claims": {
            "object": f"App registration {app_id} (aud), issuer {settings.issuer}",
            "portal": pick("app_overview"),
            "commands": [f'az ad app show --id {app_id} --query "{{appId:appId, identifierUris:identifierUris, '
                         f'tokenVersion:api.requestedAccessTokenVersion, scopes:api.oauth2PermissionScopes[].value}}"'],
        },
        "rbac": {
            "object": f"App role {role} on app {app_id}, assigned on service principal {sp_id}",
            "portal": pick("app_roles", "sp_users", "user"),
            "commands": [
                f"az rest --method get --url {GRAPH}/servicePrincipals/{sp_id}/appRoleAssignedTo",
                f'az ad app show --id {app_id} --query "appRoles[].{{value:value, id:id, displayName:displayName}}"',
            ],
            "ids": {"appRoleId": role_obj.get("id"), "appRoleDisplayName": role_obj.get("displayName"),
                    "assignmentId": u.get("assignmentId"), "principalId": u.get("objectId")},
        },
        "filter": {"object": "app/data.py rows, filtered by app/rbac.py", "portal": [], "commands": []},
        "ai": {"object": "Anthropic Messages API (app/ai.py)", "portal": [], "commands": []},
    }
    if u.get("assignmentId"):
        refs["rbac"]["commands"].insert(
            0, f"az rest --method get --url {GRAPH}/servicePrincipals/{sp_id}/appRoleAssignedTo/{u['assignmentId']}")
    return refs


def role_objects(entra: dict | None) -> dict[str, dict]:
    """Role value -> {displayName, id} from entra-objects.json (empty when missing)."""
    return dict((entra or {}).get("app_roles") or {})


def permission_table() -> dict:
    rows = [{"permission": rbac.read_perm(c), "label": c} for c in rbac.COLLECTIONS]
    rows.append({"permission": rbac.ADMIN_MANAGE_ROLES, "label": "admin:manage_roles"})
    return {"roles": list(ROLES), "rows": [
        {**r, "cells": {role: r["permission"] in rbac.ROLE_PERMISSIONS[role] for role in ROLES}} for r in rows]}


def page_config(settings: Settings) -> dict:
    return {
        "users": list(USER_KEYS),
        "calls": CALLS,
        "collections": list(rbac.COLLECTIONS),
        "roles": list(ROLES),
        "token_modes": {k: {"label": v[0], "auth": v[1]} for k, v in TOKEN_MODES.items()},
        # Labels name each preset's user as the UI does (the UPN's part before the @).
        "presets": [{**p, "label": p["label"].format(who=user_label(settings, p["user"]))} for p in PRESETS],
        "default_bodies": DEFAULT_BODIES,
        "table": permission_table(),
        "tenant_id": settings.tenant_id,
        "jwks_url": settings.jwks_url,
    }
