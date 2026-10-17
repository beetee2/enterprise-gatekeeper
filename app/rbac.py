"""The permission model. This file is the only source of truth for who may do what.

Roles come ONLY from the validated access token's `roles` claim (see auth.py).
Unknown roles grant nothing; no role grants nothing (deny by default).
"""

from __future__ import annotations

from collections.abc import Iterable

from . import trace

COLLECTIONS = ("kb_public", "support_tickets", "finance_revenue", "audit_log")
ADMIN_MANAGE_ROLES = "admin:manage_roles"


def read_perm(collection: str) -> str:
    return f"read:{collection}"


ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "Support.Agent": frozenset({read_perm("kb_public"), read_perm("support_tickets")}),
    "Finance.Analyst": frozenset({read_perm("kb_public"), read_perm("finance_revenue")}),
    "Tenant.Admin": frozenset({*(read_perm(c) for c in COLLECTIONS), ADMIN_MANAGE_ROLES}),
}


def permissions_for(roles: Iterable[str]) -> frozenset[str]:
    perms: set[str] = set()
    for role in roles:
        perms |= ROLE_PERMISSIONS.get(role, frozenset())
    return frozenset(perms)


def can(roles: Iterable[str], permission: str) -> bool:
    roles = list(roles)
    allowed = permission in permissions_for(roles)
    if trace.active():
        trace.add("rbac", permission=permission, token_roles=roles, allowed=allowed,
                  roles=[{"role": r, "known": r in ROLE_PERMISSIONS,
                          "grants": sorted(ROLE_PERMISSIONS.get(r, frozenset())),
                          "grants_this": permission in ROLE_PERMISSIONS.get(r, frozenset())} for r in roles],
                  why=_why(roles, permission, allowed))
    return allowed


def _why(roles: list[str], permission: str, allowed: bool) -> str:
    if allowed:
        by = [r for r in roles if permission in ROLE_PERMISSIONS.get(r, frozenset())]
        return f"{', '.join(by)} grants {permission}"
    if not roles:
        return "token has no roles claim: deny by default"
    unknown = [r for r in roles if r not in ROLE_PERMISSIONS]
    if permission.startswith("read:") and permission[5:] not in COLLECTIONS:
        return f"{permission[5:]!r} is not a collection, so no role grants it: deny by default"
    if unknown and len(unknown) == len(roles):
        return f"unknown role(s) {', '.join(unknown)} grant nothing: deny by default"
    return f"no role in {roles} grants {permission}"


def can_read(roles: Iterable[str], collection: str) -> bool:
    # An unknown collection has no read permission in any role, so it is denied.
    return can(roles, read_perm(collection))


def readable_collections(roles: Iterable[str]) -> frozenset[str]:
    perms = permissions_for(roles)
    readable = frozenset(c for c in COLLECTIONS if read_perm(c) in perms)
    trace.add("readable", collections=sorted(readable, key=COLLECTIONS.index))
    return readable
