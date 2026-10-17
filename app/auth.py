"""Entra ID: access-token validation (API side) and MSAL sign-in + token cache (proof side).

Never log or render a token. Error messages name the failed check, not the token.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import httpx
import jwt
import msal

from . import trace
from .config import Settings

ALLOWED_ALGS = ["RS256"]
CLOCK_SKEW_SECONDS = 60
JWKS_MIN_REFRESH_SECONDS = 300


class TokenError(Exception):
    """Any validation failure. The message is safe to return to the caller."""


class SignInError(Exception):
    """Sign-in callback failure. Nothing is stored when this is raised."""


@dataclass(frozen=True)
class Principal:
    oid: str
    preferred_username: str
    upn: str | None
    tid: str
    roles: tuple[str, ...]
    scopes: tuple[str, ...]


# ---------------------------------------------------------------- JWKS


def fetch_jwks(url: str) -> dict:
    """Fetch the tenant's signing keys. Tests monkeypatch this."""
    resp = httpx.get(url, timeout=10)
    resp.raise_for_status()
    return resp.json()


class JwksCache:
    def __init__(self) -> None:
        self._keys: dict[str, dict] = {}
        self._url = ""
        self._fetched_at = 0.0
        self._fetched_wall = ""
        self._lock = threading.Lock()

    def _refresh(self, url: str) -> None:
        jwks = fetch_jwks(url)
        self._keys = {k["kid"]: k for k in jwks.get("keys", []) if "kid" in k}
        self._url = url
        self._fetched_at = time.monotonic()
        self._fetched_wall = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def get(self, url: str, kid: str) -> dict:
        with self._lock:
            stale = url != self._url
            unknown_kid = kid not in self._keys
            recently = time.monotonic() - self._fetched_at < JWKS_MIN_REFRESH_SECONDS
            # Refetch on a new URL, or on an unknown kid (key rollover) at most every 5 minutes.
            fetch = stale or (unknown_kid and not recently)
            step = {"url": url, "kid": trace.short(kid, 100)}
            if fetch:
                step["source"] = "fetched"
                step["why"] = "first use of this JWKS URL" if stale else "kid not in cached keys (key rollover?)"
                try:
                    self._refresh(url)
                except httpx.HTTPError as e:
                    trace.add("jwks", **step, error=f"fetch failed: {type(e).__name__}")
                    raise
            else:
                step["source"] = "cached"
                step["why"] = ("kid not in cached keys, but the keys were fetched under "
                               f"{JWKS_MIN_REFRESH_SECONDS}s ago, so no refetch") if unknown_kid else "kid found in cached keys"
            key = self._keys.get(kid)
            trace.add("jwks", **step, fetched_at=self._fetched_wall, keys_in_set=sorted(self._keys),
                      kid_matched=key is not None)
        if key is None:
            raise TokenError("signing key not found in tenant JWKS")
        return key


_jwks = JwksCache()


def reset_jwks_cache() -> None:
    global _jwks
    _jwks = JwksCache()


# ---------------------------------------------------------------- validation


# PyJWT 2.x jwt.decode() order (api_jws, then api_jwt._validate_claims): signature,
# required claims, iat, nbf, exp, iss, aud. Our own checks (tid, scp) run after it.
CHECK_ORDER = ("alg", "kid", "signing key", "signature", "required claims",
               "exp/nbf/iat", "iss", "aud", "tid", "scp")
REQUIRED_CLAIMS = ["exp", "nbf", "iat", "iss", "aud", "tid", "oid"]
_DECODE_FAILS_AT = {  # which check failed, by the PyJWT exception jwt.decode() raised
    jwt.InvalidSignatureError: "signature",
    jwt.MissingRequiredClaimError: "required claims",
    jwt.ExpiredSignatureError: "exp/nbf/iat",
    jwt.ImmatureSignatureError: "exp/nbf/iat",
    jwt.InvalidIssuedAtError: "exp/nbf/iat",
    jwt.InvalidIssuerError: "iss",
    jwt.InvalidAudienceError: "aud",
}


class _ClaimTrace:
    """Records each validation check as validate_access_token runs it (trace on only)."""

    def __init__(self, token: str, settings: Settings) -> None:
        try:
            self.header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            self.header = {}
        try:
            self.claims = jwt.decode(token, options={"verify_signature": False})
        except jwt.PyJWTError:
            self.claims = {}
        self.s = settings
        self.checks: list[dict] = []

    def _add(self, name: str, result: str, expected, actual) -> None:
        self.checks.append({"check": name, "result": result,
                            "expected": expected, "actual": trace.short(actual)})

    def expected(self, name: str):
        s = self.s
        now = int(time.time())
        return {
            "alg": f"one of {ALLOWED_ALGS}",
            "kid": "a key id in the header",
            "signing key": f"kid present in {s.jwks_url}",
            "signature": "RS256 signature verifies with that JWKS key",
            "required claims": "all present: " + ", ".join(REQUIRED_CLAIMS),
            "exp/nbf/iat": f"nbf, iat <= now + {CLOCK_SKEW_SECONDS}s and exp > now - {CLOCK_SKEW_SECONDS}s (now {now})",
            "iss": s.issuer,
            "aud": s.client_id,
            "tid": s.tenant_id,
            "scp": f"contains {s.scope_name}",
        }[name]

    def actual(self, name: str):
        c, h = self.claims, self.header
        return {
            "alg": h.get("alg"),
            "kid": h.get("kid"),
            "signing key": h.get("kid"),
            "signature": f"signed for kid {h.get('kid')}",
            "required claims": "present: " + ", ".join(k for k in REQUIRED_CLAIMS if k in c),
            "exp/nbf/iat": {k: c.get(k) for k in ("nbf", "iat", "exp")},
            "iss": c.get("iss"),
            "aud": c.get("aud"),
            "tid": c.get("tid"),
            "scp": c.get("scp"),
        }[name]

    def ok(self, *names: str) -> None:
        for n in names:
            self._add(n, "pass", self.expected(n), self.actual(n))

    def fail(self, name: str, actual=None) -> None:
        self._add(name, "fail", self.expected(name), actual if actual is not None else self.actual(name))

    def decode_failed(self, exc: Exception) -> None:
        failed = next((n for cls, n in _DECODE_FAILS_AT.items() if isinstance(exc, cls)), None)
        if failed is None:  # anything else PyJWT raised: the first check not yet passed
            failed = next(n for n in CHECK_ORDER if n not in {c["check"] for c in self.checks})
            self.fail(failed, f"jwt.decode raised {type(exc).__name__}")
            return
        start = CHECK_ORDER.index("signature")
        self.ok(*[n for n in CHECK_ORDER[start:CHECK_ORDER.index(failed)]])
        extra = f"missing {exc.claim}" if isinstance(exc, jwt.MissingRequiredClaimError) else None
        self.fail(failed, extra)

    def finish(self, error: str | None) -> None:
        done = {c["check"] for c in self.checks}
        for n in CHECK_ORDER:
            if n not in done:
                self.checks.append({"check": n, "result": "not reached"})
        trace.add("claims", checks=self.checks, outcome="pass" if error is None else "fail",
                  error=error, header={k: trace.short(v, 100) for k, v in self.header.items()})


def validate_access_token(token: str, settings: Settings) -> Principal:
    tr = _ClaimTrace(token, settings) if trace.active() else None
    try:
        principal = _validate_access_token(token, settings, tr)
    except TokenError as e:
        if tr:
            tr.finish(str(e))
        raise
    if tr:
        tr.finish(None)
        trace.add("principal", oid=principal.oid, preferred_username=principal.preferred_username,
                  tid=principal.tid, roles=list(principal.roles), scopes=list(principal.scopes))
    return principal


def _validate_access_token(token: str, settings: Settings, tr: _ClaimTrace | None) -> Principal:
    if not settings.entra_configured:
        raise TokenError("server not configured; cannot validate tokens")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        if tr:
            tr.fail("alg", "header could not be decoded")
        raise TokenError("malformed token") from None
    if header.get("alg") not in ALLOWED_ALGS:
        if tr:
            tr.fail("alg")
        raise TokenError("unexpected signing algorithm")
    kid = header.get("kid")
    if not kid:
        if tr:
            tr.ok("alg")
            tr.fail("kid")
        raise TokenError("token has no key id")
    if tr:
        tr.ok("alg", "kid")
    try:
        jwk = _jwks.get(settings.jwks_url, kid)
    except httpx.HTTPError:
        if tr:
            tr.fail("signing key", "could not fetch the tenant JWKS")
        raise TokenError("could not fetch tenant signing keys") from None
    except TokenError:
        if tr:
            tr.fail("signing key", f"kid {kid} not in JWKS")
        raise
    if tr:
        tr.ok("signing key")
    try:
        key = jwt.PyJWK(jwk, algorithm="RS256").key
        claims = jwt.decode(
            token,
            key=key,
            algorithms=ALLOWED_ALGS,
            audience=settings.client_id,
            issuer=settings.issuer,
            leeway=CLOCK_SKEW_SECONDS,
            options={"require": REQUIRED_CLAIMS},
        )
    except jwt.PyJWTError as e:
        if tr:
            tr.decode_failed(e)
        if isinstance(e, jwt.InvalidSignatureError):
            raise TokenError("bad signature") from None
        if isinstance(e, jwt.ExpiredSignatureError):
            raise TokenError("token expired") from None
        if isinstance(e, jwt.ImmatureSignatureError):
            raise TokenError("token not yet valid") from None
        if isinstance(e, jwt.InvalidAudienceError):
            raise TokenError("wrong audience") from None
        if isinstance(e, jwt.InvalidIssuerError):
            raise TokenError("wrong issuer") from None
        if isinstance(e, jwt.MissingRequiredClaimError):
            raise TokenError(f"missing claim: {e.claim}") from None
        raise TokenError("invalid token") from None
    if tr:
        tr.ok("signature", "required claims", "exp/nbf/iat", "iss", "aud")

    if claims.get("tid") != settings.tenant_id:
        if tr:
            tr.fail("tid")
        raise TokenError("wrong tenant")
    if tr:
        tr.ok("tid")
    scopes = tuple(str(claims.get("scp", "")).split())
    if settings.scope_name not in scopes:
        if tr:
            tr.fail("scp")
        raise TokenError(f"missing scope {settings.scope_name}")
    if tr:
        tr.ok("scp")
    raw_roles = claims.get("roles", [])
    roles = tuple(r for r in raw_roles if isinstance(r, str)) if isinstance(raw_roles, list) else ()
    return Principal(
        oid=str(claims["oid"]),
        preferred_username=str(claims.get("preferred_username", "")),
        upn=claims.get("upn"),
        tid=str(claims["tid"]),
        roles=roles,
        scopes=scopes,
    )


# ---------------------------------------------------------------- MSAL sign-in


def msal_app(settings: Settings, cache: msal.SerializableTokenCache | None = None):
    return msal.ConfidentialClientApplication(
        client_id=settings.client_id,
        client_credential=settings.client_secret,
        authority=settings.authority,
        token_cache=cache,
    )


def cache_path(settings: Settings, user_key: str) -> Path:
    return settings.tokens_dir / f"{user_key}.json"


def load_cache(settings: Settings, user_key: str) -> msal.SerializableTokenCache:
    cache = msal.SerializableTokenCache()
    path = cache_path(settings, user_key)
    if path.exists():
        cache.deserialize(path.read_text())
    return cache


def save_cache(settings: Settings, user_key: str, cache: msal.SerializableTokenCache) -> None:
    """Atomic write, owner-only permissions."""
    settings.tokens_dir.mkdir(mode=0o700, exist_ok=True)
    os.chmod(settings.tokens_dir, 0o700)
    path = cache_path(settings, user_key)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(cache.serialize())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def start_sign_in(settings: Settings, user_key: str) -> dict:
    """Begin auth code + PKCE. Returns the MSAL flow (state, PKCE verifier, nonce, auth_uri)."""
    return msal_app(settings).initiate_auth_code_flow(
        scopes=[settings.api_scope],
        redirect_uri=settings.redirect_uri,
        login_hint=settings.users[user_key],
        prompt="login",
    )


def finish_sign_in(settings: Settings, user_key: str, flow: dict, auth_response: dict) -> str:
    """Redeem the code, verify the signed-in account is the expected user, then store the cache.

    Returns the signed-in UPN. Raises SignInError on any failure; nothing is stored then.
    """
    cache = msal.SerializableTokenCache()
    try:
        result = msal_app(settings, cache).acquire_token_by_auth_code_flow(flow, auth_response)
    except ValueError:  # state mismatch / replayed or forged callback
        raise SignInError("sign-in state did not match; start again") from None
    if "error" in result:
        # error_description from Entra is safe to show; it never contains tokens.
        raise SignInError(f"{result.get('error')}: {result.get('error_description', '')}".strip())
    id_claims = result.get("id_token_claims") or {}
    signed_in = str(id_claims.get("preferred_username", ""))
    expected = settings.users[user_key]
    if signed_in.casefold() != expected.casefold():
        raise SignInError(
            f"signed in as {signed_in or 'an unknown account'}, but this slot is for {expected}; nothing was stored"
        )
    if id_claims.get("tid") != settings.tenant_id:
        raise SignInError("signed in to the wrong tenant; nothing was stored")
    save_cache(settings, user_key, cache)
    return signed_in


def get_access_token(settings: Settings, user_key: str) -> tuple[str | None, str | None]:
    """Silent token for ENTRA_API_SCOPE from the user's cache. Returns (token, problem)."""
    if not settings.entra_configured:
        return None, "not configured"
    if not cache_path(settings, user_key).exists():
        trace.add("token", source="none", problem="not signed in", cache_file=f".tokens/{user_key}.json missing")
        return None, "not signed in"
    cache = load_cache(settings, user_key)
    app = msal_app(settings, cache)
    expected = settings.users[user_key].casefold()
    accounts = [a for a in app.get_accounts() if a.get("username", "").casefold() == expected]
    if not accounts:
        trace.add("token", source="none", problem="not signed in", account=settings.users[user_key])
        return None, "not signed in"
    result = app.acquire_token_silent([settings.api_scope], account=accounts[0])
    if trace.active():
        _trace_silent(settings, app, result or {}, user_key)
    if cache.has_state_changed:
        save_cache(settings, user_key, cache)
    if not result or "access_token" not in result:
        return None, "session expired; sign in again"
    return result["access_token"], None


def _trace_silent(settings: Settings, app, result: dict, user_key: str) -> None:
    """What acquire_token_silent did. Never the access token, refresh token or client secret."""
    source = result.get("token_source")  # MSAL sets "cache", "identity_provider" or "broker"
    expires_in = result.get("expires_in")
    step = {
        "account": settings.users[user_key],
        "msal_token_source": source,
        "source": {"cache": "MSAL cache hit (no network call)",
                   "identity_provider": "network refresh at Entra"}.get(source, source or "no token"),
        "scope": settings.api_scope,
        "client_id": settings.client_id,
        "cache_file": f".tokens/{user_key}.json",
    }
    if source == "identity_provider":
        try:
            step["token_endpoint"] = app.authority.token_endpoint
        except Exception:  # pragma: no cover - authority metadata is loaded by then
            step["token_endpoint"] = f"{settings.authority}/oauth2/v2.0/token"
        step["grant_type"] = "refresh_token"
        step["client_auth"] = "client_secret (not shown)"
    if isinstance(expires_in, int):
        step["expires_in_seconds"] = expires_in
        step["expires_at"] = datetime.fromtimestamp(time.time() + expires_in, timezone.utc).isoformat(timespec="seconds")
    if "error" in result:
        step["error"] = result.get("error")
    trace.add("token", **step)

