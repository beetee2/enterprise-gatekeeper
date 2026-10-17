"""FastAPI app: Entra-protected API, sign-in bridge, the /proof page and the /playground."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.concurrency import run_in_threadpool
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import ai, auth, playground, proof, rbac, trace
from .config import EXPECTED_ROLE, USER_KEYS, Settings, load_settings
from .data import rows_in

HERE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=HERE / "templates")

# DNS rebinding defence: only these Host headers are served (any port).
ALLOWED_HOSTS = ["localhost", "127.0.0.1"]


def allowed_origins(settings: Settings) -> set[str]:
    """Origins allowed to POST /proof/run: this app's own, port taken from the redirect URI."""
    u = urlsplit(settings.redirect_uri)
    port = u.port or (443 if u.scheme == "https" else 80)
    return {f"{u.scheme}://{host}:{port}" for host in ALLOWED_HOSTS}


class AskRequest(BaseModel):
    # Extra fields (e.g. a smuggled "roles") are ignored, never read.
    model_config = ConfigDict(extra="ignore")
    question: str = Field(min_length=1, max_length=2000)
    collections: list[str] = Field(min_length=1, max_length=len(rbac.COLLECTIONS))


def create_app(settings: Settings | None = None, token_provider: proof.TokenProvider | None = None) -> FastAPI:
    settings = settings or load_settings()
    token_provider = token_provider or (lambda key: auth.get_access_token(settings, key))

    app = FastAPI(title="Gatekeeper AI", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret,
        session_cookie="gk_session",
        max_age=600,  # only holds the in-flight sign-in flow
        same_site="lax",
        https_only=False,  # localhost over http
    )
    # Trace collection: only for requests that carry this process's random key (see trace.py).
    trace_key = trace.new_key()
    app.state.traces = trace.TraceStore()
    app.add_middleware(trace.TraceMiddleware, key=trace_key, store=app.state.traces)
    # Added last = runs first: a request with a foreign Host header is rejected before anything else.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    app.state.settings = settings
    app.state.started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    # How /playground/send reaches this API. Tests swap in an in-process client.
    app.state.api_client = lambda base: httpx.Client(base_url=base, timeout=120)
    origins = allowed_origins(settings)

    # ------------------------------------------------------------ API auth

    def require_principal(request: Request) -> auth.Principal:
        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            trace.add("auth_header", present=bool(header), ok=False, error="missing bearer token")
            raise HTTPException(401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
        trace.add("auth_header", present=True, ok=True, scheme="Bearer")
        try:
            return auth.validate_access_token(token.strip(), settings)
        except auth.TokenError as e:
            raise HTTPException(
                401, f"invalid token: {e}", headers={"WWW-Authenticate": 'Bearer error="invalid_token"'}
            ) from None

    # ------------------------------------------------------------ API

    @app.get("/api/me")
    def me(p: auth.Principal = Depends(require_principal)):
        trace.add("decision", status=200, why="any valid token may read its own identity; no permission needed")
        return {"oid": p.oid, "preferred_username": p.preferred_username, "upn": p.upn,
                "tid": p.tid, "roles": list(p.roles)}

    @app.get("/api/data/{collection}")
    def read_collection(collection: str, p: auth.Principal = Depends(require_principal)):
        if not rbac.can_read(p.roles, collection):
            trace.add("decision", status=403, why=f"no role in the token grants read:{collection}")
            return JSONResponse({"denied": [collection]}, status_code=403)
        rows = rows_in([collection])
        if trace.active():
            trace.add("decision", status=200, why=f"read:{collection} granted")
            trace.add("filter", requested=[collection], passed={collection: [r["id"] for r in rows]},
                      excluded={c: "not requested" for c in rbac.COLLECTIONS if c != collection})
        return {"collection": collection, "rows": rows}

    @app.post("/api/ask")
    async def ask(request: Request, p: auth.Principal = Depends(require_principal)):
        # Body is parsed after authentication so unauthenticated callers always get 401.
        try:
            req = AskRequest.model_validate(await request.json())
        except (ValueError, ValidationError):
            return JSONResponse({"detail": "body must be {question: str, collections: [str]}"}, status_code=400)
        requested = list(dict.fromkeys(req.collections))
        denied = [c for c in requested if not rbac.can_read(p.roles, c)]
        if denied:
            trace.add("decision", status=403, denied=denied,
                      why="strict: any requested collection the token's roles cannot read denies the whole ask")
            return JSONResponse({"denied": denied}, status_code=403)
        # Retrieval: only permitted collections, filtered again row by row, BEFORE the model.
        permitted = rbac.readable_collections(p.roles)
        rows = [r for r in rows_in(requested) if r["collection"] in permitted]
        used = {"collections_used": sorted({r["collection"] for r in rows}), "row_ids": [r["id"] for r in rows]}
        if trace.active():
            trace.add("decision", status=200, why="every requested collection is readable")
            passed: dict[str, list[str]] = {}
            for r in rows:
                passed.setdefault(r["collection"], []).append(r["id"])
            trace.add("filter", requested=requested, permitted=sorted(permitted, key=rbac.COLLECTIONS.index),
                      passed=passed, excluded={c: ("not permitted" if c not in permitted else "not requested")
                                               for c in rbac.COLLECTIONS if c not in passed})
            trace.add("ai_call", model=ai.MODEL, effort=ai.EFFORT, rows_sent=len(rows),
                      collections=sorted(passed, key=rbac.COLLECTIONS.index))
        try:
            text = await run_in_threadpool(ai.answer, settings, req.question, rows)
        except ai.AINotConfigured as e:
            return JSONResponse({"detail": str(e), **used}, status_code=503)
        except ai.AIError as e:
            return JSONResponse({"detail": str(e), **used}, status_code=502)
        return {"answer": text, **used}

    @app.post("/api/admin/roles")
    def admin_roles(p: auth.Principal = Depends(require_principal)):
        if not rbac.can(p.roles, rbac.ADMIN_MANAGE_ROLES):
            trace.add("decision", status=403, why=f"no role in the token grants {rbac.ADMIN_MANAGE_ROLES}")
            return JSONResponse({"denied": [rbac.ADMIN_MANAGE_ROLES]}, status_code=403)
        trace.add("decision", status=200, why=f"{rbac.ADMIN_MANAGE_ROLES} granted; dry run, nothing changes")
        return {"dry_run": True, "message": "Dry run: you may manage roles. No role assignment was changed."}

    # ------------------------------------------------------------ sign-in

    @app.get("/auth/login")
    def login(request: Request, user: str = ""):
        if not settings.entra_configured:
            return _not_configured(request)
        if user not in USER_KEYS:
            raise HTTPException(400, "user must be alice, bob or carol")
        flow = auth.start_sign_in(settings, user)
        request.session["auth_flow"] = {"user": user, "flow": flow}
        return RedirectResponse(flow["auth_uri"], status_code=302)

    @app.get("/auth/callback")
    def callback(request: Request):
        if not settings.entra_configured:
            return _not_configured(request)
        pending = request.session.pop("auth_flow", None)
        if not pending or pending.get("user") not in USER_KEYS:
            return _message(request, "Sign-in failed", "No sign-in in progress (or it expired). Start again from /proof.", 400)
        try:
            auth.finish_sign_in(settings, pending["user"], pending["flow"], dict(request.query_params))
        except auth.SignInError as e:
            return _message(request, "Sign-in rejected", str(e), 403)
        return RedirectResponse("/proof", status_code=302)

    # ------------------------------------------------------------ pages

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        return templates.TemplateResponse(request, "index.html", {"s": settings})

    @app.get("/proof", response_class=HTMLResponse)
    def proof_page(request: Request):
        cards = []
        for key in USER_KEYS:
            card = {"key": key, "upn": settings.users.get(key, ""), "expected_role": EXPECTED_ROLE[key],
                    "signed_in": False, "roles": None, "problem": None}
            if settings.entra_configured:
                token, problem = token_provider(key)
                if token:
                    try:
                        p = auth.validate_access_token(token, settings)
                        card.update(signed_in=True, roles=list(p.roles))
                    except auth.TokenError as e:
                        card["problem"] = f"token failed validation: {e}"
                else:
                    card["problem"] = problem
            cards.append(card)
        result = proof.read_result(settings.proof_output) if settings.entra_configured else None
        return templates.TemplateResponse(request, "proof.html", {"s": settings, "cards": cards, "result": result})

    @app.post("/proof/run")
    def proof_run(request: Request):
        # Custom header => a cross-site page cannot trigger a run without a CORS preflight we never allow.
        if request.headers.get("x-proof-run") != "1":
            raise HTTPException(400, "missing X-Proof-Run header")
        # Browsers always send Origin on a POST fetch; a missing or foreign one is refused.
        if request.headers.get("origin") not in origins:
            raise HTTPException(403, "Origin not allowed")
        if not settings.entra_configured:
            return JSONResponse({"detail": "not configured — run scripts/provision.sh"}, status_code=503)
        # Call our own listening socket, never a URL built from the Host header.
        port = (request.scope.get("server") or ("127.0.0.1", 8000))[1]
        api_base = f"http://127.0.0.1:{port}"
        with httpx.Client(base_url=api_base, timeout=120) as client:
            result = proof.run_proof(settings, client, token_provider, api_base, app.state.started_at)
        proof.write_result(settings.proof_output, result)
        return result

    # ------------------------------------------------------------ playground

    @app.get("/playground", response_class=HTMLResponse)
    def playground_page(request: Request):
        entra, entra_problem = playground.load_entra_objects(settings)
        users = []
        for key in USER_KEYS:
            u = {"key": key, "upn": settings.users.get(key, ""), "label": playground.user_label(settings, key),
                 "expected_role": EXPECTED_ROLE[key], "signed_in": False, "roles": None, "problem": None,
                 "claims": None, "links": playground.portal_links(entra, key)}
            if settings.entra_configured:
                token, problem = token_provider(key)
                if token:
                    u["claims"] = playground.decoded_claims(token)  # never the token itself
                    try:
                        u.update(signed_in=True, roles=list(auth.validate_access_token(token, settings).roles))
                    except auth.TokenError as e:
                        u["problem"] = f"token failed validation: {e}"
                else:
                    u["problem"] = problem
            users.append(u)
        data = {**playground.page_config(settings), "user_cards": users, "entra_problem": entra_problem,
                "role_objects": playground.role_objects(entra), "configured": settings.entra_configured}
        return templates.TemplateResponse(request, "playground.html", {"s": settings, "users": users, "data": data,
                                                                       "entra_problem": entra_problem})

    @app.post("/playground/send")
    async def playground_send(request: Request):
        # Same guards as /proof/run: custom header (forces a CORS preflight we never allow) and Origin.
        if request.headers.get("x-playground-send") != "1":
            raise HTTPException(400, "missing X-Playground-Send header")
        if request.headers.get("origin") not in origins:
            raise HTTPException(403, "Origin not allowed")
        if not settings.entra_configured:
            return JSONResponse({"detail": "not configured — run scripts/provision.sh"}, status_code=503)
        try:
            req = playground.SendRequest.model_validate(await request.json())
            method, path, body, extra = playground.build_request(req)
        except ValidationError as e:
            msgs = "; ".join(f"{'.'.join(str(x) for x in err['loc']) or 'body'}: {err['msg']}" for err in e.errors())
            return JSONResponse({"detail": msgs}, status_code=400)
        except ValueError as e:
            return JSONResponse({"detail": str(e) or "body must be JSON"}, status_code=400)
        port = (request.scope.get("server") or ("127.0.0.1", 8000))[1]
        return await run_in_threadpool(_playground_call, req, method, path, body, extra, f"http://127.0.0.1:{port}")

    def _playground_call(req, method, path, body, extra, api_base):
        who = playground.user_label(settings, req.user)
        token = None
        with trace.collect() as token_steps:
            if req.token_mode != "none":
                token, problem = token_provider(req.user)
                if not token:
                    return JSONResponse({"detail": f"{settings.users.get(req.user) or who} has no token ({problem}). "
                                                   "Sign in, or pick token mode 'No token'."}, status_code=409)
        if req.token_mode == "none":
            token_steps.append({"kind": "token", "source": "none", "note": "token mode 'No token': no Authorization header"})
        elif not token_steps:
            token_steps.append({"kind": "token", "source": "injected token provider (fake tenant or tests): no MSAL call"})
        sent = playground.make_token(req.token_mode, token, req.forged_role) if token else None
        if req.token_mode not in ("real", "none"):
            token_steps.append({"kind": "forge", "mode": req.token_mode,
                                "label": playground.TOKEN_MODES[req.token_mode][0],
                                **({"forged_roles": [req.forged_role]} if req.token_mode == "forged_roles" else {}),
                                **({"note": "no change: the edited token is byte-identical to the real one "
                                            "(the claim already had this value), so its signature still verifies"}
                                   if sent == token else {})})

        headers = dict(extra)
        if body is not None:
            headers["Content-Type"] = "application/json"
        trace_id = trace.new_id()
        internal = {trace.TRACE_HEADER: "1", trace.KEY_HEADER: trace_key, trace.ID_HEADER: trace_id}
        auth_header = {"Authorization": f"Bearer {sent}"} if sent else {}
        started = time.monotonic()
        with app.state.api_client(api_base) as client:
            resp = client.request(method, path, headers={**headers, **auth_header, **internal}, content=body)
        elapsed_ms = round((time.monotonic() - started) * 1000)
        api_steps = app.state.traces.pop(trace_id) or [{"kind": "error", "error": "no trace was captured"}]
        try:
            resp_body = resp.json()
        except ValueError:
            resp_body = resp.text[:20000]
        shown = [[k, v] for k, v in headers.items()]
        desc = playground.auth_description(req.token_mode, who, req.forged_role)
        if desc:
            shown.insert(0, ["Authorization", desc])
        result = {
            "request": {"method": method, "path": path, "headers": shown,
                        "body": body.decode() if body is not None else None,
                        "user": req.user, "user_label": who, "call": req.call, "token_mode": req.token_mode},
            "response": {"status": resp.status_code, "elapsed_ms": elapsed_ms, "body": resp_body,
                         "headers": {k: v for k, v in resp.headers.items()
                                     if k.lower() in ("content-type", "www-authenticate")}},
            "trace": token_steps + api_steps,
            "refs": playground.references(settings, playground.load_entra_objects(settings)[0], req.user),
        }
        # Belt and braces: nothing that looks like a token (or its signature) leaves the server.
        if playground.contains_token_material(json.dumps(result, ensure_ascii=False), [token or "", sent or ""]):
            return JSONResponse({"detail": "result withheld: it contained token material"}, status_code=500)
        return result

    def _not_configured(request: Request):
        return _message(request, "Not configured", "Entra ID is not configured — run scripts/provision.sh.", 503)

    def _message(request: Request, title: str, text: str, status: int):
        return templates.TemplateResponse(request, "message.html", {"title": title, "text": text}, status_code=status)

    return app


app = create_app()
