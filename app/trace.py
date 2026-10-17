"""Request-scoped trace for /playground: what the real code path did, step by step.

Off by default. auth.py, rbac.py, main.py and ai.py call `add()`, which does nothing
unless a trace is being collected. The API turns collection on only when a request
carries `X-Gatekeeper-Trace: 1` plus this process's random key (`X-Gatekeeper-Trace-Key`),
which only /playground/send knows. The trace is never put in the API response: it is
kept in memory under the caller's trace id, and /playground/send collects it from there.

Steps hold claim values, key ids, role names and row ids only: never a token, a
signature, a secret, a refresh token or row contents.
"""

from __future__ import annotations

import json
import re
import secrets
import threading
from collections import OrderedDict
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from urllib.parse import parse_qsl

TRACE_HEADER = "x-gatekeeper-trace"
KEY_HEADER = "x-gatekeeper-trace-key"
ID_HEADER = "x-gatekeeper-trace-id"
_ID_RE = re.compile(r"[0-9a-f]{32}")
MAX_BODY_SCAN = 64 * 1024
MAX_VALUE = 200

_steps: ContextVar[list[dict] | None] = ContextVar("gk_trace", default=None)


def active() -> bool:
    return _steps.get() is not None


def add(kind: str, **data) -> None:
    steps = _steps.get()
    if steps is not None:
        steps.append({"kind": kind, **data})


@contextmanager
def collect() -> Iterator[list[dict]]:
    steps: list[dict] = []
    token = _steps.set(steps)
    try:
        yield steps
    finally:
        _steps.reset(token)


def short(value, limit: int = MAX_VALUE):
    """Claim values come from the (possibly forged) token: keep them JSON-safe and short."""
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit] + "…"
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [short(v, limit) for v in value[:20]]
    if isinstance(value, dict):
        return {str(k)[:64]: short(v, limit) for k, v in list(value.items())[:20]}
    return short(str(value), limit)


class TraceStore:
    """Finished traces by id, until /playground/send picks them up. Bounded."""

    def __init__(self, max_items: int = 32) -> None:
        self._items: OrderedDict[str, list[dict]] = OrderedDict()
        self._max = max_items
        self._lock = threading.Lock()

    def put(self, trace_id: str, steps: list[dict]) -> None:
        with self._lock:
            self._items[trace_id] = steps
            while len(self._items) > self._max:
                self._items.popitem(last=False)

    def pop(self, trace_id: str) -> list[dict] | None:
        with self._lock:
            return self._items.pop(trace_id, None)

    def __len__(self) -> int:
        return len(self._items)


def new_key() -> str:
    return secrets.token_urlsafe(32)


def new_id() -> str:
    return secrets.token_hex(16)


def _role_hints(headers: list[tuple[bytes, bytes]], query: bytes, body: bytes) -> list[dict]:
    """Places a caller tried to state a role. The server never reads them; the trace says so."""
    found = []
    for name, value in headers:
        n = name.decode("latin-1")
        if "role" in n.lower():
            found.append({"where": "header", "name": n, "value": short(value.decode("latin-1"), 100)})
    for k, v in parse_qsl(query.decode("latin-1"), keep_blank_values=True):
        if "role" in k.lower():
            found.append({"where": "query", "name": k, "value": short(v, 100)})
    try:
        data = json.loads(body) if body else None
    except ValueError:
        data = None
    if isinstance(data, dict):
        for k, v in data.items():
            if "role" in str(k).lower():
                found.append({"where": "body", "name": str(k), "value": short(v, 100)})
        q = data.get("question")
        if isinstance(q, str):
            hits = [w for w in ("Tenant.Admin", "Finance.Analyst", "Support.Agent", "admin") if w.lower() in q.lower()]
            if hits:
                found.append({"where": "prompt text", "name": "question", "value": "mentions " + ", ".join(hits)})
    return found


class TraceMiddleware:
    """Pure ASGI. Collects a trace only for requests that carry the trace header AND this
    process's key AND a well-formed trace id; every other request passes through untouched."""

    def __init__(self, app, key: str, store: TraceStore) -> None:
        self.app = app
        self.key = key.encode()
        self.store = store

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        trace_id = headers.get(ID_HEADER.encode(), b"").decode("latin-1")
        if (headers.get(TRACE_HEADER.encode()) != b"1"
                or not secrets.compare_digest(headers.get(KEY_HEADER.encode(), b""), self.key)
                or not _ID_RE.fullmatch(trace_id)):
            return await self.app(scope, receive, send)

        # Buffer the body once so the role-hint scan can read it, then replay it to the app.
        chunks, more = [], True
        while more:
            msg = await receive()
            if msg["type"] != "http.request":
                break
            chunks.append(msg.get("body", b""))
            more = msg.get("more_body", False)
        body = b"".join(chunks)
        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        status = {}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
            await send(message)

        with collect() as steps:
            add("request", method=scope["method"], path=scope["path"])
            hints = _role_hints(scope.get("headers", []), scope.get("query_string", b""), body[:MAX_BODY_SCAN])
            if hints:
                add("role_hints", found=hints,
                    note="Present in the request and never read: roles come only from the validated token's roles claim.")
            try:
                await self.app(scope, replay, send_wrapper)
            finally:
                add("response", status=status.get("code"))
                self.store.put(trace_id, steps)
