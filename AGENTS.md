# AGENTS.md

Guide for coding agents (and humans) working on this repo. Read [CONTRACT.md](CONTRACT.md) for the
spec and [README.md](README.md) for setup on a real tenant.

## Purpose

A FastAPI auth bridge that makes a sample AI app trust a real Microsoft Entra ID tenant: Entra v2
access tokens are validated against the tenant JWKS, the token's `roles` claim drives app-role RBAC,
and only permitted rows ever reach Claude. `/proof` grades the live server against the CONTRACT.md
permission table (42 checks, verdict PASS/INCOMPLETE/FAIL); `/playground` sends one real call at a
time and shows a trace of the real code path. It exists to pass the first gate of an enterprise
security review: SSO plus strict data isolation.

## Commands

```bash
uv sync                                         # setup (Python 3.12)
uv run pytest -q                                # 215 tests, fake tenant, no Azure, ~4 s
uv run uvicorn app.main:app --port 8000         # run (single worker, port 8000 only)
scripts/provision.sh --alice <upn> --bob <upn> --carol <upn>   # first run; later runs read .env
scripts/teardown.sh                             # destructive; a human runs it, never an agent
bash -n scripts/*.sh && uvx --from shellcheck-py shellcheck scripts/*.sh   # after any script edit
```

## Architecture

| File | Owns |
|---|---|
| `app/main.py` | `create_app(settings, token_provider)`: routes, TrustedHost, Origin and custom-header guards, the `/api/ask` row filter |
| `app/auth.py` | token validation (JWKS cache, claim checks in order), MSAL auth code + PKCE sign-in, per-user cache in `.tokens/` |
| `app/rbac.py` | `ROLE_PERMISSIONS`; the only code that grants access |
| `app/data.py` | sample rows, each with a unique canary |
| `app/ai.py` | the Claude call (`claude-haiku-5-5`, effort `high`) |
| `app/proof.py` | `/proof/run`: real HTTP calls per user, graded against `CONTRACT_TABLE`, canary leak scan, forged tokens |
| `app/playground.py` | presets, token modes, request building, token-material check, "Look it up yourself" references |
| `app/trace.py` | request-scoped trace and the middleware that enables it |
| `app/config.py` | `Settings`, read only from `.env`; fixed slot → role map (`EXPECTED_ROLE`) |
| `scripts/provision.sh` | Entra objects via `az` + Graph; writes `.env` and `docs/entra-objects.json` |
| `tests/conftest.py` | the fake tenant: RSA key as JWKS, Entra-shaped token minting, `ClaudeStub` |

Request path for `/api/*`: TrustedHost → TraceMiddleware (passes through unless keyed) →
`require_principal` → `auth.validate_access_token` (alg, kid, JWKS key, signature, required claims,
exp/nbf/iat, iss, aud, tid, scp) → `rbac.can*` on `principal.roles` → for `/api/ask`, 403 if any
collection is denied, else `rows_in()` filtered by `readable_collections()` → `ai.answer(rows)`.

Sign-in: `/auth/login?user=alice|bob|carol` (login_hint + `prompt=login`) → Entra →
`/auth/callback` checks `preferred_username` and `tid` against `.env`, then saves the MSAL cache.
`/proof` and `/playground` get tokens server-side with `acquire_token_silent`.

## Invariants (never break; each has guards)

| Invariant | Guarded by |
|---|---|
| Roles come only from the validated token's `roles` claim, never from body, query, headers or prompt | `test_token_validation.py::test_roles_in_body_and_query_are_ignored`, `test_playground.py::test_role_hints_are_reported_and_ignored`, `test_ask.py::test_injection_cannot_widen_access`, `test_rbac.py::test_roles_claim_not_a_list_grants_nothing` |
| Deny by default: no role, unknown role, wrong case or unknown collection grants nothing | `test_rbac.py::test_deny_by_default`, `::test_unknown_collection_denied_even_for_admin` |
| RBAC filtering happens before rows reach Claude | `test_ask.py::test_ask_never_sends_forbidden_rows`, `test_rbac.py::test_strict_multi_collection_ask`, `test_ask.py::test_ai_not_configured_is_503_after_rbac` |
| CONTRACT.md's permission table is the source of truth; `app/rbac.py` and `proof.CONTRACT_TABLE` must match it | `test_rbac.py::test_contract_table_parsed_and_transcribed_correctly` (parses CONTRACT.md), `::test_rbac_module_matches_contract`, `::test_http_matrix_matches_contract` |
| `/proof` grades against the contract, not rbac.py, and never takes the server's word (canary leak scan of whole responses) | `test_proof_leaks.py` (all), `test_proof.py::test_proof_detects_a_broken_server`, `::test_negatives_fail_if_server_skips_verification` |
| Tokens, refresh tokens and the client secret never reach the browser, logs, traces, `docs/proof/latest.json` or git | `test_playground.py::test_result_has_no_token_or_secret`, `::test_msal_step_shows_refresh_but_no_secrets`, `::test_playground_page`, `test_proof.py::test_write_and_read_result`, `test_token_validation.py::test_token_never_echoed_in_errors`, `test_playground.py::test_committed_entra_objects_have_no_secrets`; git: `.gitignore` (no test) |
| The trace never alters API responses and can't be enabled from outside | `test_playground.py::test_outside_caller_cannot_enable_trace`, `::test_with_the_key_the_trace_is_stored_not_returned`, `::test_validation_untouched_without_trace` |
| TrustedHost and Origin (+ `X-Proof-Run` / `X-Playground-Send`) on `/proof/run` and `/playground/send` | `test_proof.py::test_proof_run_endpoint_guards`, `::test_proof_run_rejects_missing_or_foreign_origin`, `::test_dns_rebinding_foreign_host_rejected`, `::test_origin_port_comes_from_redirect_uri`, `test_playground.py::test_send_requires_header_and_origin`, `::test_send_rejects_foreign_host` |
| Single uvicorn worker: traces live in an in-memory `TraceStore` | no test; never add `--workers` or move the store without replacing it |
| PASS needs all three users and nothing skipped; a result without a verdict is never green | `test_proof.py::test_signed_out_user_is_skipped_not_passed`, `::test_page_is_amber_incomplete_not_green_when_users_missing`, `::test_page_never_green_for_a_result_without_verdict` |

**Changing permissions** means changing all three together: the CONTRACT.md table, `rbac.ROLE_PERMISSIONS`
and `proof.CONTRACT_TABLE`. A new collection also needs rows with unique canaries in `data.py`, an entry
in `rbac.COLLECTIONS` and `proof.COLLECTIONS`, and updated counts in `tests/test_rbac.py` (5 table rows)
and `tests/test_proof.py` (`EXPECTED_GRID`, 42 checks). A new role also needs an app role in
`provision.sh`'s `ROLE_SPECS`.

## Secrets and data

- `.env` (client secret, session secret, Anthropic key) and `.tokens/` (MSAL caches with refresh
  tokens) are gitignored. Never print, cat, grep out values from, or commit either. Read only key names.
- Before every commit: `git status` and `git diff --cached` must show neither, and no token-shaped
  string (`eyJ...`), `sk-ant-` key or secret anywhere in the diff.
- Never paste tokens into chat, logs, test fixtures or commit messages. Tests mint their own fakes.
- `docs/entra-objects.json` and `docs/proof/latest.json` are generated per tenant and gitignored: they
  hold no secrets, but they name the tenant and its users (PII). Never commit them, and never put real
  UPNs, names or tenant ids in tracked files; use `contoso.onmicrosoft.com`-style placeholders.

## Working against a real tenant

- `provision.sh` is idempotent and safe to re-run; a clean re-run reports "already in place" and
  leaves `docs/entra-objects.json` unchanged. Test users come from `--alice/--bob/--carol`, else
  `GK_USER_*` env vars, else `.env`; there is no default.
- It only adds roles and scopes, never removes them: Graph rejects removing an enabled scope or role
  until it is disabled first. Keep that rule if you edit the PATCH logic.
- `teardown.sh` deletes the app registration and every role assignment: a human runs it.
- Never create or delete users or touch passwords from scripts.
- ROPC (password grant) isn't used and won't work with MFA: humans sign the test users in through
  the browser. An agent can't complete a real sign-in; ask the human, then run the proof.
- Test script changes with a stub `az` first on PATH before touching the tenant.
- Restart the server after provision: settings load once at startup.

## Gotchas learned here

- Haiku 5.5 has no server-side refusal fallback, so `ai.py` calls plain `messages.create` without
  betas (a refusal is handled via `stop_reason`).
- The shell's `ANTHROPIC_BASE_URL` must not leak in: `config.py` reads only `.env`, and `ai.py` passes
  `api_key` and `base_url` explicitly.
- `az ad app permission admin-consent` uses a legacy endpoint, so provision writes Graph
  `oauth2PermissionGrants` (`AllPrincipals`) instead.
- Security Defaults force MFA registration on first sign-in; the 14-day skip was removed in July 2024.
- Access tokens live 60–90 minutes, so a role change in Entra shows only after re-sign-in.
- Most forged-token modes fail at the signature check (tampered, forged roles, attacker key, edited
  aud, expired); `alg=none` and HS256 fail at the alg check. Tests rely on this order.
- `preferred_username` is mutable: it is used only to check that the right person signed into a
  slot, never for authorization.
- The admin-center deep-link formats in `playground.portal_links` are undocumented (taken from
  Microsoft-owned GitHub code) and may break.
- The Origin allow-list is derived from `ENTRA_REDIRECT_URI`'s port; `localhost` and `127.0.0.1`
  are different cookie hosts, so sign-in only works from `http://localhost:8000`.
- `provision.sh` needs bash 4.4+ and works with GNU or BSD `date`.

## Verifying a change

1. `uv run pytest -q` stays green. Add a test next to the invariant you touched.
2. UI work: run a fake-tenant instance on another port; never stop or restart `:8000`, which may
   hold a human's real sign-ins. `create_app(settings, token_provider=...)` takes any
   `user_key -> (token, problem)` callable; the tests use it the same way:

   ```python
   # uv run python fake8001.py   (from the repo root; writes nothing to the repo)
   import sys, tempfile
   from pathlib import Path
   sys.path[:0] = [".", "tests"]
   import uvicorn, conftest as ct
   from app import ai, auth
   from app.main import create_app
   auth.fetch_jwks = lambda url: {"keys": [ct.jwk_for(ct.SIGNING_KEY, ct.KID)]}
   ai.answer = ct.ClaudeStub()
   tmp = Path(tempfile.mkdtemp())
   s = ct.make_settings(tmp, redirect_uri="http://localhost:8001/auth/callback",
                        entra_objects=tmp / "entra-objects.json")
   uvicorn.run(create_app(s, token_provider=lambda k: (ct.token_for(k), None)),
               host="127.0.0.1", port=8001)
   ```

   The redirect URI sets the port the Origin checks accept. Pass a provider that returns
   `(None, "not signed in")` for some users to see INCOMPLETE.
3. Real tenant: a human signs the three users in at http://localhost:8000/proof and runs the proof.
   Expect **PASS · 42/42**.

## Conventions

- Match the existing style: small functions, comments that say why, no new dependencies without need.
- Vanilla JS, DOM built with `textContent` only (no `innerHTML`); CSS tokens for light and dark
  themes; no build step.
- YAGNI: build what the contract asks for.
- When behaviour changes, update CONTRACT.md in the same change, and README.md if setup changes.

## Git

- Repo: https://github.com/beetee2/enterprise-gatekeeper (public). Commit as the beetee2 GitHub
  account (its noreply email).
- End commit messages with `Co-Authored-By: <model> <noreply@anthropic.com>`.
- Push over HTTPS with gh's credentials. Don't switch the remote to SSH: the local SSH key belongs
  to a different GitHub account.
- Commit only when asked.
