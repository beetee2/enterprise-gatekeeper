"""Settings, read only from the project's .env file.

The shell environment is deliberately NOT consulted, so variables such as a
developer's ANTHROPIC_BASE_URL never leak into the app.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parent.parent

# The three proof users and the role CONTRACT.md says each one holds.
USER_KEYS = ("alice", "bob", "carol")
EXPECTED_ROLE = {
    "alice": "Support.Agent",
    "bob": "Finance.Analyst",
    "carol": "Tenant.Admin",
}

REQUIRED_ENTRA = (
    "ENTRA_TENANT_ID",
    "ENTRA_CLIENT_ID",
    "ENTRA_CLIENT_SECRET",
    "ENTRA_API_SCOPE",
    "ENTRA_REDIRECT_URI",
    "GK_USER_ALICE",
    "GK_USER_BOB",
    "GK_USER_CAROL",
    "SESSION_SECRET",
)

DEFAULT_ANTHROPIC_BASE_URL = "https://api.anthropic.com"


@dataclass(frozen=True)
class Settings:
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    api_scope: str = ""
    redirect_uri: str = "http://localhost:8000/auth/callback"
    users: dict[str, str] = field(default_factory=dict)  # user key -> UPN
    session_secret: str = ""
    anthropic_api_key: str = ""
    anthropic_base_url: str = DEFAULT_ANTHROPIC_BASE_URL
    missing: tuple[str, ...] = REQUIRED_ENTRA
    tokens_dir: Path = ROOT / ".tokens"
    proof_output: Path = ROOT / "docs" / "proof" / "latest.json"
    entra_objects: Path = ROOT / "docs" / "entra-objects.json"  # non-secret ids, from provision.sh

    @property
    def entra_configured(self) -> bool:
        return not self.missing

    @property
    def ai_configured(self) -> bool:
        return bool(self.anthropic_api_key)

    @property
    def authority(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}"

    @property
    def issuer(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"

    @property
    def jwks_url(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}/discovery/v2.0/keys"

    @property
    def scope_name(self) -> str:
        # api://<clientId>/access_as_user -> access_as_user
        return self.api_scope.rsplit("/", 1)[-1] if self.api_scope else "access_as_user"


def load_settings(env_file: Path | None = None) -> Settings:
    env_file = env_file or ROOT / ".env"
    values = {k: (v or "").strip() for k, v in dotenv_values(env_file).items()} if env_file.exists() else {}
    missing = tuple(k for k in REQUIRED_ENTRA if not values.get(k))
    return Settings(
        tenant_id=values.get("ENTRA_TENANT_ID", ""),
        client_id=values.get("ENTRA_CLIENT_ID", ""),
        client_secret=values.get("ENTRA_CLIENT_SECRET", ""),
        api_scope=values.get("ENTRA_API_SCOPE", ""),
        redirect_uri=values.get("ENTRA_REDIRECT_URI") or "http://localhost:8000/auth/callback",
        users={k: values.get(f"GK_USER_{k.upper()}", "") for k in USER_KEYS},
        # Without a configured secret the app still boots (unconfigured state);
        # sessions then just don't survive a restart.
        session_secret=values.get("SESSION_SECRET") or secrets.token_urlsafe(32),
        anthropic_api_key=values.get("ANTHROPIC_API_KEY", ""),
        anthropic_base_url=values.get("ANTHROPIC_BASE_URL") or DEFAULT_ANTHROPIC_BASE_URL,
        missing=missing,
    )
