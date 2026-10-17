#!/usr/bin/env bash
# Provision the Entra ID objects for Gatekeeper (see CONTRACT.md).
# Idempotent: re-running reuses the app, service principal, grants and role
# assignments it finds. The three test users must already exist in the tenant;
# this script never creates users or touches passwords. Secrets go only to
# .env (mode 600) and are never printed. Run with --help for usage.
set -euo pipefail
if ((BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4))); then
  printf 'ERROR: bash 4.4 or newer is required (macOS: brew install bash)\n' >&2; exit 1
fi
shopt -s inherit_errexit

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/.env"

APP_NAME="Gatekeeper AI"
REDIRECT_URI="http://localhost:8000/auth/callback"
SCOPE_VALUE="access_as_user"
SECRET_NAME="gatekeeper"
GRAPH="https://graph.microsoft.com/v1.0"
GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"  # Microsoft Graph
GRAPH_SCOPES="openid profile offline_access User.Read"

USER_KEYS=(alice bob carol)
declare -A USER_UPN=()  # filled from --alice/--bob/--carol, GK_USER_* or .env below
declare -A USER_ROLE=([alice]=Support.Agent [bob]=Finance.Analyst [carol]=Tenant.Admin)
# value|display name|description
ROLE_SPECS=(
  "Support.Agent|Support Agent|Reads product help articles and customer support tickets."
  "Finance.Analyst|Finance Analyst|Reads product help articles and per-customer revenue."
  "Tenant.Admin|Tenant Admin|Reads every collection, including the audit log, and manages roles."
)

usage() {
  cat <<'USAGE'
Usage: scripts/provision.sh --alice <upn> --bob <upn> --carol <upn>

The three test users must already exist in the tenant az is signed in to.
Each gets exactly one app role:
  --alice <upn>   Support.Agent     (or GK_USER_ALICE)
  --bob <upn>     Finance.Analyst   (or GK_USER_BOB)
  --carol <upn>   Tenant.Admin      (or GK_USER_CAROL)

Each UPN comes from its flag, else the GK_USER_* environment variable, else
the GK_USER_* line in .env (so a re-run needs no arguments).
USAGE
}

log() { printf '%s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

declare -A FLAG_UPN=()
while (($#)); do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --alice|--bob|--carol)
      [[ $# -ge 2 && -n "$2" && "$2" != -* ]] || { usage >&2; die "$1 needs a UPN"; }
      FLAG_UPN[${1#--}]="$2"
      shift 2 ;;
    *) usage >&2; printf 'Unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

TMPD="$(mktemp -d)"
chmod 700 "$TMPD"
trap 'rm -rf "$TMPD"' EXIT

# --- helpers ---------------------------------------------------------------

uri() { jq -rn --arg s "$1" '$s|@uri'; }

graph_get() {
  az rest --only-show-errors --method get --url "$1" -o json
}

# graph_send METHOD URL JSON  (body via a temp file avoids shell-quoting issues)
graph_send() {
  local body="$TMPD/body.json"
  printf '%s' "$3" > "$body"
  az rest --only-show-errors --method "$1" --url "$2" --body "@$body" -o json
}

# retry TRIES DELAY CMD...  (new directory objects can take seconds to replicate)
retry() {
  local tries=$1 delay=$2 i
  shift 2
  for ((i = 1; ; i++)); do
    if "$@"; then return 0; fi
    ((i >= tries)) && return 1
    log "    retrying in ${delay}s (directory replication can lag) ..."
    sleep "$delay"
  done
}

# env_get FILE KEY -> raw value of the last KEY= line, or empty
env_get() {
  [[ -f "$1" ]] || return 0
  awk -v k="$2" 'index($0, k "=") == 1 { v = substr($0, length(k) + 2) } END { print v }' "$1"
}

unquote() { local v=$1; v=${v#[\"\']}; v=${v%[\"\']}; printf '%s' "$v"; }

new_uuid() { uuidgen | tr '[:upper:]' '[:lower:]'; }

# --- test users: flag, else GK_USER_* env var, else .env --------------------

unset_flags=()
for key in "${USER_KEYS[@]}"; do
  var="GK_USER_${key^^}"
  upn="${FLAG_UPN[$key]:-${!var:-$(unquote "$(env_get "$ENV_FILE" "$var")")}}"
  if [[ -z "$upn" ]]; then
    unset_flags+=("--$key")
  elif [[ "$upn" != ?*@?* || "$upn" =~ [[:space:]] ]]; then
    die "--$key / $var: '$upn' does not look like a UPN (name@domain)"
  else
    USER_UPN[$key]="$upn"
  fi
done
if ((${#unset_flags[@]})); then
  usage >&2
  die "no UPN given for: ${unset_flags[*]}"
fi
dupes="$(printf '%s\n' "${USER_UPN[@]}" | tr '[:upper:]' '[:lower:]' | sort | uniq -d)"
[[ -z "$dupes" ]] || die "each test user needs its own account; given more than once: $dupes"

# --- preflight -------------------------------------------------------------

for cmd in az jq openssl uuidgen awk; do
  command -v "$cmd" >/dev/null || die "'$cmd' is required (see Prerequisites in README.md)"
done

ACCOUNT_JSON="$(az account show -o json 2>/dev/null)" \
  || die "az is not signed in. Run: az login --tenant <tenant-id> --allow-no-subscriptions"
TENANT_ID="$(jq -r '.tenantId' <<<"$ACCOUNT_JSON")"
SIGNED_IN_AS="$(jq -r '.user.name // "unknown"' <<<"$ACCOUNT_JSON")"
DOMAIN="$(graph_get "$GRAPH/domains" | jq -r '[.value[] | select(.isDefault)][0].id // empty')"
[[ -n "$DOMAIN" ]] || die "could not find the tenant's default domain via GET /domains"

log "Tenant:         $TENANT_ID"
log "Default domain: $DOMAIN"
log "Signed in as:   $SIGNED_IN_AS"

# The test users must already exist (CONTRACT.md); check before changing anything.
declare -A USER_ID
missing=()
for key in "${USER_KEYS[@]}"; do
  if uid="$(az ad user show --only-show-errors --id "${USER_UPN[$key]}" -o json 2>/dev/null | jq -r '.id // empty')" \
      && [[ -n "$uid" ]]; then
    USER_ID[$key]="$uid"
  else
    missing+=("${USER_UPN[$key]}")
  fi
done
((${#missing[@]} == 0)) || die "test user(s) not found in tenant $TENANT_ID: ${missing[*]}
       Create them in the Entra admin center first (this script never creates users)."
log "Test users:     found ${USER_UPN[alice]}, ${USER_UPN[bob]}, ${USER_UPN[carol]}"

# --- app registration ------------------------------------------------------

log "==> App registration '$APP_NAME'"
APPS_JSON="$(graph_get "$GRAPH/applications?\$filter=$(uri "displayName eq '$APP_NAME'")&\$select=id,appId,displayName")"
APP_COUNT="$(jq '.value | length' <<<"$APPS_JSON")"
if ((APP_COUNT > 1)); then
  die "found $APP_COUNT apps named '$APP_NAME' ($(jq -r '[.value[].appId] | join(", ")' <<<"$APPS_JSON")); delete the extras first"
elif ((APP_COUNT == 1)); then
  APP_OBJ_ID="$(jq -r '.value[0].id' <<<"$APPS_JSON")"
  APP_ID="$(jq -r '.value[0].appId' <<<"$APPS_JSON")"
  log "    found existing app (client id $APP_ID)"
else
  CREATED="$(az ad app create --only-show-errors \
    --display-name "$APP_NAME" \
    --sign-in-audience AzureADMyOrg \
    --web-redirect-uris "$REDIRECT_URI" \
    -o json)"
  APP_OBJ_ID="$(jq -r '.id' <<<"$CREATED")"
  APP_ID="$(jq -r '.appId' <<<"$CREATED")"
  log "    created app (client id $APP_ID)"
fi

app_get() { graph_get "$GRAPH/applications/$APP_OBJ_ID"; }
APP_JSON="$(retry 6 5 app_get)"

# Wanted app roles, each with a fresh GUID that is used only if no role with
# that value exists yet (existing roles keep their ids).
WANTED_ROLES="[]"
for spec in "${ROLE_SPECS[@]}"; do
  IFS='|' read -r r_value r_name r_desc <<<"$spec"
  WANTED_ROLES="$(jq -c --arg id "$(new_uuid)" --arg v "$r_value" --arg n "$r_name" --arg d "$r_desc" \
    '. + [{id: $id, value: $v, displayName: $n, description: $d,
           allowedMemberTypes: ["User"], isEnabled: true}]' <<<"$WANTED_ROLES")"
done

# Build a PATCH holding only what has to change. Add only, never remove:
# Graph rejects removing an enabled scope/role without disabling it first.
PATCH1="$(jq -c \
  --arg appId "$APP_ID" \
  --arg redirect "$REDIRECT_URI" \
  --arg scopeValue "$SCOPE_VALUE" \
  --arg scopeId "$(new_uuid)" \
  --argjson wantedRoles "$WANTED_ROLES" '
  def add_missing($xs): . + ($xs - .);
  . as $app
  | ($app.identifierUris // []) as $uris
  | ($app.web.redirectUris // []) as $redirects
  | ($app.api // {}) as $api
  | ($api.oauth2PermissionScopes // []) as $scopes
  | ($app.appRoles // []) as $roles
  | ($roles | map(.value)) as $roleValues
  | {}
  | if ($uris | index("api://" + $appId)) then . else
      .identifierUris = ($uris | add_missing(["api://" + $appId])) end
  | if ($redirects | index($redirect)) then . else
      .web = {redirectUris: ($redirects | add_missing([$redirect]))} end
  | if ($api.requestedAccessTokenVersion == 2) and ($scopes | any(.value == $scopeValue)) then . else
      .api = ($api
        | .requestedAccessTokenVersion = 2
        | .oauth2PermissionScopes = (
            if ($scopes | any(.value == $scopeValue)) then $scopes else $scopes + [{
              id: $scopeId,
              value: $scopeValue,
              type: "User",
              isEnabled: true,
              adminConsentDisplayName: "Access Gatekeeper AI as the signed-in user",
              adminConsentDescription: "Allows the Gatekeeper AI web app to call the Gatekeeper API on behalf of the signed-in user. What the user can read is limited by their assigned app role.",
              userConsentDisplayName: "Access Gatekeeper AI as you",
              userConsentDescription: "Allows Gatekeeper AI to call its API on your behalf, limited to what your role allows."
            }] end))
    end
  | ($wantedRoles | map(select(.value as $v | $roleValues | index($v) | not))) as $newRoles
  | if ($newRoles | length) == 0 then . else .appRoles = ($roles + $newRoles) end
' <<<"$APP_JSON")"

if [[ "$PATCH1" == "{}" ]]; then
  log "    identifier URI, redirect URI, scope and app roles already in place"
else
  log "    updating: $(jq -r 'keys | join(", ")' <<<"$PATCH1")"
  graph_send patch "$GRAPH/applications/$APP_OBJ_ID" "$PATCH1" >/dev/null
  APP_JSON="$(app_get)"
fi

SCOPE_ID="$(jq -r --arg v "$SCOPE_VALUE" '.api.oauth2PermissionScopes[] | select(.value == $v) | .id' <<<"$APP_JSON")"
[[ -n "$SCOPE_ID" ]] || die "scope $SCOPE_VALUE missing after update"

# Microsoft Graph delegated permissions (ids looked up, not hard-coded).
GRAPH_SP_JSON="$(graph_get "$GRAPH/servicePrincipals(appId='$GRAPH_APP_ID')?\$select=id,oauth2PermissionScopes")"
GRAPH_SP_ID="$(jq -r '.id' <<<"$GRAPH_SP_JSON")"
GRAPH_ACCESS="$(jq -c --arg want "$GRAPH_SCOPES" '
  ($want | split(" ")) as $w
  | [.oauth2PermissionScopes[] | select(.value as $v | $w | index($v)) | {id, type: "Scope"}]' <<<"$GRAPH_SP_JSON")"
(( $(jq 'length' <<<"$GRAPH_ACCESS") == 4 )) || die "could not resolve all Graph scopes: $GRAPH_SCOPES"

PATCH2="$(jq -c \
  --arg graphAppId "$GRAPH_APP_ID" --argjson graphAccess "$GRAPH_ACCESS" \
  --arg appId "$APP_ID" --arg scopeId "$SCOPE_ID" '
  (.requiredResourceAccess // []) as $cur
  | [ {resourceAppId: $graphAppId, resourceAccess: $graphAccess},
      {resourceAppId: $appId, resourceAccess: [{id: $scopeId, type: "Scope"}]} ] as $want
  | ($cur + [ $want[] | select(.resourceAppId as $r | $cur | map(.resourceAppId) | index($r) | not) ])
  | map(.resourceAppId as $r
        | ([$want[] | select(.resourceAppId == $r)][0].resourceAccess // []) as $add
        | .resourceAccess += ($add - .resourceAccess)) as $merged
  | if ($merged | map(.resourceAccess |= sort_by(.id)) | sort_by(.resourceAppId))
       == ($cur | map(.resourceAccess |= sort_by(.id)) | sort_by(.resourceAppId))
    then {} else {requiredResourceAccess: $merged} end
' <<<"$APP_JSON")"

if [[ "$PATCH2" == "{}" ]]; then
  log "    required permissions already in place"
else
  log "    adding required permissions: Graph ($GRAPH_SCOPES), own API ($SCOPE_VALUE)"
  graph_send patch "$GRAPH/applications/$APP_OBJ_ID" "$PATCH2" >/dev/null
fi

# --- service principal -----------------------------------------------------

log "==> Service principal"
sp_find() {
  graph_get "$GRAPH/servicePrincipals?\$filter=$(uri "appId eq '$APP_ID'")&\$select=id,appRoleAssignmentRequired" \
    | jq -c '.value[0] // empty'
}
SP_JSON="$(sp_find)"
if [[ -z "$SP_JSON" ]]; then
  sp_create() { az ad sp create --only-show-errors --id "$APP_ID" -o json; }
  SP_JSON="$(retry 6 5 sp_create | jq -c '{id, appRoleAssignmentRequired}')"
  log "    created"
else
  log "    found existing"
fi
SP_ID="$(jq -r '.id' <<<"$SP_JSON")"

if [[ "$(jq -r '.appRoleAssignmentRequired' <<<"$SP_JSON")" != "true" ]]; then
  sp_require() { graph_send patch "$GRAPH/servicePrincipals/$SP_ID" '{"appRoleAssignmentRequired":true}' >/dev/null; }
  retry 6 5 sp_require
  log "    set appRoleAssignmentRequired=true"
else
  log "    appRoleAssignmentRequired already true"
fi

# --- tenant-wide admin consent (so test users never see a consent prompt) ---

log "==> Admin consent (oauth2PermissionGrant, AllPrincipals)"
# ensure_grant RESOURCE_SP_ID LABEL "scope1 scope2 ..."
ensure_grant() {
  local resource=$1 label=$2 want=$3 grants existing missing merged
  grants="$(graph_get "$GRAPH/oauth2PermissionGrants?\$filter=$(uri "clientId eq '$SP_ID'")")" || return
  existing="$(jq -c --arg r "$resource" \
    '[.value[] | select(.resourceId == $r and .consentType == "AllPrincipals")][0] // empty' <<<"$grants")"
  if [[ -z "$existing" ]]; then
    graph_send post "$GRAPH/oauth2PermissionGrants" "$(jq -cn --arg c "$SP_ID" --arg r "$resource" --arg s "$want" \
      '{clientId: $c, consentType: "AllPrincipals", resourceId: $r, scope: $s}')" >/dev/null || return
    log "    granted $label: $want"
    return
  fi
  missing="$(jq -r --arg w "$want" \
    '(($w | split(" ")) - ((.scope // "") | split(" "))) | join(" ")' <<<"$existing")"
  if [[ -z "$missing" ]]; then
    log "    $label already granted"
    return
  fi
  merged="$(jq -r '.scope // ""' <<<"$existing") $missing"
  graph_send patch "$GRAPH/oauth2PermissionGrants/$(jq -r '.id' <<<"$existing")" \
    "$(jq -cn --arg s "${merged# }" '{scope: $s}')" >/dev/null || return
  log "    extended $label grant with: $missing"
}
retry 6 5 ensure_grant "$GRAPH_SP_ID" "Microsoft Graph" "$GRAPH_SCOPES"
retry 6 5 ensure_grant "$SP_ID" "$APP_NAME" "$SCOPE_VALUE"

# --- client secret ---------------------------------------------------------

log "==> Client secret"
OLD_CLIENT_ID="$(unquote "$(env_get "$ENV_FILE" ENTRA_CLIENT_ID)")"
OLD_SECRET="$(unquote "$(env_get "$ENV_FILE" ENTRA_CLIENT_SECRET)")"
CLIENT_SECRET=""
if [[ -n "$OLD_SECRET" && "$OLD_CLIENT_ID" == "$APP_ID" ]]; then
  # Reuse only if Entra still holds an unexpired secret whose hint (first 3 chars) matches.
  if jq -e --arg h "${OLD_SECRET:0:3}" '
      any(.passwordCredentials[]?;
          .hint == $h and ((.endDateTime | sub("\\.[0-9]+"; "") | sub("\\+00:00$"; "Z") | fromdateiso8601) > now))
    ' <<<"$APP_JSON" >/dev/null; then
    CLIENT_SECRET="$OLD_SECRET"
    log "    reusing the secret already in .env"
  else
    log "    secret in .env is unknown to Entra or expired; creating a new one"
  fi
fi
if [[ -z "$CLIENT_SECRET" ]]; then
  # GNU date, else BSD/macOS date
  END_DATE="$(date -u -d '+6 months' +%Y-%m-%dT%H:%M:%S+00:00 2>/dev/null \
    || date -u -v+6m +%Y-%m-%dT%H:%M:%S+00:00)"
  CLIENT_SECRET="$(az ad app credential reset --only-show-errors \
    --id "$APP_ID" --append --display-name "$SECRET_NAME" --end-date "$END_DATE" \
    -o json | jq -r '.password')"
  [[ -n "$CLIENT_SECRET" && "$CLIENT_SECRET" != "null" ]] || die "credential reset returned no password"
  log "    created secret '$SECRET_NAME' (expires $END_DATE)"
fi

# --- .env ------------------------------------------------------------------

MANAGED_KEYS=(ENTRA_TENANT_ID ENTRA_CLIENT_ID ENTRA_CLIENT_SECRET ENTRA_API_SCOPE ENTRA_REDIRECT_URI
  GK_USER_ALICE GK_USER_BOB GK_USER_CAROL ANTHROPIC_API_KEY SESSION_SECRET)

ANTHROPIC_API_KEY="$(env_get "$ENV_FILE" ANTHROPIC_API_KEY)"
SESSION_SECRET="$(env_get "$ENV_FILE" SESSION_SECRET)"
[[ -n "$SESSION_SECRET" ]] || SESSION_SECRET="$(openssl rand -hex 32)"

write_env() {
  local tmp extra
  tmp="$(mktemp "$ROOT/.env.tmp.XXXXXX")"
  chmod 600 "$tmp"
  {
    printf '# Written by scripts/provision.sh. ANTHROPIC_API_KEY is yours to fill in.\n'
    printf 'ENTRA_TENANT_ID=%s\n' "$TENANT_ID"
    printf 'ENTRA_CLIENT_ID=%s\n' "$APP_ID"
    printf 'ENTRA_CLIENT_SECRET=%s\n' "$CLIENT_SECRET"
    printf 'ENTRA_API_SCOPE=api://%s/%s\n' "$APP_ID" "$SCOPE_VALUE"
    printf 'ENTRA_REDIRECT_URI=%s\n' "$REDIRECT_URI"
    printf 'GK_USER_ALICE=%s\n' "${USER_UPN[alice]}"
    printf 'GK_USER_BOB=%s\n' "${USER_UPN[bob]}"
    printf 'GK_USER_CAROL=%s\n' "${USER_UPN[carol]}"
    printf 'ANTHROPIC_API_KEY=%s\n' "$ANTHROPIC_API_KEY"
    printf 'SESSION_SECRET=%s\n' "$SESSION_SECRET"
    if [[ -f "$ENV_FILE" ]]; then
      # keep any other keys someone added by hand
      extra="$(awk -v keys="${MANAGED_KEYS[*]}" '
        BEGIN { n = split(keys, k, " "); for (i = 1; i <= n; i++) m[k[i]] = 1 }
        /^[A-Za-z_][A-Za-z0-9_]*=/ { key = substr($0, 1, index($0, "=") - 1); if (!(key in m)) print }
      ' "$ENV_FILE")"
      [[ -z "$extra" ]] || printf '%s\n' "$extra"
    fi
  } > "$tmp"
  mv -f "$tmp" "$ENV_FILE"
}
write_env
log "==> Wrote .env (mode 600; secret values not shown)"

# --- app role assignments --------------------------------------------------

log "==> App role assignments (exactly one role per user)"
for key in "${USER_KEYS[@]}"; do
  role="${USER_ROLE[$key]}"
  role_id="$(jq -r --arg v "$role" '.appRoles[] | select(.value == $v) | .id' <<<"$APP_JSON")"
  [[ -n "$role_id" ]] || die "app role $role not found on the app"
  uid="${USER_ID[$key]}"
  assigned="$(graph_get "$GRAPH/servicePrincipals/$SP_ID/appRoleAssignedTo" \
    | jq -c --arg u "$uid" '[.value[] | select(.principalId == $u)]')"
  # remove any other role this user holds on this app
  for wrong in $(jq -r --arg r "$role_id" '.[] | select(.appRoleId != $r) | .id' <<<"$assigned"); do
    az rest --only-show-errors --method delete --url "$GRAPH/servicePrincipals/$SP_ID/appRoleAssignedTo/$wrong" >/dev/null
    log "    removed an extra role from ${USER_UPN[$key]}"
  done
  if jq -e --arg r "$role_id" 'any(.[]; .appRoleId == $r)' <<<"$assigned" >/dev/null; then
    log "    ${USER_UPN[$key]} already has $role"
  else
    assign() {
      graph_send post "$GRAPH/servicePrincipals/$SP_ID/appRoleAssignedTo" \
        "$(jq -cn --arg p "$uid" --arg r "$SP_ID" --arg a "$role_id" '{principalId: $p, resourceId: $r, appRoleId: $a}')" >/dev/null
    }
    retry 6 5 assign
    log "    assigned $role to ${USER_UPN[$key]}"
  fi
done

# --- non-secret object ids for /playground ----------------------------------

OBJECTS_FILE="$ROOT/docs/entra-objects.json"
log "==> Entra object ids -> docs/entra-objects.json (ids only, no secrets)"
# users_json: one entry per user with the assignment that grants their role; fails
# (so retry waits) while a just-created assignment has not replicated yet.
users_json() {
  local all out='{}' key role_id asg
  all="$(graph_get "$GRAPH/servicePrincipals/$SP_ID/appRoleAssignedTo")" || return
  for key in "${USER_KEYS[@]}"; do
    role_id="$(jq -r --arg v "${USER_ROLE[$key]}" '.appRoles[] | select(.value == $v) | .id' <<<"$APP_JSON")"
    asg="$(jq -r --arg u "${USER_ID[$key]}" --arg r "$role_id" \
      '[.value[] | select(.principalId == $u and .appRoleId == $r)][0].id // empty' <<<"$all")"
    [[ -n "$asg" ]] || return 1
    out="$(jq -c --arg k "$key" --arg upn "${USER_UPN[$key]}" --arg oid "${USER_ID[$key]}" \
      --arg role "${USER_ROLE[$key]}" --arg asg "$asg" \
      '. + {($k): {upn: $upn, objectId: $oid, role: $role, assignmentId: $asg}}' <<<"$out")"
  done
  printf '%s' "$out"
}
USERS_JSON="$(retry 6 5 users_json)" || die "could not read the role assignments back"
mkdir -p "$ROOT/docs"
OBJ_TMP="$(mktemp "$ROOT/docs/.entra-objects.json.XXXXXX")"
jq -S -n \
  --arg tid "$TENANT_ID" --arg domain "$DOMAIN" --arg name "$APP_NAME" \
  --arg appId "$APP_ID" --arg appObjId "$APP_OBJ_ID" --arg spId "$SP_ID" \
  --arg scopeValue "$SCOPE_VALUE" --arg scopeId "$SCOPE_ID" --arg redirect "$REDIRECT_URI" \
  --argjson roles "$(jq -c '[.appRoles[] | {key: .value, value: {id, displayName}}] | from_entries' <<<"$APP_JSON")" \
  --argjson users "$USERS_JSON" '{
    note: "Written by scripts/provision.sh: Entra object ids only, safe to commit. Read by /playground.",
    tenant_id: $tid, default_domain: $domain,
    app: {displayName: $name, appId: $appId, objectId: $appObjId, redirectUri: $redirect},
    service_principal: {id: $spId, appRoleAssignmentRequired: true},
    scope: {value: $scopeValue, id: $scopeId},
    app_roles: $roles,
    users: $users
  }' > "$OBJ_TMP"
chmod 644 "$OBJ_TMP"
mv -f "$OBJ_TMP" "$OBJECTS_FILE"
log "    wrote $(jq -r '.users | length' "$OBJECTS_FILE") users, $(jq -r '.app_roles | length' "$OBJECTS_FILE") app roles"

# --- summary ---------------------------------------------------------------

printf '\nProvisioned %s (client id %s) in tenant %s\n\n' "$APP_NAME" "$APP_ID" "$TENANT_ID"
printf '%-6s  %-44s  %s\n' "user" "UPN" "role"
printf '%-6s  %-44s  %s\n' "------" "--------------------------------------------" "---------------"
for key in "${USER_KEYS[@]}"; do
  printf '%-6s  %-44s  %s\n' "$key" "${USER_UPN[$key]}" "${USER_ROLE[$key]}"
done
KEY_NOTE=""
[[ -z "$ANTHROPIC_API_KEY" ]] || KEY_NOTE=" -- already set"
cat <<EOF

Next steps:
  1. Put your Anthropic key in .env (ANTHROPIC_API_KEY)$KEY_NOTE
  2. Start the app on http://localhost:8000 and open http://localhost:8000/proof
  3. Sign in as each user (their existing passwords). Tenants with Security Defaults
     make each user register MFA on first sign-in (no 14-day skip since July 2024).
EOF
