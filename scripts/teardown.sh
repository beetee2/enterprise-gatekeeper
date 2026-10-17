#!/usr/bin/env bash
# Remove the Gatekeeper app role assignments and app registration,
# then delete .tokens/. Never deletes users. .env is kept (it holds your
# ANTHROPIC_API_KEY); provision.sh rewrites its Entra values on the next run.
#
# Usage: scripts/teardown.sh [--yes]
set -euo pipefail
if ((BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4))); then
  printf 'ERROR: bash 4.4 or newer is required (macOS: brew install bash)\n' >&2; exit 1
fi
shopt -s inherit_errexit

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_NAME="Gatekeeper AI"
GRAPH="https://graph.microsoft.com/v1.0"

ASSUME_YES=false
for arg in "$@"; do
  case "$arg" in
    --yes|-y) ASSUME_YES=true ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
uri() { jq -rn --arg s "$1" '$s|@uri'; }
graph_get() { az rest --only-show-errors --method get --url "$1" -o json </dev/null; }

for cmd in az jq; do
  command -v "$cmd" >/dev/null || die "'$cmd' is required"
done
TENANT_ID="$(az account show -o json 2>/dev/null | jq -r '.tenantId')" \
  || die "az is not signed in. Run: az login --tenant <tenant-id> --allow-no-subscriptions"

# "objectId appId" per matching app
APPS="$(graph_get "$GRAPH/applications?\$filter=$(uri "displayName eq '$APP_NAME'")&\$select=id,appId" \
  | jq -r '.value[] | "\(.id) \(.appId)"')"

# "spId<TAB>assignmentId<TAB>principal<TAB>role" per role assignment on each app's service principal
ASSIGNMENTS=""
if [[ -n "$APPS" ]]; then
  while read -r _ app_id; do
    sp_id="$(graph_get "$GRAPH/servicePrincipals?\$filter=$(uri "appId eq '$app_id'")&\$select=id" \
      | jq -r '.value[0].id // empty')"
    [[ -n "$sp_id" ]] || continue
    app_roles="$(graph_get "$GRAPH/servicePrincipals/$sp_id?\$select=appRoles" | jq -c '.appRoles')"
    rows="$(graph_get "$GRAPH/servicePrincipals/$sp_id/appRoleAssignedTo" | jq -r --arg sp "$sp_id" --argjson roles "$app_roles" '
      .value[] | .appRoleId as $r
      | [$sp, .id, (.principalDisplayName // .principalId), (([$roles[] | select(.id == $r) | .value][0]) // $r)]
      | join("\t")')"
    [[ -z "$rows" ]] || ASSIGNMENTS+="$rows"$'\n'
  done <<<"$APPS"
fi
ASSIGNMENTS="${ASSIGNMENTS%$'\n'}"

printf 'Tenant %s\n' "$TENANT_ID"
printf 'Will remove (users themselves are NOT deleted):\n'
if [[ -n "$ASSIGNMENTS" ]]; then
  while IFS=$'\t' read -r _ _ who role; do printf '  role assignment  %s -> %s\n' "$who" "$role"; done <<<"$ASSIGNMENTS"
fi
if [[ -n "$APPS" ]]; then
  while read -r _ app_id; do printf '  app registration %s (client id %s)\n' "$APP_NAME" "$app_id"; done <<<"$APPS"
else
  printf '  (no app registration named %s found)\n' "$APP_NAME"
fi
printf '  local            %s/.tokens/\n' "$ROOT"

if ! $ASSUME_YES; then
  read -r -p "Type 'yes' to continue: " answer
  [[ "$answer" == "yes" ]] || { printf 'Aborted.\n'; exit 1; }
fi

if [[ -n "$ASSIGNMENTS" ]]; then
  while IFS=$'\t' read -r sp_id assignment_id who role; do
    az rest --only-show-errors --method delete \
      --url "$GRAPH/servicePrincipals/$sp_id/appRoleAssignedTo/$assignment_id" >/dev/null </dev/null
    printf 'removed role %s from %s\n' "$role" "$who"
  done <<<"$ASSIGNMENTS"
fi
if [[ -n "$APPS" ]]; then
  while read -r obj_id app_id; do
    # also removes the app's service principal and its consent grants
    az ad app delete --only-show-errors --id "$obj_id" </dev/null
    printf 'deleted app registration %s\n' "$app_id"
  done <<<"$APPS"
fi

rm -rf "$ROOT/.tokens"
printf 'removed .tokens/\n'
printf 'The deleted app stays in Entra "Deleted applications" for 30 days before it is purged.\n'
