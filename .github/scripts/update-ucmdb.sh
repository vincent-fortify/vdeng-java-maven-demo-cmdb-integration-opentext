#!/usr/bin/env bash
# Push Fortify on Demand release results to an OpenText UCMDB CI.
#
# Reads the release-level issue counts from FoD (via fcli), then updates
# vulnerability_details and vulnerability_status on the mapped UCMDB CI.
#
# Required env:
#   FOD_URL, FOD_TENANT, FOD_USER, FOD_PAT, FOD_RELEASE   (FoD side)
#   UCMDB_URL, UCMDB_USER, UCMDB_PASSWORD,
#   UCMDB_CLIENT_CONTEXT, UCMDB_CI_ID, UCMDB_CI_TYPE       (UCMDB side)
# Optional env:
#   UCMDB_CUSTOMER_NAME      default "Default Client"
#   UCMDB_STATUS_VULNERABLE  default "Vulnerable"
#   UCMDB_STATUS_CLEAN       enum value to write when there are no Critical/High
#                            issues. If unset, status is left unchanged.

set -euo pipefail

: "${FOD_URL:?}" "${FOD_TENANT:?}" "${FOD_USER:?}" "${FOD_PAT:?}" "${FOD_RELEASE:?}"
: "${UCMDB_URL:?}" "${UCMDB_USER:?}" "${UCMDB_PASSWORD:?}"
: "${UCMDB_CLIENT_CONTEXT:?}" "${UCMDB_CI_ID:?}" "${UCMDB_CI_TYPE:?}"

UCMDB_CUSTOMER_NAME="${UCMDB_CUSTOMER_NAME:-Default Client}"
UCMDB_STATUS_VULNERABLE="${UCMDB_STATUS_VULNERABLE:-Vulnerable}"
UCMDB_STATUS_CLEAN="${UCMDB_STATUS_CLEAN:-}"
API="${UCMDB_URL%/}/rest-api"

# ---------------------------------------------------------------------------
# 1. Get release-level counts from FoD
# ---------------------------------------------------------------------------
echo "Logging in to FoD (${FOD_URL}) ..."
fcli fod session login --url "$FOD_URL" --tenant "$FOD_TENANT" \
  --user "$FOD_USER" --password "$FOD_PAT" --fod-session cmdb >/dev/null
trap 'fcli fod session logout --fod-session cmdb >/dev/null 2>&1 || true' EXIT

echo "Reading release ${FOD_RELEASE} ..."
REL_JSON=$(fcli fod release get "$FOD_RELEASE" --fod-session cmdb -o json)
# fcli may return a single object or a one-element array
REL_JSON=$(jq 'if type=="array" then .[0] else . end' <<<"$REL_JSON")

CRIT=$(jq -r '.critical // 0' <<<"$REL_JSON")
HIGH=$(jq -r '.high // 0' <<<"$REL_JSON")
MED=$(jq -r '.medium // 0' <<<"$REL_JSON")
LOW=$(jq -r '.low // 0' <<<"$REL_JSON")
PASSED=$(jq -r '.isPassed' <<<"$REL_JSON")
case "$PASSED" in
  true)  POLICY="Pass" ;;
  false) POLICY="Fail" ;;
  *)     POLICY="Unknown" ;;
esac

DETAILS="Fortify: ${CRIT} - Critical, ${HIGH} - High, ${MED} - Medium, ${LOW} - Low | Policy: ${POLICY} | Release: ${FOD_RELEASE} | Updated: $(date -u +%Y-%m-%dT%H:%MZ)"

if (( CRIT + HIGH > 0 )); then
  STATUS="$UCMDB_STATUS_VULNERABLE"
else
  STATUS="$UCMDB_STATUS_CLEAN"
fi

echo "Details: ${DETAILS}"
echo "Status:  ${STATUS:-<unchanged, UCMDB_STATUS_CLEAN not set>}"

# ---------------------------------------------------------------------------
# 2. Authenticate to UCMDB
# ---------------------------------------------------------------------------
echo "Authenticating to UCMDB ..."
AUTH_BODY=$(jq -n \
  --arg u "$UCMDB_USER" --arg p "$UCMDB_PASSWORD" \
  --arg c "$UCMDB_CUSTOMER_NAME" --argjson ctx "$UCMDB_CLIENT_CONTEXT" \
  '{username:$u, password:$p, repository:"UCMDB", clientContext:$ctx, customerName:$c}')

TOKEN=$(curl -sS --fail-with-body -X POST "${API}/authenticate" \
  -H 'Content-Type: application/json' -d "$AUTH_BODY" | jq -r '.token // empty')

if [[ -z "$TOKEN" ]]; then
  echo "::error::UCMDB authentication failed (no token returned)"
  exit 1
fi
echo "::add-mask::${TOKEN}"

# ---------------------------------------------------------------------------
# 3. Update the CI
# ---------------------------------------------------------------------------
PAYLOAD=$(jq -n \
  --arg id "$UCMDB_CI_ID" --arg type "$UCMDB_CI_TYPE" \
  --arg details "$DETAILS" --arg status "$STATUS" \
  '[{ucmdbId:$id, type:$type,
     properties: ({vulnerability_details:$details}
                  + (if $status == "" then {} else {vulnerability_status:$status} end))}]')

echo "Updating CI ${UCMDB_CI_ID} (${UCMDB_CI_TYPE}) ..."
RESP=$(curl -sS --fail-with-body -X PUT "${API}/dataModel/ci" \
  -H 'Accept: application/json' -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${TOKEN}" -d "$PAYLOAD")
echo "$RESP" | jq .

if ! jq -e --arg id "$UCMDB_CI_ID" '.updatedCis | index($id)' <<<"$RESP" >/dev/null; then
  echo "::error::UCMDB did not report CI ${UCMDB_CI_ID} as updated"
  exit 1
fi

# ---------------------------------------------------------------------------
# 4. Job summary
# ---------------------------------------------------------------------------
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "### UCMDB update"
    echo ""
    echo "| Field | Value |"
    echo "|---|---|"
    echo "| CI | \`${UCMDB_CI_ID}\` (${UCMDB_CI_TYPE}) |"
    echo "| FoD release | ${FOD_RELEASE} |"
    echo "| Critical / High / Medium / Low | ${CRIT} / ${HIGH} / ${MED} / ${LOW} |"
    echo "| Policy | ${POLICY} |"
    echo "| vulnerability_status | ${STATUS:-unchanged} |"
  } >> "$GITHUB_STEP_SUMMARY"
fi

echo "UCMDB CI updated."
