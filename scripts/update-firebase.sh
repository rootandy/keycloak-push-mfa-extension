#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/update-firebase.sh <pseudonymous-user-id> <new-firebase-id>

Environment overrides:
  REALM_BASE            Realm base URL (default: stored value, fallback http://localhost:8080/realms/push-mfa)
  DEVICE_STATE_DIR      Directory storing device state from enroll.sh (default: scripts/device-state)
  TOKEN_ENDPOINT        Override token endpoint (default: stored value)
  DEVICE_CLIENT_ID      Override OAuth client ID (default: stored value)
  DEVICE_CLIENT_SECRET  Override OAuth client secret (default: stored value)
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" || $# -ne 2 ]]; then
  usage
  exit $([[ $# -eq 2 ]] && [[ ${1:-} != "-h" && ${1:-} != "--help" ]] && echo 1 || echo 0)
fi

PSEUDONYMOUS_ID=$1
NEW_FIREBASE_ID=$2

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMON_SIGN_JWS="${COMMON_SIGN_JWS:-"$SCRIPT_DIR/sign_jws.py"}"
source "$SCRIPT_DIR/common.sh"
common::ensure_crypto

REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEVICE_STATE_DIR=${DEVICE_STATE_DIR:-"$REPO_ROOT/scripts/device-state"}
STATE_FILE="$DEVICE_STATE_DIR/${PSEUDONYMOUS_ID}.json"

if [[ ! -f "$STATE_FILE" ]]; then
  echo "error: device state file not found: $STATE_FILE" >&2
  exit 1
fi

STATE=$(cat "$STATE_FILE")
USER_ID=$(echo "$STATE" | jq -r '.userId')
DEVICE_ID=$(echo "$STATE" | jq -r '.deviceId')
PRIVATE_KEY_B64=$(echo "$STATE" | jq -r '.privateKey')
KEY_ID=$(echo "$STATE" | jq -r '.keyId // "push-device-client-key"')
PUBLIC_JWK=$(echo "$STATE" | jq -c '.publicJwk // empty')
REALM_BASE_DEFAULT=$(echo "$STATE" | jq -r '.realmBase // empty')
REALM_BASE=${REALM_BASE:-$REALM_BASE_DEFAULT}
REALM_BASE=${REALM_BASE:-http://localhost:8080/realms/push-mfa}
TOKEN_ENDPOINT_STATE=$(echo "$STATE" | jq -r '.tokenEndpoint // empty')
CLIENT_ID_STATE=$(echo "$STATE" | jq -r '.clientId // empty')
CLIENT_SECRET_STATE=$(echo "$STATE" | jq -r '.clientSecret // empty')
TOKEN_ENDPOINT=${TOKEN_ENDPOINT:-$TOKEN_ENDPOINT_STATE}
CLIENT_ID=${DEVICE_CLIENT_ID:-$CLIENT_ID_STATE}
CLIENT_SECRET=${DEVICE_CLIENT_SECRET:-$CLIENT_SECRET_STATE}
SIGNING_ALG=$(echo "$STATE" | jq -r '.signingAlg // (.publicJwk.alg // "RS256")')
SIGNING_ALG=$(common::to_upper "$SIGNING_ALG")

if [[ -z $USER_ID || -z $DEVICE_ID || -z $PRIVATE_KEY_B64 || -z $PUBLIC_JWK ]]; then
  echo "error: device state missing required fields" >&2
  exit 1
fi
if [[ -z ${TOKEN_ENDPOINT:-} || -z ${CLIENT_ID:-} || -z ${CLIENT_SECRET:-} ]]; then
  echo "error: missing token endpoint or client credentials" >&2
  exit 1
fi

KEY_FILE="$DEVICE_STATE_DIR/${PSEUDONYMOUS_ID}.key"
printf '%s' "$PRIVATE_KEY_B64" | common::write_private_key "$KEY_FILE"

TOKEN_RESPONSE=$(common::fetch_access_token "$TOKEN_ENDPOINT" "$CLIENT_ID" "$CLIENT_SECRET" "$KEY_FILE" "$PUBLIC_JWK" "$KEY_ID" "$USER_ID" "$DEVICE_ID" "$SIGNING_ALG")
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token // empty')
if [[ -z $ACCESS_TOKEN || $ACCESS_TOKEN == "null" ]]; then
  echo "error: failed to obtain access token" >&2
  echo "$TOKEN_RESPONSE" >&2
  exit 1
fi

UPDATE_URL="$REALM_BASE/push-mfa/device/firebase"
UPDATE_DPOP=$(common::create_dpop_proof "PUT" "$UPDATE_URL" "$KEY_FILE" "$PUBLIC_JWK" "$KEY_ID" "$USER_ID" "$DEVICE_ID" "$SIGNING_ALG")
echo ">> Updating Firebase ID for $PSEUDONYMOUS_ID"
curl -s -X PUT \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $UPDATE_DPOP" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg firebaseId "$NEW_FIREBASE_ID" '{"firebaseId": $firebaseId}')" \
  "$UPDATE_URL" | jq
