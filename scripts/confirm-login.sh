#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/confirm-login.sh <confirm-token>

Environment overrides:
  REALM_BASE               Realm base URL (default: http://localhost:8080/realms/push-mfa). Falls back to stored value.
  DEVICE_STATE_DIR         Directory storing device state from enroll.sh (default: scripts/device-state)
  LOGIN_ACTION             Action encoded in the device token (approve or deny, default: approve)
  TOKEN_ENDPOINT           Override token endpoint (default: stored value)
  DEVICE_CLIENT_ID         Override OAuth client ID (default: stored value)
  DEVICE_CLIENT_SECRET     Override OAuth client secret (default: stored value)
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" || $# -ne 1 ]]; then
  usage
  exit $([[ $# -eq 1 ]] && [[ ${1:-} != "-h" && ${1:-} != "--help" ]] && echo 1 || echo 0)
fi

CONFIRM_TOKEN=$1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEVICE_STATE_DIR=${DEVICE_STATE_DIR:-"$REPO_ROOT/scripts/device-state"}
TOKEN_TTL_SECONDS=${TOKEN_TTL_SECONDS:-60}

if [[ ! -d "$DEVICE_STATE_DIR" ]]; then
  echo "error: device state directory '$DEVICE_STATE_DIR' does not exist" >&2
  exit 1
fi

b64urlencode() {
  python3 -c "import base64, sys; data = sys.stdin.buffer.read(); print(base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii'))"
}

b64urldecode() {
  python3 -c 'import sys, base64
s = sys.stdin.read().strip()
s += "=" * (-len(s) % 4)  # fix missing padding
sys.stdout.buffer.write(base64.urlsafe_b64decode(s))'
}

create_dpop_proof() {
  local method=$1
  local url=$2
  local key_file=$3
  local jwk_json=$4
  local key_id=$5
  local user_id=$6
  local device_id=$7
  local ttl=${8:-60}
  local iat=$(date +%s)
  local jti=$(python3 - <<'PY'
import uuid
print(str(uuid.uuid4()))
PY
)
  local payload=$(jq -n \
    --arg htm "$method" \
    --arg htu "$url" \
    --arg sub "$user_id" \
    --arg deviceId "$device_id" \
    --arg iat "$iat" \
    --arg jti "$jti" \
    '{"htm": $htm, "htu": $htu, "sub": $sub, "deviceId": $deviceId, "iat": ($iat|tonumber), "jti": $jti}')
  local header_json=$(jq -cn --arg alg "RS256" --arg typ "dpop+jwt" --arg kid "$key_id" --argjson jwk "$jwk_json" '{alg:$alg,typ:$typ,kid:$kid,jwk:$jwk}')
  local header_b64=$(printf '%s' "$header_json" | b64urlencode)
  local payload_b64=$(printf '%s' "$payload" | b64urlencode)
  local signature_b64=$(printf '%s' "$header_b64.$payload_b64" | openssl dgst -binary -sha256 -sign "$key_file" | b64urlencode)
  echo "$header_b64.$payload_b64.$signature_b64"
}

obtain_access_token() {
  local proof=$(create_dpop_proof "POST" "$TOKEN_ENDPOINT" "$KEY_FILE" "$PUBLIC_JWK" "$KID" "$USER_ID" "$DEVICE_ID" "$TOKEN_TTL_SECONDS")
  curl -s -X POST \
    -H "DPoP: $proof" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials" \
    -d "client_id=$CLIENT_ID" \
    -d "client_secret=$CLIENT_SECRET" \
    "$TOKEN_ENDPOINT"
}

echo ">> Decoding confirm token"
CONFIRM_PAYLOAD=$(echo -n "$CONFIRM_TOKEN" | cut -d'.' -f2 | b64urldecode)

if [[ -z $CONFIRM_PAYLOAD ]]; then
  echo "error: invalid confirm token" >&2
  exit 1
fi

PSEUDONYMOUS_ID=$(echo "$CONFIRM_PAYLOAD" | jq -r '.sub')
CHALLENGE_ID=$(echo "$CONFIRM_PAYLOAD" | jq -r '.cid // empty')
if [[ -z $PSEUDONYMOUS_ID || $PSEUDONYMOUS_ID == "null" ]]; then
  echo "error: confirm token missing pseudonymous user id" >&2
  exit 1
fi

if [[ -z $CHALLENGE_ID || $CHALLENGE_ID == "null" ]]; then
  echo "error: confirm token missing challenge id" >&2
  exit 1
fi

STATE_FILE="$DEVICE_STATE_DIR/${PSEUDONYMOUS_ID}.json"
if [[ ! -f "$STATE_FILE" ]]; then
  echo "error: no device state found for pseudonymous id '$PSEUDONYMOUS_ID' ($STATE_FILE)" >&2
  exit 1
fi

STATE=$(cat "$STATE_FILE")
USER_ID=$(echo "$STATE" | jq -r '.userId')
DEVICE_ID=$(echo "$STATE" | jq -r '.deviceId')
PRIVATE_KEY_B64=$(echo "$STATE" | jq -r '.privateKey')
KID=$(echo "$STATE" | jq -r '.keyId // "push-device-client-key"')
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

if [[ -z $USER_ID || -z $DEVICE_ID || -z $PRIVATE_KEY_B64 || -z $PUBLIC_JWK || -z ${TOKEN_ENDPOINT:-} || -z ${CLIENT_ID:-} || -z ${CLIENT_SECRET:-} ]]; then
  echo "error: device state missing required fields" >&2
  exit 1
fi

KEY_FILE="$DEVICE_STATE_DIR/${PSEUDONYMOUS_ID}.key"
python3 - "$PRIVATE_KEY_B64" "$KEY_FILE" <<'PY'
import base64, sys
data = sys.argv[1]
path = sys.argv[2]
with open(path, 'wb') as fh:
    fh.write(base64.b64decode(data))
PY

TOKEN_RESPONSE=$(obtain_access_token)
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token // empty')
TOKEN_TYPE=$(echo "$TOKEN_RESPONSE" | jq -r '.token_type // empty')
if [[ -z $ACCESS_TOKEN || $ACCESS_TOKEN == "null" ]]; then
  echo "error: failed to obtain access token" >&2
  echo "$TOKEN_RESPONSE" >&2
  exit 1
fi

PENDING_URL="$REALM_BASE/push-mfa/login/pending"
echo ">> Demo: listing pending challenges (response is informational)"
PENDING_HTU="$PENDING_URL?userId=$USER_ID"
PENDING_DPOP=$(create_dpop_proof "GET" "$PENDING_HTU" "$KEY_FILE" "$PUBLIC_JWK" "$KID" "$USER_ID" "$DEVICE_ID" "$TOKEN_TTL_SECONDS")
curl -s -G \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $PENDING_DPOP" \
  --data-urlencode "userId=$USER_ID" \
  "$PENDING_URL" | jq

EXPIRY=$(($(date +%s) + 120))
LOGIN_ACTION=${LOGIN_ACTION:-approve}
LOGIN_PAYLOAD=$(jq -n \
  --arg cid "$CHALLENGE_ID" \
  --arg sub "$USER_ID" \
  --arg deviceId "$DEVICE_ID" \
  --arg exp "$EXPIRY" \
  --arg action "$LOGIN_ACTION" \
  '{"cid": $cid, "sub": $sub, "deviceId": $deviceId, "exp": ($exp|tonumber), "action": ($action|ascii_downcase)}')

LOGIN_HEADER_B64=$(printf '{"alg":"RS256","kid":"%s","typ":"JWT"}' "$KID" | b64urlencode)
LOGIN_PAYLOAD_B64=$(printf '%s' "$LOGIN_PAYLOAD" | b64urlencode)
LOGIN_SIGNATURE_B64=$(printf '%s' "$LOGIN_HEADER_B64.$LOGIN_PAYLOAD_B64" | openssl dgst -binary -sha256 -sign "$KEY_FILE" | b64urlencode)
DEVICE_LOGIN_TOKEN="$LOGIN_HEADER_B64.$LOGIN_PAYLOAD_B64.$LOGIN_SIGNATURE_B64"

RESPOND_URL="$REALM_BASE/push-mfa/login/challenges/$CHALLENGE_ID/respond"
echo ">> Responding to challenge"
RESPOND_DPOP=$(create_dpop_proof "POST" "$RESPOND_URL" "$KEY_FILE" "$PUBLIC_JWK" "$KID" "$USER_ID" "$DEVICE_ID" "$TOKEN_TTL_SECONDS")
curl -s -X POST \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $RESPOND_DPOP" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg token "$DEVICE_LOGIN_TOKEN" '{"token": $token}')" \
  "$RESPOND_URL" | jq
