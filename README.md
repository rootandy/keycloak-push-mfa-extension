# Keycloak Push MFA Extension

## Introduction

:warning: This is a proof-of-concept implementation intended for educational purposes only. Do not use in production environments.

This project extends Keycloak with a push-style second factor that mimics passkey primitives. After initial enrollment, the mobile app never receives the real user identifier from Keycloak; instead, it works with a pseudonymous id that only the app can map back to the real user. Everything is implemented with standard Keycloak SPIs plus a small JAX-RS resource exposed under `/realms/<realm>/push-mfa`.

- Build the provider: `mvn -DskipTests package`
- Run Keycloak locally (imports realm + loads provider): `docker compose up --build keycloak`
- Keycloak admin UI: <http://localhost:8080> (`admin` / `admin`)
- Test realm: `push-mfa` with the user `test / test`

## High Level Flow

1. **Enrollment challenge (RequiredAction):** Keycloak renders a QR code that encodes the realm-signed `enrollmentToken` (in this demo it uses a custom scheme: `push-mfa-login-app://?token=<enrollmentToken>`). The token is a JWT signed with the realm key and contains user id (`sub`), username, `enrollmentId`, and a Base64URL nonce.

   ```json
   {
     "_comment": "enrollmentToken payload (realm -> device)",
     "iss": "http://localhost:8080/realms/push-mfa",
     "aud": "push-mfa",
     "typ": "push-enroll-challenge",
     "sub": "87fa1c21-1b1e-4af8-98b1-1df2e90d3c3d",
     "username": "test",
     "realm": "push-mfa",
     "enrollmentId": "b15ef7f2-494c-4f03-a9b4-5b7eb4a71caa",
     "nonce": "JYlLk0d9h9zGN7kMd8n5Vw",
     "exp": 1731403200,
     "iat": 1731402900
   }
   ```

2. **Device enrollment response:** The app verifies the token using the realm JWKS, generates its own key pair and `kid`, and posts a JWT back to Keycloak that echoes the nonce and enrollment id, embeds the JWK under `cnf.jwk`, and introduces a pseudonymous user id. The JWT header uses the device `kid`; the payload looks like this:

   ```json
   {
     "_comment": "device enrollment payload (device -> realm)",
     "enrollmentId": "b15ef7f2-494c-4f03-a9b4-5b7eb4a71caa",
     "nonce": "JYlLk0d9h9zGN7kMd8n5Vw",
     "sub": "87fa1c21-1b1e-4af8-98b1-1df2e90d3c3d",
     "deviceType": "ios",
     "firebaseId": "mock-fcm-token",
     "pseudonymousUserId": "device-alias-bf7a9f52",
     "deviceId": "device-3d7a4e65-9bd6-4df3-9c7d-2b3e0ce9e1a5",
     "deviceLabel": "Demo Phone",
     "cnf": {
       "jwk": {
         "kty": "RSA",
         "n": "uVvbx3-...",
         "e": "AQAB",
         "alg": "RS256",
         "use": "sig",
         "kid": "device-key-31c3"
       }
     },
     "iat": 1731402910,
     "exp": 1731403200
   }
   ```

3. **Confirm token delivery:** Every login creates a fresh push challenge. Keycloak signs a `confirmToken` using the realm key and displays/logs it. This token is what would be sent via Firebase: it only contains the pseudonymous user id and the challenge id (`cid`), so the push provider learns nothing about the real user or that it is a login.

   ```json
   {
     "_comment": "confirmToken payload (realm -> device via Firebase/FCM)",
     "iss": "http://localhost:8080/realms/push-mfa",
     "sub": "device-alias-bf7a9f52",
     "typ": "1",
     "ver": "1",
     "cid": "1a6d6a0b-3385-4772-8eb8-0d2f4dbd25a4",
     "client_id": "test-app",
     "iat": 1731402960,
     "exp": 1731403260
   }
   ```

4. **Login approval:** The device looks up the confirm token’s `sub`, resolves it to the real Keycloak user id in its secure storage, and signs a JWT (`loginToken`) with the same key pair from enrollment. The payload echoes the challenge id (`cid`), the real `sub`, and the desired `action` (`approve`/`deny`) so Keycloak can fully trust the intent because it is covered by the device signature (no nonce is needed because possession of the device key already proves authenticity, and `cid` is unguessable).

   ```json
   {
     "_comment": "login approval payload (device -> realm)",
     "cid": "1a6d6a0b-3385-4772-8eb8-0d2f4dbd25a4",
     "sub": "87fa1c21-1b1e-4af8-98b1-1df2e90d3c3d",
     "deviceId": "device-3d7a4e65-9bd6-4df3-9c7d-2b3e0ce9e1a5",
     "action": "approve",
     "exp": 1731403020
   }
   ```

   For endpoints such as `/login/pending`, `/device/firebase`, `/device/rotate-key`, and `/login/challenges/{cid}/respond`, the device presents a lightweight **DPoP proof** in the `DPoP` header. (Enrollment completion still uses the specialized JWT described above.) The proof payload is short-lived and binds the request to a physical device:

   ```json
   {
     "_comment": "DPoP proof payload (header for REST endpoints using device proofs)",
     "sub": "87fa1c21-1b1e-4af8-98b1-1df2e90d3c3d",
     "deviceId": "device-3d7a4e65-9bd6-4df3-9c7d-2b3e0ce9e1a5",
     "exp": 1731402960
   }
   ```

   To call those endpoints the device first requests an OAuth access token that is bound to the same key via DPoP:

   ```bash
   REALM_BASE=http://localhost:8080/realms/push-mfa
   TOKEN_ENDPOINT="$REALM_BASE/protocol/openid-connect/token"
   CLIENT_ID=push-device-client
   CLIENT_SECRET=device-client-secret
   DEVICE_JWK='{"kty":"RSA","n":"...","e":"AQAB","kid":"device-key-31c3"}'
   DEVICE_KEY=./device-private-key.pem

   # Pseudocode: construct the DPoP JWT header/payload and sign it with the device key.
   # Header always includes the device JWK. The payload's htm/htu must match the HTTP method/URL,
   # `sub` must be the Keycloak user id, and `deviceId` the ID assigned during enrollment.
   DPOP_PROOF=$(echo -n "<header>.<payload>" | openssl dgst -binary -sha256 -sign "$DEVICE_KEY" | base64urlencode)

   curl -s -X POST "$TOKEN_ENDPOINT" \
     -H "DPoP: $DPOP_PROOF" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=client_credentials" \
     -d "client_id=$CLIENT_ID" \
     -d "client_secret=$CLIENT_SECRET"
   ```

   The response contains `access_token`. Every subsequent REST call uses `Authorization: DPoP <access_token>` plus a fresh DPoP proof for that specific HTTP method and URL.

5. **Browser wait + polling:** The Keycloak login UI polls its own challenge store. Once the challenge is approved (or denied) the form resolves automatically. Polling `GET /login/pending` from the app is optional; the confirm token already carries the `cid`.

> This PoC demonstrates both real-time strategies: the enrollment UI listens to server-sent events (SSE) emitted for its challenge, while the login approval screen continues to use classic polling so both patterns can be evaluated side-by-side.

### Enrollment SSE details

- **Endpoint:** `GET /realms/<realm>/push-mfa/enroll/challenges/{challengeId}/events?secret=<watchSecret>` streams `text/event-stream`. The `watchSecret` is a per-challenge random value stored in `PushChallenge.watchSecret`; it prevents other sessions from observing enrollment progress.
- **Server loop:** `PushMfaResource#emitEnrollmentEvents` runs asynchronously, polls the challenge store every second, and emits a `status` event whenever the challenge state changes or an error occurs. Each event payload is JSON shaped like:

  ```json
  {
    "status": "PENDING | APPROVED | DENIED | NOT_FOUND | FORBIDDEN | INVALID | INTERRUPTED",
    "challengeId": "<uuid>",
    "expiresAt": "2025-11-14T13:16:12.902Z",
    "resolvedAt": "2025-11-14T13:16:22.180Z"
  }
  ```

  Failures (missing secret, secret mismatch, challenge not found, thread interruption, serialization errors) are logged at INFO level so pod logs provide a complete timeline for troubleshooting.

- **Client behavior:** The enrollment page (`push-register.ftl`) spins up a single `EventSource` pointed at the `eventsUrl`. When a non-`PENDING` status arrives the stream is closed and the hidden `check` form is submitted, allowing Keycloak’s RequiredAction to complete without any manual refresh. If the connection drops (pod restart, network flap) the browser’s native EventSource automatically retries; the script only logs `error` events for visibility.

- **No polling fallback:** Unlike earlier iterations the SSE client never schedules timer-based polling. If EventSource is missing (very old browsers) the script simply logs a warning, which is acceptable in this demo because enrollment is expected to run in modern browsers.

## Custom Keycloak APIs

All endpoints live under `/realms/push-mfa/push-mfa`. Enrollment completion posts the device JWT in the request body, while every other endpoint requires a DPoP header signed with the device key (the structure shown above). There is no Keycloak-issued service token—authentication is fully tied to the device key material.

### Complete enrollment

```
POST /realms/push-mfa/push-mfa/enroll/complete
Content-Type: application/json

{
  "token": "<device-signed enrollment JWT>"
}
```

Keycloak verifies the signature using `cnf.jwk`, persists the credential (JWK, algorithm, deviceType, firebaseId, pseudonymousUserId, deviceId, deviceLabel), and resolves the enrollment challenge. The `deviceLabel` is read from the JWT payload (falls back to `PushMfaConstants.USER_CREDENTIAL_DISPLAY_NAME` when absent).

```json
{
  "status": "enrolled"
}
```

### List pending login challenges

```
GET /realms/push-mfa/push-mfa/login/pending?userId=<keycloak-user-id>
Authorization: DPoP <access-token>
DPoP: <proof JWT>
```

The `DPoP` header carries a short-lived JWT signed with the device key (see the example above). Its payload must include `htm`, `htu`, `iat`, `jti`, plus the custom `sub` (Keycloak user id) and `deviceId`. Keycloak verifies the signature using the stored credential and only returns pending challenges tied to that device id.

```json
{
  "challenges": [
    {
      "userId": "87fa1c21-1b1e-4af8-98b1-1df2e90d3c3d",
      "cid": "1a6d6a0b-3385-4772-8eb8-0d2f4dbd25a4",
      "expiresAt": "2025-11-14T13:16:12.902Z",
      "clientId": "test-app"
    }
  ]
}
```

If the credential referenced by the device assertion does not own an outstanding challenge, the array is empty even if other devices for the same user are awaiting approval.

### Approve or deny a challenge

```
POST /realms/push-mfa/push-mfa/login/challenges/{cid}/respond
Authorization: DPoP <access-token>
DPoP: <proof JWT>
Content-Type: application/json

{
  "token": "<device-signed login JWT>"
}
```

Keycloak verifies the DPoP proof to authenticate the device, then validates the login token (stored in the request body) with the saved JWK. The login token must carry `cid`, `sub`, `deviceId`, and `action`. `"action": "approve"` marks the challenge as approved; `"action": "deny"` marks it as denied. Any other value is rejected.

```json
{ "status": "approved" }
```

### Update the Firebase registration

```
PUT /realms/push-mfa/push-mfa/device/firebase
Authorization: DPoP <access-token>
DPoP: <proof JWT>
Content-Type: application/json

{
  "firebaseId": "new-fcm-token"
}
```

Keycloak authenticates the request with the current device key and replaces the stored Firebase/FCM identifier tied to that credential. The response body is `{ "status": "updated" }` (or `"unchanged"` if the value was already in sync).

> Demo helper: `scripts/update-firebase.sh <pseudonymous-id> <new-firebase-id>`

### Rotate the device key

```
PUT /realms/push-mfa/push-mfa/device/rotate-key
Authorization: DPoP <access-token>
DPoP: <proof JWT>
Content-Type: application/json

{
  "publicKeyJwk": {
    "kty": "RSA",
    "n": "....",
    "e": "AQAB",
    "alg": "RS256",
    "use": "sig",
    "kid": "device-key-rotated"
  },
  "algorithm": "RS256"
}
```

The DPoP proof must be signed with the *existing* device key. After validation, Keycloak swaps the stored JWK/algorithm (and updates the credential timestamp). The response is `{ "status": "rotated" }`. Future API calls must be signed with the newly-installed key.

> Demo helper: `scripts/rotate-device-key.sh <pseudonymous-id>`

## App Implementation Notes

- **Realm verification:** Enrollment starts when the app scans the QR code and reads `enrollmentToken`. Verify the JWT with the realm JWKS (`/realms/push-mfa/protocol/openid-connect/certs`) before trusting its contents.
- **Device key material:** Generate a key pair per device, select a unique `kid`, and keep the private key in the device secure storage. Persist and exchange the public component exclusively as a JWK (the same document posted in `cnf.jwk`).
- **State to store locally:** pseudonymous user id ↔ real Keycloak user id mapping, the device key pair, the `kid`, `deviceType`, `firebaseId`, preferred `deviceLabel`, and any metadata needed to post to Keycloak again.
- **Confirm token handling:** When the confirm token arrives through Firebase (or when the user copies it from the waiting UI), decode the JWT, extract `cid` and `sub`, and either call `/login/pending` (optional) or immediately sign the login approval JWT and post it to `/login/challenges/{cid}/respond`.
- **Pending challenge discovery:** Before calling `/login/pending`, mint a DPoP proof that includes the HTTP method (`htm`), full URL (`htu`), `sub`, `deviceId`, `iat`, and a fresh `jti`, and send it via the `DPoP` header so Keycloak can scope the response to that physical device.
- **Access tokens:** Obtain a short-lived access token via the realm’s token endpoint using the device client credentials. The token request itself must include a DPoP proof, and each subsequent REST call must send `Authorization: DPoP <access-token>` alongside a fresh `DPoP` header signed with the same key.
- **Request authentication:** Every REST call (aside from enrollment, which already embeds the device key) must include a DPoP proof signed with the current device key. The proof binds the request method and URL to the hardware-backed key, making replay or reverse-engineering of a shared client secret ineffective.
- **Error handling:** Enrollment and login requests return structured error responses (`400`, `403`, or `404`) when the JWTs are invalid, expired, or mismatched. Surface those errors to the user to re-trigger the flow if necessary.
- **Key rotation / Firebase changes:** Use the `/device/firebase` and `/device/rotate-key` endpoints (described above) to update the stored metadata while authenticating with the current device key. Rotation should generate a fresh key pair, send the public JWK + algorithm, and immediately start using the new key for every subsequent JWT.

With these primitives an actual mobile app UI or automation can be layered on top without depending on helper shell scripts.

## Security Guarantees and Mobile Obligations

### Security guarantees provided by the extension

- **Signed artifacts end-to-end:** Enrollment and confirm tokens are JWTs signed by realm keys, and device responses are signed with the device key pair. Every hop is authenticated and tamper-evident.
- **Challenge binding:** Enrollment tokens embed a nonce plus enrollment id, and login approvals reference the opaque challenge id (`cid`), so replaying a response for a different user or challenge fails.
- **Limited data exposure:** Confirm tokens carry only the pseudonymous user id and challenge id, preventing the push channel from learning the user’s identity or whether a login succeeded.
- **Short-lived state:** Challenge lifetime equals every token’s `exp`, so an attacker has at most ~2 minutes to replay data even if transport is intercepted.
- **Key continuity:** The stored `cnf.jwk` couples future approvals to the same hardware-backed key, giving Keycloak a stable signal that a response truly came from the enrolled device.
- **Hardware-bound authentication:** Every REST call is authenticated with a JWT signed by that device’s private key, which is far more secure than distributing an easily reverse-engineered client secret inside the mobile app. Stealing the client binary is no longer enough; the attacker must compromise the device’s key material as well.
- **DPoP-bound access tokens:** Each access token carries a `cnf.jkt` thumbprint that must match the enrolled device’s JWK. The server recomputes the thumbprint from the stored credential and rejects any DPoP proof or access token that doesn’t match, so only the key pair used during enrollment can successfully invoke the APIs.

### Obligations for the mobile application

- **Verify every JWT:** Check issuer, audience, signature, and `exp` on enrollment and confirm tokens before acting. Fetch the realm JWKS over HTTPS and cache it defensively.
- **Protect the device key pair:** Generate it with high-entropy sources, store the private key in Secure Enclave/Keystore/KeyChain, and never export it. Rotate/re-enroll immediately if compromise is suspected.
- **Enforce challenge integrity:** When a confirm token arrives, compare the `cid`, `sub`, and `client_id` against locally stored state and discard anything unexpected or expired.
- **Secure transport:** Call the Keycloak endpoints only over TLS, validate certificates (no user-controlled CA overrides), and pin if your threat model requires it.
- **Harden local state:** Keep the pseudonymous ↔ real user mapping, firebase identifiers, and enrollment metadata in encrypted storage with OS-level protection.
- **Surface errors to users:** Treat 4xx responses (expired, invalid signature, nonce mismatch) as security events, notifying the user and requiring a fresh enrollment or login attempt rather than silently retrying.
