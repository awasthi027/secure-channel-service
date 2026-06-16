# Secure Channel Management Service

Spring Boot service that enforces secure-channel-first communication.

## What it implements

- Secure channel creation bound to `deviceId + deviceType`.
- Session lifecycle: `ACTIVE`, `EXPIRED`, `TERMINATED`.
- HMAC lifecycle: generation, status, revocation, expiration.
- HMAC-SHA256 request signing for protected APIs.
- Replay protection with timestamp, nonce, and request ID.
- Audit-friendly security event logging without key exposure.

## Tech Stack

- Java 21
- Spring Boot 3.3
- Maven
- In-memory stores (`ConcurrentHashMap`) for demo use

## Configure registered devices

Edit `src/main/resources/application.yml`:

```yaml
secure:
  registered-devices:
    - device-id: device-123
      device-type: MOBILE
```

## Build and run

```bash
mvn spring-boot:run
```

## Railway deployment

This service supports two transport modes:

- **Local/dev mode**: direct TLS + mTLS on `https://localhost:8443`
- **Railway mode**: Railway terminates TLS at the edge and forwards plain HTTP to the container

The included `Dockerfile` is preconfigured for Railway by setting:

- `SERVER_SSL_ENABLED=false`
- `SECURE_CLIENT_IDENTITY_MODE=header`
- `SECURE_CLIENT_IDENTITY_HEADER=X-Device-Id`

In Railway mode, clients must:

- call the public HTTPS URL, for example `https://secure-channel-service-production.up.railway.app`
- send `X-Device-Id` on `POST /ecdh/init`
- send `X-Device-Id` on protected API calls alongside the existing signed headers

Local mTLS clients should continue using the localhost HTTPS URL and client certificates.

## API overview

### Secure channel APIs

- `POST /secure-channel/create`
- `POST /secure-channel/terminate`
- `GET /secure-channel/status?sessionId=...`

### ECDH handshake APIs (learning flow)

- `POST /ecdh/init` (creates `PENDING` session, returns server public key + proof)
- `POST /ecdh/confirm` (verifies client proof, activates session, provisions HMAC)

### HMAC APIs

- `POST /hmac/generate`
- `POST /hmac/terminate`
- `GET /hmac/status?sessionId=...`

### Protected API sample

- `POST /protected/echo`

This endpoint requires headers:

- `X-Session-Id`
- `X-Signature`
- `X-Timestamp` (epoch millis)
- `X-Nonce`
- `X-Request-Id`

## Request signing

Canonical string format:

```text
METHOD
PATH
SESSION_ID
TIMESTAMP
NONCE
REQUEST_ID
BASE64_SHA256(BODY)
```

Signature:

- `Base64(HMAC-SHA256(canonical, hmacKey))`

## Example flow

1. Create channel and obtain `sessionId` + one-time `hmacKey`.
2. Sign protected requests with required headers.
3. Call protected APIs.
4. Revoke HMAC or terminate session when done.

ECDH flow:

1. Client sends ephemeral public key and nonce to `POST /ecdh/init`.
2. Server returns its ephemeral public key, nonce, and proof.
3. Client derives shared secret, verifies proof, then sends `clientProof` to `POST /ecdh/confirm`.
4. Server activates session and provisions HMAC derived from the same shared secret.

## Security notes

- Use HTTPS/TLS in deployment.
- HMAC keys are encrypted at rest in service memory.
- Key material is never logged.
- Replay attempts are rejected.

## Running tests

```bash
mvn test
```
