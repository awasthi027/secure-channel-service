# Railway Deployment Guide

This service supports two deployment modes:

## Mode 1: Local Development (Mutual TLS)

For local development and testing with direct mTLS certificates:

```bash
# Run with embedded certificates on default HTTPS port
mvn spring-boot:run

# Service listens on: https://localhost:8443
```

**Configuration:**
- TLS is **enabled** in-container: `server.ssl.enabled=true`
- Client authentication is **required**: `server.ssl.client-auth=need`
- Identity extraction via **mTLS certificate CN** from client cert

**Client requirements:**
```swift
let baseURL = "https://localhost:8443"
// URLSession with MTLSDelegate using client.p12 certificate
```

---

## Mode 2: Railway Production (Edge TLS)

Railway terminates TLS at the edge and forwards plain HTTP to the container. The included `Dockerfile` is **pre-configured** for this mode.

### Deploy to Railway

```bash
# From the repository root
railway login
railway up
```

**From Railway dashboard:**
1. Add a PostgreSQL plugin (if persistence is needed later)
2. Set environment variables (see below)
3. View logs in real-time

### Configuration

The `Dockerfile` sets these environment defaults:

```dockerfile
ENV SERVER_SSL_ENABLED=false
ENV SECURE_CLIENT_IDENTITY_MODE=header
ENV SECURE_CLIENT_IDENTITY_HEADER=X-Device-Id
```

**What this means:**
- The container runs on plain HTTP (Railway edge handles HTTPS)
- Device identity comes from an HTTP header, not a certificate
- No in-container TLS overhead

### Client Requirements

Update your iOS client to send the Railway identity header:

```swift
// SecureNetworkEnvironment.swift
let baseURL = "https://secure-channel-service-production.up.railway.app"
let deviceIdentityHeader = "X-Device-Id"

// Only use mTLS for localhost
if baseURL.contains("localhost") {
    let delegate = MTLSDelegate(p12Name: "client", p12Password: "client-secret")
    session = URLSession(configuration: .default, delegate: delegate, delegateQueue: .main)
} else {
    // Railway: plain HTTPS, no client cert needed
    session = URLSession(configuration: .default)
}

// Send device identity header on all requests
urlRequest.setValue(deviceId, forHTTPHeaderField: deviceIdentityHeader)
```

#### Request Headers on Railway

**POST `/ecdh/init`** (and all protected APIs):
```http
POST https://secure-channel-service-production.up.railway.app/ecdh/init HTTP/1.1
Content-Type: application/json
X-Device-Id: device-123

{
  "deviceId": "device-123",
  "deviceType": "mobile",
  "clientPublicKey": "...",
  "clientNonce": "..."
}
```

**Protected API calls** (POST `/protected/echo`, GET `/channel/status`, etc.):
```http
GET https://secure-channel-service-production.up.railway.app/channel/status HTTP/1.1
X-Session-Id: <sessionId>
X-Request-Timestamp: <epoch-millis>
X-Request-Nonce: <uuid>
X-Request-Signature: <hmac-sha256-base64>
X-Device-Id: device-123
```

---

## Environment Variables

You can override defaults by setting environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `PORT` | `8080` | Container HTTP port (leave default for Railway) |
| `SERVER_SSL_ENABLED` | `false` | Enable/disable in-container TLS |
| `SERVER_SSL_CLIENT_AUTH` | `need` (if SSL enabled) | mTLS requirement: `need`, `optional`, or `none` |
| `SECURE_CLIENT_IDENTITY_MODE` | `header` | How to extract device ID: `mtls` or `header` |
| `SECURE_CLIENT_IDENTITY_HEADER` | `X-Device-Id` | HTTP header name for device identity |

### Use mTLS in Railway (Advanced)

If you want to keep mTLS in Railway, set:

```bash
SERVER_SSL_ENABLED=true
SECURE_CLIENT_IDENTITY_MODE=mtls
```

And configure the Railway environment with your PKCS12 certificates as base64-encoded environment variables. This is **not recommended** for Railway since edge TLS is simpler and more performant.

---

## Testing Locally with Railway Configuration

To test Railway mode locally before deployment:

```bash
# Run with Railway environment settings
export SERVER_SSL_ENABLED=false
export SECURE_CLIENT_IDENTITY_MODE=header
mvn spring-boot:run -Dspring-boot.run.arguments="--server.port=8080"

# Service will listen on: http://localhost:8080
```

Run the integration tests:

```bash
mvn test -Dtest=RailwayHeaderIdentityIntegrationTest
```

All tests should pass, confirming the header-based identity extraction works.

---

## Authorization Flow Comparison

### Local (mTLS)

```
Client                           Server
  │                               │
  ├─ GenerateKeys & Nonce        │
  │                               │
  ├─ POST /ecdh/init ───────────>│
  │  (Client cert in TLS)         │(Extracts deviceId from cert CN)
  │<─ SessionId, ServerKey ───────┤
  │                               │
  ├─ Verify proof ────────────────>│
  │  POST /ecdh/confirm           │
  │                               │(Verifies proof, activates session)
  │<─ HMAC Key (sessionId) ───────┤
  │                               │
  ├─ Signed Request ────────────>│
  │  (mTLS handshake,              │(Validates signature & device)
  │   X-Session-Id header)        │
  │<─ Response ───────────────────┤
```

### Railway (Header Mode)

```
Client                           Server
  │                               │
  ├─ GenerateKeys & Nonce        │
  │                               │
  ├─ HTTPS to edge ─────┐ Railway │
  │  X-Device-Id header  ├──────>│(TLS terminated at edge)
  │  POST /ecdh/init    │         │(Receives plain HTTP)
  │                      │        ├─ Extracts deviceId from header
  │                      │<───────│
  │<─ SessionId ────────┘        │
  │  ServerKey                    │
  │                               │
  ├─ HTTPS to edge ─────────────>│
  │  X-Device-Id header           │
  │  POST /ecdh/confirm           │
  │                               │
  │<─ HMAC Key ───────────────────┤
  │                               │
  ├─ HTTPS to edge ─────────────>│
  │  X-Device-Id header           │
  │  X-Session-Id                 │
  │  X-Request-Signature          │
  │  (other headers)              │
  │                               │
  │<─ Response ───────────────────┤
```

---

## Troubleshooting

### "Error: Bad Request - This combination requires TLS"

**Cause:** Client sending HTTP to a Railway public URL that doesn't support it.

**Fix:** Ensure your client uses `https://` (not `http://`) to Railway, and uses `http://` (not `https://`) to localhost.

### "UnauthorizedException: Missing required device identity header"

**Cause:** Device sent request without `X-Device-Id` header in Railway mode.

**Fix:** Add the header to all requests:
```swift
request.setValue(environment.deviceId, forHTTPHeaderField: "X-Device-Id")
```

### "UnauthorizedException: No client certificate presented"

**Cause:** Client tried to use local mTLS configuration on Railway (or header mode on localhost with SSL enabled).

**Fix:** Match the deployment mode:
- **Local:** Use `https://localhost:8443` with mTLS certificates
- **Railway:** Use `https://secure-channel-service-production.up.railway.app` with `X-Device-Id` header

---

## Monitoring & Logs

### View logs on Railway

```bash
railway logs -f
```

Look for:
- `event=ecdh_init sessionTag=... deviceId=...` — Successful handshake initiation
- `event=ecdh_confirmed` — Session activation
- `event=request_verified` — Successful protected request verification
- `UnauthorizedException` — Failed verification (check device ID, signature, session)

### Health Check

```bash
# Local
curl https://localhost:8443/health \
  --cacert src/main/resources/certs/ca.crt

# Railway
curl https://secure-channel-service-production.up.railway.app/health
```

Response:
```json
{
  "status": "UP",
  "service": "secure-channel-service"
}
```

---

## Summary

| Aspect | Local | Railway |
|--------|-------|---------|
| **Base URL** | `https://localhost:8443` | `https://secure-channel-service-production.up.railway.app` |
| **TLS** | Container handles | Railway edge |
| **Identity** | Client certificate CN | `X-Device-Id` header |
| **Client Setup** | mTLS delegate | Plain HTTPS |
| **Test Command** | `mvn spring-boot:run` | `railway up` |
| **Configuration** | `application.yml` | Docker ENV + Railway dashboard |

Both modes use the same ECDH handshake and HMAC-SHA256 signing. Only the identity extraction method differs.

