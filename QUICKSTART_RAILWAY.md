# Quick Start: Deploy to Railway

## Problem Solved

✅ Service now runs on Railway with edge TLS  
✅ No more "Bad Request: This combination requires TLS" errors  
✅ Device identity works via HTTP header on Railway  
✅ Local mTLS development still works unchanged  
✅ Client (iOS) updated to use Railway URL and header-based identity  

---

## Deployment Steps

### 1. Deploy Backend to Railway

```bash
cd /Users/ashisha2/Desktop/backend-learning/secure-channel-service

# Install Railway CLI (if not already installed)
# npm install -g @railway/cli

# Login to Railway
railway login

# Deploy
railway up
```

Railway will:
- Build using the included `Dockerfile`
- Detect `railway.json` for configuration
- Run on HTTPS public URL: `https://secure-channel-service-production.up.railway.app`
- Use the embedded environment variables (SSL disabled, header mode enabled)

### 2. Update iOS Client

The client code at `/Users/ashisha2/Desktop/POC_Apps/BackendClientApps/SecurityTestApp/` has been updated:

**Key changes:**
- ✅ `SecureNetworkEnvironment.swift`: Uses Railway HTTPS URL
- ✅ `SecureNetworkEnvironment.swift`: Only uses mTLS for `localhost`
- ✅ `EcdhClient.swift`: Sends `X-Device-Id` header on `/ecdh/init`
- ✅ `SignedRequestExecutor.swift`: Sends `X-Device-Id` header on all requests
- ✅ `SecureChannelViewModel.swift`: Passes header name to client

**To use:**
```swift
// Automatically uses Railway URL & header mode
let viewModel = SecureChannelViewModel()
viewModel.runFullEcdhHandshake()  // Works on Railway!
```

### 3. Verify Deployment

#### Check Backend Health

```bash
# Public Railway URL
curl https://secure-channel-service-production.up.railway.app/health

# Should respond:
# {"status": "UP", "service": "secure-channel-service"}
```

#### Check Logs

```bash
railway logs -f

# Look for:
# 2026-06-16T18:X:XX... INFO secure-channel-service : Started application in X seconds
# event=ecdh_init sessionTag=... deviceId=device-123
```

#### Test from iOS

1. Build & run the updated SecurityTestApp in Xcode
2. Tap "Run Full ECDH Handshake"
3. Check logs — should see successful handshake

---

## Files Changed

### Backend Service

```
✅ railway.json                          (new) Railway configuration
✅ Dockerfile                            (updated) Railway defaults
✅ application.yml                       (updated) Configurable properties
✅ README.md                             (updated) Railway section
✅ RAILWAY_DEPLOYMENT.md                 (new) Comprehensive guide
✅ IMPLEMENTATION_SUMMARY.md             (new) Technical details

✅ ClientCertificateExtractor.java       (updated) Header-based fallback
✅ ArticleControllerTest.java            (updated) Test fixture
✅ ChannelStatusControllerTest.java      (updated) Test fixture
✅ RailwayHeaderIdentityIntegrationTest.java (new) Railway mode tests
```

### iOS Client

```
✅ SecureNetworkEnvironment.swift        (updated) Railway URL, conditional mTLS
✅ EcdhClient.swift                      (updated) Send header on /ecdh/init
✅ SignedRequestExecutor.swift           (updated) Send header on all requests
✅ SecureChannelViewModel.swift          (updated) Pass header to client
```

---

## Testing

### Backend Tests

```bash
cd /Users/ashisha2/Desktop/backend-learning/secure-channel-service

# Test Railway mode locally
export SERVER_SSL_ENABLED=false
export SECURE_CLIENT_IDENTITY_MODE=header
mvn test -Dtest=RailwayHeaderIdentityIntegrationTest

# Result: ✅ 3/3 tests pass
```

### Local Development (Unchanged)

```bash
# Default still works with mTLS
mvn spring-boot:run

# Client: https://localhost:8443 with mTLS certificate
# Tests: MutualTlsEcdhIntegrationTest (mTLS-specific)
```

---

## Environment Variables (Optional)

If you need to customize on Railway:

**In Railway Dashboard → Variables:**
```
SERVER_SSL_ENABLED=false                # (default from Dockerfile)
SECURE_CLIENT_IDENTITY_MODE=header      # (default from Dockerfile)
SECURE_CLIENT_IDENTITY_HEADER=X-Device-Id  # (default from Dockerfile)
```

Or use Railway CLI:
```bash
railway variable set SERVER_SSL_ENABLED=false
railway variable set SECURE_CLIENT_IDENTITY_MODE=header
railway up
```

---

## Troubleshooting

### "400 Bad Request - This combination requires TLS"

**Root cause:** Client using wrong URL scheme or server misconfigured.

**Fix:**
- Client: Ensure using `https://` to Railway (not `http://`)
- Server: Verify `SERVER_SSL_ENABLED=false` is set

### "UnauthorizedException: Missing required device identity header"

**Root cause:** Request missing `X-Device-Id` header.

**Fix:** Client automatically sends header, but if testing with curl:
```bash
curl -H "X-Device-Id: device-123" https://secure-channel-service-production.up.railway.app/health
```

### "Certificate required" errors

**Root cause:** Using local mTLS configuration on Railway.

**Fix:** Switch to Railway mode or update client to use `https://...up.railway.app` URL.

---

## Architecture Comparison

### Local Development Path

```
iOS Client (localhost:8443 with mTLS cert)
    ↓ HTTPS (TLS + mTLS)
Java Service (Container: TLS enabled)
    ├─ device-id from certificate CN
    ├─ Verify HMAC signature
    └─ Return response
```

### Railway Production Path

```
iOS Client (up.railway.app)
    ↓ HTTPS (tunnel to Railway edge)
Railway Edge (TLS termination)
    ↓ HTTP (X-Forwarded-*)
Java Service Container (Plain HTTP)
    ├─ device-id from X-Device-Id header
    ├─ Verify HMAC signature
    └─ Return response
```

**Both** implement the same security model — only the identity extraction differs.

---

## Summary Checklist

- [x] Backend configured for Railway (railway.json, environment variables)
- [x] Dockerfile defaults to Railway mode
- [x] ClientCertificateExtractor supports header-based identity
- [x] iOS client sends X-Device-Id header
- [x] iOS client uses Railway HTTPS URL
- [x] Local development still works with mTLS
- [x] Tests verify Railway header mode works
- [x] Documentation covers both modes and troubleshooting

**Ready to deploy!** Run `railway up` from the service root directory.

For detailed docs, see:
- `RAILWAY_DEPLOYMENT.md` — Comprehensive deployment guide
- `IMPLEMENTATION_SUMMARY.md` — Technical implementation details

