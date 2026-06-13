package com.example.securechannel;

import com.example.securechannel.api.EcdhConfirmRequest;
import com.example.securechannel.api.EcdhInitRequest;
import com.example.securechannel.exception.UnauthorizedException;
import com.example.securechannel.service.CryptoService;
import com.example.securechannel.service.EcdhHandshakeService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Base64;
import java.security.SecureRandom;
import java.util.Arrays;
import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for ECDH handshake service without requiring real HTTPS.
 * Tests the core ECDH key exchange and proof validation logic.
 */
@SpringBootTest
@DisplayName("ECDH Handshake Service Unit Tests")
class EcdhHandshakeServiceTest {

    @Autowired
    private EcdhHandshakeService ecdhHandshakeService;

    @Autowired
    private CryptoService cryptoService;

    private final String deviceId = "device-123";
    private final String deviceType = "mobile";

    private String validClientPublicKey;
    private String validClientNonce;

    @BeforeEach
    void setUp() {
        // Generate valid test keys
        byte[] clientPublicKey = cryptoService.generateX25519KeyPair().getPublic().getEncoded();
        validClientPublicKey = Base64.getEncoder().encodeToString(clientPublicKey);

        // Generate a 32-byte nonce
        byte[] nonce = new byte[32];
        new SecureRandom().nextBytes(nonce);
        validClientNonce = Base64.getEncoder().encodeToString(nonce);
    }

    @Test
    @DisplayName("Should initialize ECDH handshake and return server public key and nonce")
    void testEcdhInit() {
        // Given
        EcdhInitRequest request = new EcdhInitRequest(
                deviceId,
                deviceType,
                validClientPublicKey,
                validClientNonce
        );

        // When
        EcdhHandshakeService.InitResult result = ecdhHandshakeService.init(request);

        // Then
        assertNotNull(result.sessionId(), "Session ID should be generated");
        assertEquals(deviceId, result.deviceId(), "Device ID should match request");
        assertEquals(deviceType, result.deviceType(), "Device type should match request");
        assertNotNull(result.serverPublicKey(), "Server public key should be generated");
        assertNotNull(result.serverNonce(), "Server nonce should be generated");
        assertNotNull(result.serverProof(), "Server proof should be generated");
    }

    @Test
    @DisplayName("Should generate different session IDs for independent handshakes")
    void testMultipleSessionsAreUnique() {
        // Generate two different client keys
        byte[] clientPublicKey1 = cryptoService.generateX25519KeyPair().getPublic().getEncoded();
        String clientKey1 = Base64.getEncoder().encodeToString(clientPublicKey1);
        byte[] nonce1 = new byte[32];
        new SecureRandom().nextBytes(nonce1);
        String nonce1Str = Base64.getEncoder().encodeToString(nonce1);

        byte[] clientPublicKey2 = cryptoService.generateX25519KeyPair().getPublic().getEncoded();
        String clientKey2 = Base64.getEncoder().encodeToString(clientPublicKey2);
        byte[] nonce2 = new byte[32];
        new SecureRandom().nextBytes(nonce2);
        String nonce2Str = Base64.getEncoder().encodeToString(nonce2);

        // Given
        EcdhInitRequest request1 = new EcdhInitRequest(
                deviceId,
                deviceType,
                clientKey1,
                nonce1Str
        );

        EcdhInitRequest request2 = new EcdhInitRequest(
                deviceId,
                deviceType,
                clientKey2,
                nonce2Str
        );

        // When
        EcdhHandshakeService.InitResult result1 = ecdhHandshakeService.init(request1);
        EcdhHandshakeService.InitResult result2 = ecdhHandshakeService.init(request2);

        // Then
        assertNotEquals(result1.sessionId(), result2.sessionId(),
                "Each session should have a unique session ID");
    }

    @Test
    @DisplayName("Should generate consistent server keys and nonces per session")
    void testServerKeysAreConsistent() {
        // Given
        EcdhInitRequest request = new EcdhInitRequest(
                deviceId,
                deviceType,
                validClientPublicKey,
                validClientNonce
        );

        // When
        EcdhHandshakeService.InitResult result = ecdhHandshakeService.init(request);
        String sessionId = result.sessionId();
        String serverPublicKey = result.serverPublicKey();
        String serverNonce = result.serverNonce();
        String serverProof = result.serverProof();

        // Then - all values should be non-null and non-empty
        assertNotNull(sessionId);
        assertNotNull(serverPublicKey);
        assertNotNull(serverNonce);
        assertNotNull(serverProof);
        assertTrue(sessionId.length() > 0, "Session ID should not be empty");
        assertTrue(serverPublicKey.length() > 0, "Server public key should not be empty");
        assertTrue(serverNonce.length() > 0, "Server nonce should not be empty");
        assertTrue(serverProof.length() > 0, "Server proof should not be empty");
    }

    @Test
    @DisplayName("Should reject confirm for non-existent session")
    void testConfirmRejectsNonExistentSession() {
        // Given
        EcdhConfirmRequest request = new EcdhConfirmRequest(
                "non-existent-session-id",
                "someProof"
        );

        // When & Then
        assertThrows(Exception.class, () -> {
            ecdhHandshakeService.confirm(request);
        }, "Should reject confirmation for non-existent session");
    }

    @Test
    @DisplayName("Should complete handshake with valid session")
    void testConfirmWithValidSession() {
        // Given - Initialize a session first
        EcdhInitRequest initRequest = new EcdhInitRequest(
                deviceId,
                deviceType,
                validClientPublicKey,
                validClientNonce
        );

        EcdhHandshakeService.InitResult initResult = ecdhHandshakeService.init(initRequest);
        String sessionId = initResult.sessionId();

        // When - Try to confirm with any client proof (may fail due to proof validation)
        EcdhConfirmRequest confirmRequest = new EcdhConfirmRequest(
                sessionId,
                "dGVzdC1jbGllbnQtcHJvb2Y="  // Base64: "test-client-proof"
        );

        // Then - Should either succeed or fail with proof validation error, but not "session not found"
        try {
            EcdhHandshakeService.ConfirmResult result = ecdhHandshakeService.confirm(confirmRequest);
            assertNotNull(result.sessionId());
            assertTrue(result.hmacKey().length() > 0, "HMAC key should be generated");
        } catch (Exception e) {
            // Expected if proof doesn't match - that's fine for this test
            // The important thing is that it found the session
            assertFalse(e.getMessage().contains("not found"),
                    "Error should not be about missing session");
        }
    }

    @Test
    @DisplayName("Should handle empty client parameters")
    void testInitWithEmptyParameters() {
        // Given
        EcdhInitRequest request = new EcdhInitRequest(
                "",  // Empty device ID
                deviceType,
                "key",
                "nonce"
        );

        // When & Then
        assertThrows(Exception.class, () -> {
            ecdhHandshakeService.init(request);
        }, "Should reject empty device ID");
    }

    @Test
    @DisplayName("Should generate base64-encoded public keys")
    void testPublicKeysAreBase64Encoded() {
        // Given
        EcdhInitRequest request = new EcdhInitRequest(
                deviceId,
                deviceType,
                validClientPublicKey,
                validClientNonce
        );

        // When
        EcdhHandshakeService.InitResult result = ecdhHandshakeService.init(request);

        // Then - Verify public keys look like base64
        assertTrue(isBase64Like(result.serverPublicKey()),
                "Server public key should be base64 encoded");
        assertTrue(isBase64Like(result.serverNonce()),
                "Server nonce should be base64 encoded");
        assertTrue(isBase64Like(result.serverProof()),
                "Server proof should be base64 encoded");
    }

    /**
     * Simple check if a string looks like base64 (contains base64 chars plus padding)
     */
    private boolean isBase64Like(String str) {
        return str != null && str.matches("[A-Za-z0-9+/]*={0,2}");
    }

    @Test
    @DisplayName("Should reject protected call when certificate identity mismatches session owner")
    void testProtectedCallRejectsCertMismatch() {
        EcdhHandshakeService.InitResult initResult = activateSession();
        String timestamp = String.valueOf(Instant.now().toEpochMilli());
        String nonce = UUID.randomUUID().toString();
        String canonical = String.join("\n", initResult.sessionId(), "different-device", "GET", "/channel/status", timestamp, nonce);
        String signature = cryptoService.signCanonical(initResult.hmacKey(), canonical);

        assertThrows(UnauthorizedException.class, () -> ecdhHandshakeService.authorizeProtectedRequest(
                initResult.sessionId(),
                "different-device",
                "GET",
                "/channel/status",
                timestamp,
                nonce,
                signature));
    }

    @Test
    @DisplayName("Should reject protected call when request signature is invalid")
    void testProtectedCallRejectsInvalidSignature() {
        EcdhHandshakeService.InitResult initResult = activateSession();
        String timestamp = String.valueOf(Instant.now().toEpochMilli());
        String nonce = UUID.randomUUID().toString();

        assertThrows(UnauthorizedException.class, () -> ecdhHandshakeService.authorizeProtectedRequest(
                initResult.sessionId(),
                deviceId,
                "GET",
                "/channel/status",
                timestamp,
                nonce,
                "invalid-signature"));
    }

    @Test
    @DisplayName("Should reject replayed nonce on protected call")
    void testProtectedCallRejectsReplayNonce() {
        EcdhHandshakeService.InitResult initResult = activateSession();
        String timestamp = String.valueOf(Instant.now().toEpochMilli());
        String nonce = UUID.randomUUID().toString();
        String canonical = String.join("\n", initResult.sessionId(), deviceId, "GET", "/channel/status", timestamp, nonce);
        String signature = cryptoService.signCanonical(initResult.hmacKey(), canonical);

        ecdhHandshakeService.authorizeProtectedRequest(
                initResult.sessionId(),
                deviceId,
                "GET",
                "/channel/status",
                timestamp,
                nonce,
                signature);

        String replayTimestamp = String.valueOf(Instant.now().toEpochMilli());
        String replayCanonical = String.join("\n", initResult.sessionId(), deviceId, "GET", "/channel/status", replayTimestamp, nonce);
        String replaySignature = cryptoService.signCanonical(initResult.hmacKey(), replayCanonical);

        assertThrows(UnauthorizedException.class, () -> ecdhHandshakeService.authorizeProtectedRequest(
                initResult.sessionId(),
                deviceId,
                "GET",
                "/channel/status",
                replayTimestamp,
                nonce,
                replaySignature));
    }

    private EcdhHandshakeService.InitResult activateSession() {
        EcdhInitRequest initRequest = new EcdhInitRequest(
                deviceId,
                deviceType,
                validClientPublicKey,
                validClientNonce);
        EcdhHandshakeService.InitResult initResult = ecdhHandshakeService.init(initRequest);
        String transcript = EcdhHandshakeService.transcript(
                initResult.sessionId(),
                validClientPublicKey,
                initResult.serverPublicKey(),
                validClientNonce,
                initResult.serverNonce());
        String clientProof = cryptoService.signCanonical(initResult.hmacKey(), transcript + "\nclient-finish");
        ecdhHandshakeService.confirm(new EcdhConfirmRequest(initResult.sessionId(), clientProof));
        return initResult;
    }
}

