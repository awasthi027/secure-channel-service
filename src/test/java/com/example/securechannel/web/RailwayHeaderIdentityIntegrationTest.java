package com.example.securechannel.web;

import com.example.securechannel.api.ApiError;
import com.example.securechannel.api.EcdhConfirmRequest;
import com.example.securechannel.api.EcdhInitRequest;
import com.example.securechannel.api.EcdhInitResponse;
import com.example.securechannel.api.SecureChannelStatusResponse;
import com.example.securechannel.service.CryptoService;
import com.example.securechannel.service.EcdhHandshakeService;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "server.ssl.enabled=false",
        "secure.client-identity.mode=header",
        "secure.client-identity.header-name=X-Device-Id"
})
@DisplayName("Railway header identity integration tests")
class RailwayHeaderIdentityIntegrationTest {

    private static final String DEVICE_ID = "device-123";
    private static final String DEVICE_HEADER = "X-Device-Id";

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private CryptoService cryptoService;

    @Autowired
    private EcdhHandshakeService ecdhHandshakeService;

    @Test
    @DisplayName("ECDH init should succeed when Railway identity header is present")
    void initShouldSucceedWithHeaderIdentity() {
        HttpHeaders headers = new HttpHeaders();
        headers.add(DEVICE_HEADER, DEVICE_ID);

        EcdhInitRequest request = new EcdhInitRequest(
                DEVICE_ID,
                "mobile",
                Base64.getEncoder().encodeToString(cryptoService.generateX25519KeyPair().getPublic().getEncoded()),
                randomNonce());

        ResponseEntity<EcdhInitResponse> response = restTemplate.exchange(
                "http://localhost:" + port + "/ecdh/init",
                HttpMethod.POST,
                new HttpEntity<>(request, headers),
                EcdhInitResponse.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(DEVICE_ID, response.getBody().deviceId());
        assertEquals("PENDING", response.getBody().status());
    }

    @Test
    @DisplayName("Protected requests should reject calls without the Railway identity header")
    void initShouldRejectMissingHeaderIdentity() {
        EcdhHandshakeService.InitResult initResult = activateSession();
        HttpHeaders headers = signedHeaders(initResult.sessionId(), initResult.hmacKey(), "GET", "/channel/status");

        ResponseEntity<ApiError> response = restTemplate.exchange(
                "http://localhost:" + port + "/channel/status",
                HttpMethod.GET,
                new HttpEntity<>(headers),
                ApiError.class);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Missing required device identity header: " + DEVICE_HEADER, response.getBody().message());
    }

    @Test
    @DisplayName("Protected APIs should accept the Railway identity header")
    void protectedApiShouldAcceptHeaderIdentity() {
        EcdhHandshakeService.InitResult initResult = activateSession();

        HttpHeaders headers = signedHeaders(initResult.sessionId(), initResult.hmacKey(), "GET", "/channel/status");
        headers.add(DEVICE_HEADER, DEVICE_ID);

        ResponseEntity<SecureChannelStatusResponse> response = restTemplate.exchange(
                "http://localhost:" + port + "/channel/status",
                HttpMethod.GET,
                new HttpEntity<>(headers),
                SecureChannelStatusResponse.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(initResult.sessionId(), response.getBody().sessionId());
        assertEquals("ACTIVE", response.getBody().status());
    }

    private EcdhHandshakeService.InitResult activateSession() {
        String clientPublicKey = Base64.getEncoder().encodeToString(
                cryptoService.generateX25519KeyPair().getPublic().getEncoded());
        String clientNonce = randomNonce();

        EcdhHandshakeService.InitResult initResult = ecdhHandshakeService.init(
                new EcdhInitRequest(DEVICE_ID, "mobile", clientPublicKey, clientNonce));

        String transcript = EcdhHandshakeService.transcript(
                initResult.sessionId(),
                clientPublicKey,
                initResult.serverPublicKey(),
                clientNonce,
                initResult.serverNonce());

        String clientProof = cryptoService.signCanonical(initResult.hmacKey(), transcript + "\nclient-finish");
        ecdhHandshakeService.confirm(new EcdhConfirmRequest(initResult.sessionId(), clientProof));
        return initResult;
    }

    private HttpHeaders signedHeaders(String sessionId, String hmacKeyB64, String method, String path) {
        String timestamp = String.valueOf(Instant.now().toEpochMilli());
        String nonce = UUID.randomUUID().toString();
        String canonical = String.join("\n", sessionId, DEVICE_ID, method, path, timestamp, nonce);

        HttpHeaders headers = new HttpHeaders();
        headers.add("X-Session-Id", sessionId);
        headers.add("X-Request-Timestamp", timestamp);
        headers.add("X-Request-Nonce", nonce);
        headers.add("X-Request-Signature", cryptoService.signCanonical(hmacKeyB64, canonical));
        return headers;
    }

    private String randomNonce() {
        byte[] nonce = new byte[32];
        new SecureRandom().nextBytes(nonce);
        return Base64.getEncoder().encodeToString(nonce);
    }
}

