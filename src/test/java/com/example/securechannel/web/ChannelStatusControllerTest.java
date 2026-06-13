package com.example.securechannel.web;

import com.example.securechannel.api.ApiError;
import com.example.securechannel.api.EcdhConfirmRequest;
import com.example.securechannel.api.EcdhInitRequest;
import com.example.securechannel.api.HealthResponse;
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
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import jakarta.servlet.http.HttpServletRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DisplayName("Channel Status Controller Tests")
class ChannelStatusControllerTest {

    private static final String DEVICE_ID = "device-123";

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private EcdhHandshakeService ecdhHandshakeService;

    @Autowired
    private CryptoService cryptoService;

    @Test
    @DisplayName("Health endpoint should be reachable without handshake")
    void healthEndpointShouldBeOpen() {
        ResponseEntity<HealthResponse> response = restTemplate.getForEntity(
                "http://localhost:" + port + "/health",
                HealthResponse.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("UP", response.getBody().status());
        assertEquals("secure-channel-service", response.getBody().service());
    }

    @Test
    @DisplayName("Channel status endpoint should reject unknown session")
    void channelStatusShouldRejectUnknownSession() {
        HttpHeaders headers = new HttpHeaders();
        withSignedHeaders(headers, "missing-session", DEVICE_ID, cryptoService.generateHmacKeyB64());
        ResponseEntity<ApiError> response = restTemplate.exchange(
                "http://localhost:" + port + "/channel/status",
                HttpMethod.GET,
                new HttpEntity<>(headers),
                ApiError.class);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("ECDH session not found or not active", response.getBody().message());
    }

    @Test
    @DisplayName("Channel status endpoint should reject missing session header")
    void channelStatusShouldRejectMissingHeader() {
        ResponseEntity<ApiError> response = restTemplate.getForEntity(
                "http://localhost:" + port + "/channel/status",
                ApiError.class);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("X-Session-Id header is required", response.getBody().message());
    }

    @Test
    @DisplayName("Channel status endpoint should respond after successful confirm")
    void channelStatusShouldRespondForActiveSession() {
        String clientPublicKey = Base64.getEncoder().encodeToString(
                cryptoService.generateX25519KeyPair().getPublic().getEncoded());
        byte[] nonce = new byte[32];
        new SecureRandom().nextBytes(nonce);
        String clientNonce = Base64.getEncoder().encodeToString(nonce);

        EcdhInitRequest initRequest = new EcdhInitRequest(
                DEVICE_ID,
                "mobile",
                clientPublicKey,
                clientNonce);

        EcdhHandshakeService.InitResult initResult = ecdhHandshakeService.init(initRequest);

        String transcript = EcdhHandshakeService.transcript(
                initResult.sessionId(),
                clientPublicKey,
                initResult.serverPublicKey(),
                clientNonce,
                initResult.serverNonce());

        String clientProof = cryptoService.signCanonical(initResult.hmacKey(), transcript + "\nclient-finish");

        ecdhHandshakeService.confirm(new EcdhConfirmRequest(initResult.sessionId(), clientProof));

        HttpHeaders headers = new HttpHeaders();
        withSignedHeaders(headers, initResult.sessionId(), DEVICE_ID, initResult.hmacKey());
        ResponseEntity<SecureChannelStatusResponse> response = restTemplate.exchange(
                "http://localhost:" + port + "/channel/status",
                HttpMethod.GET,
                new HttpEntity<>(headers),
                SecureChannelStatusResponse.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("ACTIVE", response.getBody().status());
        assertEquals(initResult.sessionId(), response.getBody().sessionId());
    }

    private void withSignedHeaders(HttpHeaders headers, String sessionId, String deviceId, String hmacKeyB64) {
        String timestamp = String.valueOf(Instant.now().toEpochMilli());
        String nonce = UUID.randomUUID().toString();
        String canonical = String.join("\n", sessionId, deviceId, "GET", "/channel/status", timestamp, nonce);

        headers.add("X-Session-Id", sessionId);
        headers.add("X-Request-Timestamp", timestamp);
        headers.add("X-Request-Nonce", nonce);
        headers.add("X-Request-Signature", cryptoService.signCanonical(hmacKeyB64, canonical));
    }

    @TestConfiguration
    static class CertificateExtractorStubConfig {
        @Bean
        @Primary
        ClientCertificateExtractor certificateExtractorStub() {
            return new ClientCertificateExtractor() {
                @Override
                public String extractDeviceIdFromCertificate(HttpServletRequest request) {
                    return DEVICE_ID;
                }
            };
        }
    }
}

