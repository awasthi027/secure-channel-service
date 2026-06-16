package com.example.securechannel.web;

import com.example.securechannel.api.ApiError;
import com.example.securechannel.api.ArticleRequest;
import com.example.securechannel.api.ArticleResponse;
import com.example.securechannel.api.EcdhConfirmRequest;
import com.example.securechannel.api.EcdhInitRequest;
import com.example.securechannel.service.CryptoService;
import com.example.securechannel.service.EcdhHandshakeService;
import jakarta.servlet.http.HttpServletRequest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DisplayName("Article Controller Security Tests")
class ArticleControllerTest {

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
    @DisplayName("Should create and get article using protected headers")
    void shouldCreateAndGetArticle() {
        EcdhHandshakeService.InitResult initResult = activateSession();

        HttpHeaders postHeaders = signedHeaders(
                initResult.sessionId(),
                initResult.hmacKey(),
                "POST",
                "/articles");

        ArticleRequest createRequest = new ArticleRequest("Secure Title", "Secure Description");
        ResponseEntity<ArticleResponse> createResponse = restTemplate.exchange(
                "http://localhost:" + port + "/articles",
                HttpMethod.POST,
                new HttpEntity<>(createRequest, postHeaders),
                ArticleResponse.class);

        assertEquals(HttpStatus.OK, createResponse.getStatusCode());
        assertNotNull(createResponse.getBody());
        assertEquals("Secure Title", createResponse.getBody().title());

        long articleId = createResponse.getBody().id();
        HttpHeaders getHeaders = signedHeaders(
                initResult.sessionId(),
                initResult.hmacKey(),
                "GET",
                "/articles/" + articleId);

        ResponseEntity<ArticleResponse> getResponse = restTemplate.exchange(
                "http://localhost:" + port + "/articles/" + articleId,
                HttpMethod.GET,
                new HttpEntity<>(getHeaders),
                ArticleResponse.class);

        assertEquals(HttpStatus.OK, getResponse.getStatusCode());
        assertNotNull(getResponse.getBody());
        assertEquals(articleId, getResponse.getBody().id());
        assertEquals("Secure Title", getResponse.getBody().title());
        assertEquals("Secure Description", getResponse.getBody().description());
    }

    @Test
    @DisplayName("Should get all articles using protected headers")
    void shouldGetAllArticles() {
        EcdhHandshakeService.InitResult initResult = activateSession();

        HttpHeaders postHeaders1 = signedHeaders(
                initResult.sessionId(),
                initResult.hmacKey(),
                "POST",
                "/articles");
        HttpHeaders postHeaders2 = signedHeaders(
                initResult.sessionId(),
                initResult.hmacKey(),
                "POST",
                "/articles");

        restTemplate.exchange(
                "http://localhost:" + port + "/articles",
                HttpMethod.POST,
                new HttpEntity<>(new ArticleRequest("Title-1", "Desc-1"), postHeaders1),
                ArticleResponse.class);
        restTemplate.exchange(
                "http://localhost:" + port + "/articles",
                HttpMethod.POST,
                new HttpEntity<>(new ArticleRequest("Title-2", "Desc-2"), postHeaders2),
                ArticleResponse.class);

        HttpHeaders getAllHeaders = signedHeaders(
                initResult.sessionId(),
                initResult.hmacKey(),
                "GET",
                "/articles");
        ResponseEntity<ArticleResponse[]> getAllResponse = restTemplate.exchange(
                "http://localhost:" + port + "/articles",
                HttpMethod.GET,
                new HttpEntity<>(getAllHeaders),
                ArticleResponse[].class);

        assertEquals(HttpStatus.OK, getAllResponse.getStatusCode());
        ArticleResponse[] body = getAllResponse.getBody();
        assertNotNull(body);
        List<ArticleResponse> articles = List.of(body);
        List<String> titles = articles.stream().map(ArticleResponse::title).collect(Collectors.toList());
        assertTrue(titles.contains("Title-1"));
        assertTrue(titles.contains("Title-2"));
    }

    @Test
    @DisplayName("Should reject article create when signature headers are missing")
    void shouldRejectMissingProtectedHeaders() {
        ArticleRequest createRequest = new ArticleRequest("Title", "Description");
        ResponseEntity<ApiError> response = restTemplate.exchange(
                "http://localhost:" + port + "/articles",
                HttpMethod.POST,
                new HttpEntity<>(createRequest),
                ApiError.class);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("X-Session-Id header is required", response.getBody().message());
    }

    private EcdhHandshakeService.InitResult activateSession() {
        String clientPublicKey = Base64.getEncoder().encodeToString(
                cryptoService.generateX25519KeyPair().getPublic().getEncoded());
        byte[] nonce = new byte[32];
        new SecureRandom().nextBytes(nonce);
        String clientNonce = Base64.getEncoder().encodeToString(nonce);

        EcdhInitRequest initRequest = new EcdhInitRequest(DEVICE_ID, "mobile", clientPublicKey, clientNonce);
        EcdhHandshakeService.InitResult initResult = ecdhHandshakeService.init(initRequest);

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

    @TestConfiguration
    static class CertificateExtractorStubConfig {
        @Bean
        @Primary
        ClientCertificateExtractor certificateExtractorStub() {
            return new ClientCertificateExtractor("mtls", "X-Device-Id") {
                @Override
                public String extractDeviceIdFromCertificate(HttpServletRequest request) {
                    return DEVICE_ID;
                }
            };
        }
    }
}

