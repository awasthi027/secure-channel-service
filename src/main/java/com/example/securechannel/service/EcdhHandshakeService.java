package com.example.securechannel.service;

import com.example.securechannel.api.EcdhConfirmRequest;
import com.example.securechannel.api.EcdhInitRequest;
import com.example.securechannel.exception.BadRequestException;
import com.example.securechannel.exception.UnauthorizedException;
import com.example.securechannel.model.EcdhHandshakeRecord;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class EcdhHandshakeService {

    private static final Logger LOGGER = LoggerFactory.getLogger(EcdhHandshakeService.class);

    private static final Duration SESSION_TTL = Duration.ofMinutes(5);
    private static final Duration INACTIVITY_TIMEOUT = Duration.ofMinutes(2);
    private static final Duration ROTATE_AFTER = Duration.ofMinutes(2);
    private static final Duration REQUEST_SKEW_TOLERANCE = Duration.ofSeconds(30);
    private static final Duration NONCE_RETENTION = Duration.ofMinutes(3);

    private final Map<String, EcdhHandshakeRecord> pending = new ConcurrentHashMap<>();
    private final Map<String, ActiveSessionState> active = new ConcurrentHashMap<>();
    private final CryptoService cryptoService;

    public EcdhHandshakeService(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    public InitResult init(EcdhInitRequest request) {
        KeyPair serverEphemeral = cryptoService.generateX25519KeyPair();
        PublicKey clientPublicKey = cryptoService.decodeX25519PublicKey(request.clientPublicKey());

        String sessionId = UUID.randomUUID().toString();
        byte[] clientNonce = decodeB64(request.clientNonce(), "Invalid client nonce");
        byte[] serverNonce = cryptoService.randomBytes(32);

        byte[] sharedSecret = cryptoService.deriveEcdhSharedSecret(serverEphemeral, clientPublicKey);
        CryptoService.DerivedSessionKeys keys = cryptoService.deriveSessionKeys(
                sharedSecret,
                sessionId,
                clientNonce,
                serverNonce);

        String serverPublicKeyB64 = cryptoService.encodePublicKeyB64(serverEphemeral.getPublic());
        String serverNonceB64 = Base64.getEncoder().encodeToString(serverNonce);

        String transcriptStr = transcript(
                sessionId,
                request.clientPublicKey(),
                serverPublicKeyB64,
                request.clientNonce(),
                serverNonceB64);
        String serverProof = cryptoService.signCanonical(keys.hmacKeyB64(), transcriptStr);

        Instant now = Instant.now();
        pending.put(sessionId, new EcdhHandshakeRecord(
                sessionId,
                request.deviceId(),
                request.clientPublicKey(),
                serverPublicKeyB64,
                request.clientNonce(),
                serverNonceB64,
                transcriptStr,
                keys.hmacKeyB64(),
                now,
                now.plus(SESSION_TTL),
                now.plus(ROTATE_AFTER),
                now));

        LOGGER.info("event=ecdh_init sessionTag={} deviceId={}",
                redactSessionId(sessionId), request.deviceId());

        return new InitResult(
                sessionId,
                request.deviceId(),
                request.deviceType(),
                serverPublicKeyB64,
                serverNonceB64,
                serverProof,
                keys.hmacKeyB64());
    }

    public ConfirmResult confirm(EcdhConfirmRequest request) {
        EcdhHandshakeRecord record = pending.get(request.sessionId());
        if (record == null) {
            throw new BadRequestException("ECDH handshake not found or expired");
        }

        String expectedProof = cryptoService.signCanonical(record.derivedHmacKeyB64(), record.transcript() + "\nclient-finish");
        if (!cryptoService.constantTimeEquals(expectedProof, request.clientProof())) {
            throw new UnauthorizedException("Invalid client handshake proof");
        }

        Instant now = Instant.now();
        EcdhHandshakeRecord activated = new EcdhHandshakeRecord(
                record.sessionId(),
                record.deviceId(),
                record.clientPublicKey(),
                record.serverPublicKey(),
                record.clientNonce(),
                record.serverNonce(),
                record.transcript(),
                record.derivedHmacKeyB64(),
                record.createdAt(),
                record.expiresAt(),
                record.rotateAfter(),
                now);

        active.put(request.sessionId(), new ActiveSessionState(activated));
        pending.remove(request.sessionId());

        LOGGER.info("event=ecdh_confirmed sessionTag={}", redactSessionId(request.sessionId()));

        return new ConfirmResult(request.sessionId(), "ACTIVE", record.derivedHmacKeyB64());
    }

    public EcdhHandshakeRecord getActive(String sessionId) {
        ActiveSessionState state = active.get(sessionId);
        if (state == null) {
            throw new UnauthorizedException("ECDH session not found or not active");
        }

        EcdhHandshakeRecord record = enforceLifecycle(sessionId, state.record(), Instant.now());
        state.record(record);
        return record;
    }

    public EcdhHandshakeRecord authorizeProtectedRequest(
            String sessionId,
            String certDeviceId,
            String method,
            String path,
            String timestampHeader,
            String nonce,
            String signature) {
        if (sessionId == null || sessionId.isBlank()) {
            throw new BadRequestException("X-Session-Id header is required");
        }
        if (timestampHeader == null || timestampHeader.isBlank()) {
            throw new BadRequestException("X-Request-Timestamp header is required");
        }
        if (nonce == null || nonce.isBlank()) {
            throw new BadRequestException("X-Request-Nonce header is required");
        }
        if (signature == null || signature.isBlank()) {
            throw new BadRequestException("X-Request-Signature header is required");
        }

        ActiveSessionState state = active.get(sessionId);
        if (state == null) {
            throw new UnauthorizedException("ECDH session not found or not active");
        }

        Instant now = Instant.now();
        EcdhHandshakeRecord record = enforceLifecycle(sessionId, state.record(), now);

        if (!record.deviceId().equals(certDeviceId)) {
            active.remove(sessionId);
            throw new UnauthorizedException("Client certificate identity does not match channel owner");
        }

        long tsMillis;
        try {
            tsMillis = Long.parseLong(timestampHeader);
        } catch (NumberFormatException ex) {
            throw new BadRequestException("X-Request-Timestamp must be epoch milliseconds");
        }

        Instant requestTime = Instant.ofEpochMilli(tsMillis);
        if (Duration.between(requestTime, now).abs().compareTo(REQUEST_SKEW_TOLERANCE) > 0) {
            throw new UnauthorizedException("Request timestamp outside allowed window");
        }

        state.pruneOldNonces(now.minus(NONCE_RETENTION));
        if (state.containsNonce(nonce)) {
            throw new UnauthorizedException("Replay detected: nonce already used");
        }

        String canonical = String.join("\n", sessionId, certDeviceId, method, path, timestampHeader, nonce);
        String expected = cryptoService.signCanonical(record.derivedHmacKeyB64(), canonical);
        if (!cryptoService.constantTimeEquals(expected, signature)) {
            throw new UnauthorizedException("Invalid request signature");
        }

        state.registerNonce(nonce, now);

        EcdhHandshakeRecord refreshed = new EcdhHandshakeRecord(
                record.sessionId(),
                record.deviceId(),
                record.clientPublicKey(),
                record.serverPublicKey(),
                record.clientNonce(),
                record.serverNonce(),
                record.transcript(),
                record.derivedHmacKeyB64(),
                record.createdAt(),
                record.expiresAt(),
                record.rotateAfter(),
                now);
        state.record(refreshed);
        return refreshed;
    }

    public static String transcript(
            String sessionId,
            String clientPublicKey,
            String serverPublicKey,
            String clientNonce,
            String serverNonce) {
        return String.join("\n", sessionId, clientPublicKey, serverPublicKey, clientNonce, serverNonce);
    }

    private byte[] decodeB64(String input, String message) {
        try {
            return Base64.getDecoder().decode(input);
        } catch (IllegalArgumentException ex) {
            throw new UnauthorizedException(message);
        }
    }

    private EcdhHandshakeRecord enforceLifecycle(String sessionId, EcdhHandshakeRecord record, Instant now) {
        if (now.isAfter(record.expiresAt())) {
            active.remove(sessionId);
            throw new UnauthorizedException("Session expired. Start a new handshake");
        }
        if (now.isAfter(record.lastActivityAt().plus(INACTIVITY_TIMEOUT))) {
            active.remove(sessionId);
            throw new UnauthorizedException("Session inactive. Start a new handshake");
        }
        if (now.isAfter(record.rotateAfter())) {
            active.remove(sessionId);
            throw new UnauthorizedException("Session rotation required. Start a new handshake");
        }
        return record;
    }

    private String redactSessionId(String sessionId) {
        String digest = cryptoService.sha256B64(sessionId.getBytes(StandardCharsets.UTF_8));
        return digest.substring(0, Math.min(12, digest.length()));
    }

    public String sessionTagForLogs(String sessionId) {
        return redactSessionId(sessionId);
    }

    private static final class ActiveSessionState {
        private final Map<String, Instant> seenNonces = new ConcurrentHashMap<>();
        private volatile EcdhHandshakeRecord record;

        private ActiveSessionState(EcdhHandshakeRecord record) {
            this.record = record;
        }

        private EcdhHandshakeRecord record() {
            return record;
        }

        private void record(EcdhHandshakeRecord updated) {
            this.record = updated;
        }

        private boolean registerNonce(String nonce, Instant seenAt) {
            return seenNonces.putIfAbsent(nonce, seenAt) == null;
        }

        private boolean containsNonce(String nonce) {
            return seenNonces.containsKey(nonce);
        }

        private void pruneOldNonces(Instant cutoff) {
            seenNonces.entrySet().removeIf(entry -> entry.getValue().isBefore(cutoff));
        }
    }

    public record InitResult(
            String sessionId,
            String deviceId,
            String deviceType,
            String serverPublicKey,
            String serverNonce,
            String serverProof,
            String hmacKey) {
    }

    public record ConfirmResult(
            String sessionId,
            String status,
            String hmacKey) {
    }
}

