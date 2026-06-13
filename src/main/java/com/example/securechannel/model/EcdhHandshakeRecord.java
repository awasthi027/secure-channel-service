package com.example.securechannel.model;

import java.time.Instant;

public record EcdhHandshakeRecord(
        String sessionId,
        String deviceId,
        String clientPublicKey,
        String serverPublicKey,
        String clientNonce,
        String serverNonce,
        String transcript,
        String derivedHmacKeyB64,
        Instant createdAt,
        Instant expiresAt,
        Instant rotateAfter,
        Instant lastActivityAt) {
}

