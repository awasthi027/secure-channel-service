package com.example.securechannel.api;

public record EcdhInitResponse(
        String sessionId,
        String deviceId,
        String deviceType,
        String serverPublicKey,
        String serverNonce,
        String serverProof,
        String status) {
}

