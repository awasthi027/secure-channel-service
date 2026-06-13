package com.example.securechannel.api;

public record EcdhConfirmResponse(
        String sessionId,
        String status,
        String hmacKey) {
}

