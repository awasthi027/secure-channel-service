package com.example.securechannel.api;

import java.time.Instant;

public record SecureChannelStatusResponse(
        String sessionId,
        String status,
        String message,
        Instant activatedAt) {
}

