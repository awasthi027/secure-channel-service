package com.example.securechannel.api;

import java.time.Instant;

public record HealthResponse(
        String status,
        String service,
        Instant timestamp) {
}

