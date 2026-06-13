package com.example.securechannel.api;

import jakarta.validation.constraints.NotBlank;

public record EcdhConfirmRequest(
        @NotBlank String sessionId,
        @NotBlank String clientProof) {
}

