package com.example.securechannel.api;

import jakarta.validation.constraints.NotBlank;

public record EcdhInitRequest(
        @NotBlank String deviceId,
        @NotBlank String deviceType,
        @NotBlank String clientPublicKey,
        @NotBlank String clientNonce) {
}

