package com.example.securechannel.api;

import jakarta.validation.constraints.NotBlank;

public record ArticleRequest(
        @NotBlank String title,
        @NotBlank String description) {
}

