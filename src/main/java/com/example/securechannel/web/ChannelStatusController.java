package com.example.securechannel.web;

import com.example.securechannel.api.HealthResponse;
import com.example.securechannel.api.SecureChannelStatusResponse;
import com.example.securechannel.model.EcdhHandshakeRecord;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ChannelStatusController {

    private final ProtectedRequestVerifier protectedRequestVerifier;

    public ChannelStatusController(ProtectedRequestVerifier protectedRequestVerifier) {
        this.protectedRequestVerifier = protectedRequestVerifier;
    }

    @GetMapping("/health")
    public HealthResponse health() {
        return new HealthResponse("UP", "secure-channel-service", Instant.now());
    }

    @GetMapping("/channel/status")
    public SecureChannelStatusResponse secureChannelStatus(HttpServletRequest request) {
        EcdhHandshakeRecord activeRecord = protectedRequestVerifier.verify(request);
        return new SecureChannelStatusResponse(
                activeRecord.sessionId(),
                "ACTIVE",
                "Secure channel is active",
                activeRecord.createdAt());
    }
}

