package com.example.securechannel.web;

import com.example.securechannel.api.EcdhConfirmRequest;
import com.example.securechannel.api.EcdhConfirmResponse;
import com.example.securechannel.api.EcdhInitRequest;
import com.example.securechannel.api.EcdhInitResponse;
import com.example.securechannel.service.EcdhHandshakeService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/ecdh")
public class EcdhController {

    private final EcdhHandshakeService ecdhHandshakeService;
    private final ClientCertificateExtractor certificateExtractor;

    public EcdhController(
            EcdhHandshakeService ecdhHandshakeService,
            ClientCertificateExtractor certificateExtractor) {
        this.ecdhHandshakeService = ecdhHandshakeService;
        this.certificateExtractor = certificateExtractor;
    }

    @PostMapping("/init")
    public EcdhInitResponse init(
            @Valid @RequestBody EcdhInitRequest request,
            HttpServletRequest httpRequest) {
        
        // Extract verified device identity from mTLS client certificate
        String certDeviceId = certificateExtractor.extractDeviceIdFromCertificate(httpRequest);
        
        // Validate that request body matches certificate (prevent impersonation)
        if (!certDeviceId.equals(request.deviceId())) {
            throw new com.example.securechannel.exception.UnauthorizedException(
                    "Request deviceId does not match mTLS certificate CN");
        }
        
        EcdhHandshakeService.InitResult result = ecdhHandshakeService.init(request);
        return new EcdhInitResponse(
                result.sessionId(),
                result.deviceId(),
                result.deviceType(),
                result.serverPublicKey(),
                result.serverNonce(),
                result.serverProof(),
                "PENDING");
    }

    @PostMapping("/confirm")
    public EcdhConfirmResponse confirm(@Valid @RequestBody EcdhConfirmRequest request) {
        EcdhHandshakeService.ConfirmResult result = ecdhHandshakeService.confirm(request);
        return new EcdhConfirmResponse(
                result.sessionId(),
                result.status(),
                result.hmacKey());
    }
}



