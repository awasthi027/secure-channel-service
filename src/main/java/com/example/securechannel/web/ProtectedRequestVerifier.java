package com.example.securechannel.web;

import com.example.securechannel.model.EcdhHandshakeRecord;
import com.example.securechannel.service.EcdhHandshakeService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class ProtectedRequestVerifier {

    private static final Logger LOGGER = LoggerFactory.getLogger(ProtectedRequestVerifier.class);

    private final EcdhHandshakeService ecdhHandshakeService;
    private final ClientCertificateExtractor certificateExtractor;

    public ProtectedRequestVerifier(
            EcdhHandshakeService ecdhHandshakeService,
            ClientCertificateExtractor certificateExtractor) {
        this.ecdhHandshakeService = ecdhHandshakeService;
        this.certificateExtractor = certificateExtractor;
    }

    public EcdhHandshakeRecord verify(HttpServletRequest request) {
        String sessionId = request.getHeader("X-Session-Id");
        String requestTimestamp = request.getHeader("X-Request-Timestamp");
        String requestNonce = request.getHeader("X-Request-Nonce");
        String requestSignature = request.getHeader("X-Request-Signature");
        String certDeviceId = certificateExtractor.extractDeviceIdFromCertificate(request);

        EcdhHandshakeRecord record = ecdhHandshakeService.authorizeProtectedRequest(
                sessionId,
                certDeviceId,
                request.getMethod(),
                request.getRequestURI(),
                requestTimestamp,
                requestNonce,
                requestSignature);

        LOGGER.info(
                "event=request_verified method={} path={} deviceId={} sessionTag={}",
                request.getMethod(),
                request.getRequestURI(),
                record.deviceId(),
                ecdhHandshakeService.sessionTagForLogs(record.sessionId()));

        return record;
    }
}

