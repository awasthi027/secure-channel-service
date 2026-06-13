package com.example.securechannel.web;

import com.example.securechannel.exception.UnauthorizedException;
import jakarta.servlet.http.HttpServletRequest;
import java.security.cert.X509Certificate;
import org.springframework.stereotype.Component;

@Component
public class ClientCertificateExtractor {

    private static final String CERT_ATTR = "jakarta.servlet.request.X509Certificate";

    /**
     * Extracts the Common Name (CN) from the verified client certificate.
     * This is populated by Tomcat after a successful mTLS handshake when
     * server.ssl.client-auth=need is configured.
     */
    public String extractDeviceIdFromCertificate(HttpServletRequest request) {
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute(CERT_ATTR);

        if (certs == null || certs.length == 0) {
            throw new UnauthorizedException("No client certificate presented in request");
        }

        X509Certificate clientCert = certs[0];
        String dn = clientCert.getSubjectX500Principal().getName();

        return extractCn(dn);
    }

    /**
     * Parses the CN from an X.500 Distinguished Name string.
     * Example: "CN=device-123,O=Learning,C=IN" -> "device-123"
     */
    private String extractCn(String dn) {
        for (String part : dn.split(",")) {
            String trimmed = part.trim();
            if (trimmed.startsWith("CN=")) {
                return trimmed.substring(3);
            }
        }
        throw new UnauthorizedException("Client certificate does not contain CN");
    }
}

