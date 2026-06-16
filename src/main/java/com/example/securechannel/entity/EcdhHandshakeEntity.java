package com.example.securechannel.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;

@Entity
@Table(name = "ecdh_handshakes")
public class EcdhHandshakeEntity {

    @Id
    private String sessionId;

    @Column(nullable = false)
    private String deviceId;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String clientPublicKey;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String serverPublicKey;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String clientNonce;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String serverNonce;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String transcript;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String derivedHmacKeyB64;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private HandshakeStatus status;

    @Column(nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    @Column(nullable = false)
    private OffsetDateTime expiresAt;

    @Column(nullable = false)
    private OffsetDateTime rotateAfter;

    @Column(nullable = false)
    private OffsetDateTime lastActivityAt;

    @PrePersist
    void onCreate() {
        OffsetDateTime now = OffsetDateTime.now();
        createdAt = now;
        lastActivityAt = now;
        if (status == null) {
            status = HandshakeStatus.PENDING;
        }
    }

    @PreUpdate
    void onUpdate() {
        // lastActivityAt is updated when needed, not on every update
    }

    // Getters and Setters
    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(String deviceId) {
        this.deviceId = deviceId;
    }

    public String getClientPublicKey() {
        return clientPublicKey;
    }

    public void setClientPublicKey(String clientPublicKey) {
        this.clientPublicKey = clientPublicKey;
    }

    public String getServerPublicKey() {
        return serverPublicKey;
    }

    public void setServerPublicKey(String serverPublicKey) {
        this.serverPublicKey = serverPublicKey;
    }

    public String getClientNonce() {
        return clientNonce;
    }

    public void setClientNonce(String clientNonce) {
        this.clientNonce = clientNonce;
    }

    public String getServerNonce() {
        return serverNonce;
    }

    public void setServerNonce(String serverNonce) {
        this.serverNonce = serverNonce;
    }

    public String getTranscript() {
        return transcript;
    }

    public void setTranscript(String transcript) {
        this.transcript = transcript;
    }

    public String getDerivedHmacKeyB64() {
        return derivedHmacKeyB64;
    }

    public void setDerivedHmacKeyB64(String derivedHmacKeyB64) {
        this.derivedHmacKeyB64 = derivedHmacKeyB64;
    }

    public HandshakeStatus getStatus() {
        return status;
    }

    public void setStatus(HandshakeStatus status) {
        this.status = status;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(OffsetDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public OffsetDateTime getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(OffsetDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

    public OffsetDateTime getRotateAfter() {
        return rotateAfter;
    }

    public void setRotateAfter(OffsetDateTime rotateAfter) {
        this.rotateAfter = rotateAfter;
    }

    public OffsetDateTime getLastActivityAt() {
        return lastActivityAt;
    }

    public void setLastActivityAt(OffsetDateTime lastActivityAt) {
        this.lastActivityAt = lastActivityAt;
    }

    public enum HandshakeStatus {
        PENDING, ACTIVE, EXPIRED, TERMINATED
    }
}

