package com.example.securechannel.service;

import com.example.securechannel.exception.BadRequestException;
import com.example.securechannel.exception.UnauthorizedException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Service;

@Service
public class CryptoService {

    private static final String DATA_KEY_ALGORITHM = "AES";
    private static final String AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String HMAC_SHA_256 = "HmacSHA256";
    private static final String ECDH_ALGORITHM = "X25519";
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_IV_LENGTH = 12;

    private final SecureRandom secureRandom = new SecureRandom();
    private final SecretKey encryptionAtRestKey;

    public CryptoService() {
        this.encryptionAtRestKey = generateAesKey();
    }

    public String generateHmacKeyB64() {
        byte[] key = new byte[32];
        secureRandom.nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }

    public String encryptAtRest(String plainText) {
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, encryptionAtRestKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            byte[] payload = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, payload, 0, iv.length);
            System.arraycopy(encrypted, 0, payload, iv.length, encrypted.length);
            return Base64.getEncoder().encodeToString(payload);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to encrypt cryptographic material", e);
        }
    }

    public String decryptAtRest(String encryptedValue) {
        try {
            byte[] payload = Base64.getDecoder().decode(encryptedValue);
            if (payload.length <= GCM_IV_LENGTH) {
                throw new BadRequestException("Invalid encrypted payload");
            }

            byte[] iv = new byte[GCM_IV_LENGTH];
            byte[] encrypted = new byte[payload.length - GCM_IV_LENGTH];
            System.arraycopy(payload, 0, iv, 0, iv.length);
            System.arraycopy(payload, iv.length, encrypted, 0, encrypted.length);

            Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, encryptionAtRestKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] plain = cipher.doFinal(encrypted);
            return new String(plain, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new UnauthorizedException("Unable to decrypt key material");
        }
    }

    public String signCanonical(String hmacKeyB64, String canonical) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(hmacKeyB64);
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, HMAC_SHA_256);
            Mac mac = Mac.getInstance(HMAC_SHA_256);
            mac.init(keySpec);
            byte[] digest = mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(digest);
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("Unable to compute message signature", ex);
        }
    }

    public String sha256B64(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getEncoder().encodeToString(digest.digest(data));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to hash payload", e);
        }
    }

    public boolean constantTimeEquals(String expected, String provided) {
        byte[] left = expected.getBytes(StandardCharsets.UTF_8);
        byte[] right = provided.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(left, right);
    }

    public byte[] randomBytes(int size) {
        byte[] data = new byte[size];
        secureRandom.nextBytes(data);
        return data;
    }

    public KeyPair generateX25519KeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(ECDH_ALGORITHM);
            generator.initialize(new NamedParameterSpec(ECDH_ALGORITHM));
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to generate X25519 key pair", e);
        }
    }

    public String encodePublicKeyB64(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public PublicKey decodeX25519PublicKey(String publicKeyB64) {
        try {
            byte[] encoded = Base64.getDecoder().decode(publicKeyB64);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
            return KeyFactory.getInstance(ECDH_ALGORITHM).generatePublic(spec);
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new BadRequestException("Invalid client public key");
        }
    }

    public byte[] deriveEcdhSharedSecret(KeyPair privateAndPublic, PublicKey peerPublicKey) {
        try {
            KeyAgreement agreement = KeyAgreement.getInstance(ECDH_ALGORITHM);
            agreement.init(privateAndPublic.getPrivate());
            agreement.doPhase(peerPublicKey, true);
            return agreement.generateSecret();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to derive shared secret", e);
        }
    }

    public DerivedSessionKeys deriveSessionKeys(byte[] sharedSecret, String sessionId, byte[] nonceClient, byte[] nonceServer) {
        byte[] salt = new byte[nonceClient.length + nonceServer.length];
        System.arraycopy(nonceClient, 0, salt, 0, nonceClient.length);
        System.arraycopy(nonceServer, 0, salt, nonceClient.length, nonceServer.length);

        byte[] prk = hmac(HMAC_SHA_256, salt, sharedSecret);
        byte[] infoBase = ("secure-channel-v1|" + sessionId).getBytes(StandardCharsets.UTF_8);
        byte[] encKey = hkdfExpand(prk, concat(infoBase, "|enc".getBytes(StandardCharsets.UTF_8)), 32);
        byte[] hmacKey = hkdfExpand(prk, concat(infoBase, "|hmac".getBytes(StandardCharsets.UTF_8)), 32);

        return new DerivedSessionKeys(
                Base64.getEncoder().encodeToString(encKey),
                Base64.getEncoder().encodeToString(hmacKey));
    }

    private byte[] hkdfExpand(byte[] prk, byte[] info, int outputLength) {
        int hashLen = 32;
        int steps = (int) Math.ceil((double) outputLength / hashLen);
        byte[] result = new byte[outputLength];
        byte[] previous = new byte[0];
        int copied = 0;

        for (int i = 1; i <= steps; i++) {
            byte[] message = concat(previous, info, new byte[] {(byte) i});
            previous = hmac(HMAC_SHA_256, prk, message);
            int bytesToCopy = Math.min(previous.length, outputLength - copied);
            System.arraycopy(previous, 0, result, copied, bytesToCopy);
            copied += bytesToCopy;
        }
        return result;
    }

    private byte[] hmac(String algorithm, byte[] key, byte[] message) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(key, algorithm));
            return mac.doFinal(message);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to compute HMAC", e);
        }
    }

    private byte[] concat(byte[]... arrays) {
        int length = Arrays.stream(arrays).mapToInt(a -> a.length).sum();
        byte[] out = new byte[length];
        int offset = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, out, offset, array.length);
            offset += array.length;
        }
        return out;
    }

    public record DerivedSessionKeys(String encryptionKeyB64, String hmacKeyB64) {
    }

    private SecretKey generateAesKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(DATA_KEY_ALGORITHM);
            keyGenerator.init(256);
            return keyGenerator.generateKey();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to initialize encryption key", e);
        }
    }
}

