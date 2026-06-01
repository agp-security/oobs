// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.crypto;

import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Objects;

// AES-256-GCM wrapper.
// Wrap output layout (single byte a column in Postgres):
//   <12-byte nonce> + ciphertext | 16-byte GCM tag
@Component
public class AesGcmBox {

    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;

    private final byte[] keyBytes;
    private final SecureRandom rng = new SecureRandom();

    public AesGcmBox(MasterKeyProvider keyProvider) {
        this.keyBytes = keyProvider.keyBytes();
    }

    public Wrapped wrap(byte[] plaintext, String aadContext) {
        Objects.requireNonNull(plaintext);
        Objects.requireNonNull(aadContext);
        byte[] nonce = new byte[NONCE_BYTES];
        rng.nextBytes(nonce);
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(keyBytes, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            c.updateAAD(aadContext.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            byte[] cipher = c.doFinal(plaintext);
            return new Wrapped(cipher, nonce);
        } catch (Exception e) {
            throw new CryptoException("AES-GCM wrap failed", e);
        }
    }

    public byte[] unwrap(byte[] cipher, byte[] nonce, String aadContext) {
        Objects.requireNonNull(cipher);
        Objects.requireNonNull(nonce);
        Objects.requireNonNull(aadContext);
        if (nonce.length != NONCE_BYTES) {
            throw new CryptoException("nonce must be " + NONCE_BYTES + " bytes; got " + nonce.length);
        }
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(keyBytes, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            c.updateAAD(aadContext.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return c.doFinal(cipher);
        } catch (Exception e) {
            throw new CryptoException("AES-GCM unwrap failed (tampered ciphertext, wrong AAD, or wrong key)", e);
        }
    }

    public record Wrapped(byte[] cipher, byte[] nonce) {}

    public static class CryptoException extends RuntimeException {
        public CryptoException(String msg) { super(msg); }
        public CryptoException(String msg, Throwable cause) { super(msg, cause); }
    }
}
