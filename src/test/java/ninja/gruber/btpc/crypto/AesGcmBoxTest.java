// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.*;

class AesGcmBoxTest {

    private AesGcmBox box;

    @BeforeEach
    void setUp() {
        // 32-byte test key
        byte[] key = new byte[32];
        for (int i = 0; i < 32; i++) key[i] = (byte) i;
        String keyB64 = Base64.getEncoder().encodeToString(key);

        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("test");
        MasterKeyProvider provider = new MasterKeyProvider(keyB64, env, new ObjectMapper());
        box = new AesGcmBox(provider);
    }

    @Test
    void wrap_then_unwrap_roundTrips() {
        byte[] plain = "the quick brown fox".getBytes(StandardCharsets.UTF_8);
        String aad = "00000000-0000-0000-0000-000000000001:cis";

        AesGcmBox.Wrapped w = box.wrap(plain, aad);
        byte[] back = box.unwrap(w.cipher(), w.nonce(), aad);

        assertThat(back).isEqualTo(plain);
    }

    @Test
    void unwrap_failsWhenAadDiffers() {
        AesGcmBox.Wrapped w = box.wrap("secret".getBytes(StandardCharsets.UTF_8), "sub-A:cis");
        assertThatThrownBy(() -> box.unwrap(w.cipher(), w.nonce(), "sub-B:cis"))
                .isInstanceOf(AesGcmBox.CryptoException.class);
    }

    @Test
    void unwrap_failsWhenCipherTampered() {
        AesGcmBox.Wrapped w = box.wrap("payload".getBytes(StandardCharsets.UTF_8), "ctx");
        byte[] tampered = w.cipher().clone();
        tampered[0] ^= 0x01;
        assertThatThrownBy(() -> box.unwrap(tampered, w.nonce(), "ctx"))
                .isInstanceOf(AesGcmBox.CryptoException.class);
    }

    @Test
    void wrap_producesFreshNonceEachCall() {
        AesGcmBox.Wrapped w1 = box.wrap("same".getBytes(StandardCharsets.UTF_8), "ctx");
        AesGcmBox.Wrapped w2 = box.wrap("same".getBytes(StandardCharsets.UTF_8), "ctx");
        assertThat(w1.nonce()).isNotEqualTo(w2.nonce());
        assertThat(w1.cipher()).isNotEqualTo(w2.cipher());
    }
}
