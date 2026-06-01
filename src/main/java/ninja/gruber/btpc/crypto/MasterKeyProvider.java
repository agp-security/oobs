// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.Base64;

@Component
public class MasterKeyProvider {

    private static final Logger log = LoggerFactory.getLogger(MasterKeyProvider.class);

    static final String USER_PROVIDED_SERVICE_NAME = "btp-containment-crypto-key";

    private static final String DEV_KEY_BASE64 =
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; //only local

    private final byte[] key;

    public MasterKeyProvider(
            @Value("${btpc.master-key:}") String configured,
            Environment env,
            ObjectMapper mapper) {
        byte[] resolved;
        String fromVcap;
        if (configured != null && !configured.isBlank()) {
            resolved = decode(configured, "btpc.master-key property");
            log.info("Master key sourced from btpc.master-key property");
        } else if ((fromVcap = readFromVcap(env, mapper)) != null) {
            resolved = decode(fromVcap, "VCAP_SERVICES user-provided[" + USER_PROVIDED_SERVICE_NAME + "].credentials.master_key");
            log.info("Master key sourced from user-provided service '{}'", USER_PROVIDED_SERVICE_NAME);
        } else if (isLocalProfile(env)) {
            resolved = decode(DEV_KEY_BASE64, "DEV_KEY (local profile)");
            log.warn("LOCAL PROFILE: using deterministic zero-key for AES gcm for testing.");
        } else {
            throw new IllegalStateException(
                    "No master key configured. Set BTPC_MASTER_KEY (base64 of 32 bytes) " +
                            "or bind the " + USER_PROVIDED_SERVICE_NAME + " user-provided service " +
                            "with credentials.master_key.");
        }
        if (resolved.length != 32) {
            throw new IllegalStateException(
                    "Master key must be exactly 32 bytes (AES-256); got " + resolved.length);
        }
        this.key = resolved;
    }

    public byte[] keyBytes() {
        return key.clone();
    }

    private static String readFromVcap(Environment env, ObjectMapper mapper) {
        String vcap = env.getProperty("VCAP_SERVICES");
        if (vcap == null || vcap.isBlank()) {
            return null;
        }
        try {
            JsonNode root = mapper.readTree(vcap);
            JsonNode arr = root.path("user-provided");
            if (!arr.isArray()) {
                return null;
            }
            for (JsonNode binding : arr) {
                if (USER_PROVIDED_SERVICE_NAME.equals(binding.path("name").asText())) {
                    JsonNode v = binding.path("credentials").path("master_key");
                    if (!v.isTextual() || v.asText().isBlank()) {
                        throw new IllegalStateException(
                                "user-provided service '" + USER_PROVIDED_SERVICE_NAME +
                                        "' is bound but credentials.master_key is missing or empty");
                    }
                    return v.asText();
                }
            }
            return null;
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("failed to parse VCAP_SERVICES: " + e.getMessage(), e);
        }
    }

    private static byte[] decode(String b64, String source) {
        try {
            return Base64.getDecoder().decode(b64);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(source + " is not valid base64", e);
        }
    }

    private static boolean isLocalProfile(Environment env) {
        for (String p : env.getActiveProfiles()) {
            if ("local".equals(p) || "test".equals(p)) {
                return true;
            }
        }
        return false;
    }
}
