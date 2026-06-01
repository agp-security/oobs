// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.enroll;

import ninja.gruber.btpc.config.UrlAllowlist;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UrlAllowlistTest {

    private final UrlAllowlist allowlist = new UrlAllowlist(
            ".hana.ondemand.com,.cloud.sap,.accounts.ondemand.com,127.0.0.1");

    @Test
    void allowsTrustedHosts() {
        assertThat(allowlist.isAllowed("https://accounts-service.cfapps.eu10.hana.ondemand.com")).isTrue();
        assertThat(allowlist.isAllowed("https://api.cloud.sap")).isTrue();
        assertThat(allowlist.isAllowed("https://trial.accounts.ondemand.com")).isTrue();
        assertThat(allowlist.isAllowed("http://127.0.0.1:8443/anything")).isTrue();
    }

    @Test
    void rejectsForeignHosts() {
        assertThat(allowlist.isAllowed("https://evil.example.com/oauth/token")).isFalse();
        assertThat(allowlist.isAllowed("http://attacker.internal:9999/")).isFalse();
        // Suffix-prefix mimicry must not slip through ("notreal.hana.ondemand.com.evil.com")
        assertThat(allowlist.isAllowed("https://hana.ondemand.com.evil.com/")).isFalse();
        // Bare domain without leading dot in suffix mode must also fail
        assertThat(allowlist.isAllowed("https://accounts.ondemand.com.attacker.io/")).isFalse();
    }

    @Test
    void rejectsMalformedUrls() {
        assertThat(allowlist.isAllowed("not a url")).isFalse();
        assertThat(allowlist.isAllowed("")).isFalse();
        assertThat(allowlist.isAllowed(null)).isFalse();
    }

    @Test
    void requireAllowed_throwsWithFieldName() {
        assertThatThrownBy(() -> allowlist.requireAllowed("https://evil.com", "uaa.url"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("uaa.url");
    }
}
