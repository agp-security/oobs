// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import ninja.gruber.btpc.cis.CisException;
import ninja.gruber.btpc.cis.support.FakeBtpServer;
import ninja.gruber.btpc.support.Allowlists;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IasClientTest {

    private FakeBtpServer btp;
    private IasClient ias;

    @BeforeEach
    void setUp() throws Exception {
        btp = new FakeBtpServer();
        ias = new IasClient(new ObjectMapper(), Allowlists.permissive());
    }

    @AfterEach
    void tearDown() { btp.close(); }

    // FakeBtpServer runs plain HTTP, so IasClient's http:// branch is exercised
    // (mTLS is skipped - production paths are https:// and gated by
    // UrlAllowlist + IasTenantService.validate()). cert/key are omitted on
    // purpose: this test exercises the SCIM call shape, not the mTLS handshake.
    private String iasKey() {
        return """
                {
                  "url": "%s",
                  "clientid": "cid"
                }
                """.formatted(btp.baseUrl());
    }

    @Test
    void findUserByEmail_returnsSingleMatch() {
        btp.respondWith("GET", "/scim/Users", 200, "application/json", """
                {"Resources":[{"id":"u-123","userName":"alice@example.com","active":true,
                               "name":{"givenName":"Alice","familyName":"Smith"}}],
                 "totalResults":1}
                """);
        Optional<IasClient.IasUser> r = ias.findUserByEmail(iasKey(), "alice@example.com");
        assertThat(r).isPresent();
        assertThat(r.get().id()).isEqualTo("u-123");
        assertThat(r.get().active()).isTrue();
        assertThat(r.get().givenName()).isEqualTo("Alice");
        // No token round-trip - IAS authenticates via mTLS cert presentation only.
        assertThat(btp.hits("POST", "/oauth2/token")).isZero();
    }

    @Test
    void findUserByEmail_emptyResources_returnsEmpty() {
        btp.respondWith("GET", "/scim/Users", 200, "application/json",
                "{\"Resources\":[],\"totalResults\":0}");
        assertThat(ias.findUserByEmail(iasKey(), "nobody@example.com")).isEmpty();
    }

    @Test
    void setActive_patchesAndReturnsUpdated() {
        btp.respondWith("PATCH", "/scim/Users/u-123", 200, "application/scim+json",
                "{\"id\":\"u-123\",\"userName\":\"alice@example.com\",\"active\":false}");
        IasClient.IasUser updated = ias.setActive(iasKey(), "u-123", false);
        assertThat(updated.id()).isEqualTo("u-123");
        assertThat(updated.active()).isFalse();
        assertThat(btp.hits("PATCH", "/scim/Users/u-123")).isEqualTo(1);
    }

    @Test
    void scimUnauthorized_wrapsAsCisException() {
        // SCIM endpoint returns 401 (e.g. revoked or unknown client cert at the
        // mTLS layer). Mapped to CisException for the operator log.
        btp.respondWith("GET", "/scim/Users", 401, "application/json",
                "{\"error\":\"unauthorized\"}");
        assertThatThrownBy(() -> ias.findUserByEmail(iasKey(), "x@y.z"))
                .isInstanceOf(CisException.class)
                .hasMessageContaining("HTTP 401");
    }

    @Test
    void httpsUrlWithoutP12_failsFast() {
        // mTLS path requires a P12 blob. With an https URL and no p12Base64
        // in the cred JSON, IasClient must throw before sending any request -
        // there's no fallback to non-mTLS over https.
        String httpsKey = """
                {"url":"https://example.accounts.ondemand.com","clientid":"x"}
                """;
        assertThatThrownBy(() -> ias.findUserByEmail(httpsKey, "x@y.z"))
                .isInstanceOf(CisException.class)
                .hasMessageContaining("p12Base64 missing");
    }
}
