// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.cis;
import ninja.gruber.btpc.cis.domain.SubaccountCandidate;

import com.fasterxml.jackson.databind.ObjectMapper;
import ninja.gruber.btpc.cis.support.FakeBtpServer;
import ninja.gruber.btpc.support.Allowlists;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CisClientTest {

    private FakeBtpServer btp;
    private CisClient cis;
    private CisTokenCache tokenCache;

    @BeforeEach
    void setUp() throws Exception {
        btp = new FakeBtpServer();
        tokenCache = new CisTokenCache();
        cis = new CisClient(new ObjectMapper(), tokenCache, Allowlists.permissive());
    }

    @AfterEach
    void tearDown() {
        btp.close();
    }

    private String serviceKey() {
        return """
                {
                  "sap.cloud.service": "com.sap.core.commercial.service.central",
                  "endpoints": { "accounts_service_url": "%s" },
                  "uaa": {
                    "url": "%s",
                    "apiurl": "%s",
                    "clientid": "test-cid",
                    "clientsecret": "test-secret",
                    "xsmasterappname": "cis-central!b14"
                  }
                }
                """.formatted(btp.baseUrl(), btp.baseUrl(), btp.baseUrl());
    }

    @Test
    void listSubaccounts_happyPath() {
        btp.respondWith("POST", "/oauth/token", 200, "application/json", """
                {"access_token":"tok-abc","token_type":"bearer","expires_in":3600}
                """);
        btp.respondWith("GET", "/accounts/v1/subaccounts", 200, "application/json", """
                {"value": [
                  {"guid":"11111111-1111-1111-1111-111111111111",
                   "displayName":"Trial EU","subdomain":"eu-trial","region":"eu10",
                   "parentType":"global-account","parentGUID":"ga-1",
                   "betaEnabled":false,"state":"OK"},
                  {"guid":"22222222-2222-2222-2222-222222222222",
                   "displayName":"Trial US","subdomain":"us-trial","region":"us10",
                   "parentType":"global-account","parentGUID":"ga-1",
                   "betaEnabled":true,"state":"OK"}
                ]}
                """);

        List<SubaccountCandidate> r = cis.listSubaccounts(serviceKey());

        assertThat(r).hasSize(2);
        assertThat(r.get(0).displayName()).isEqualTo("Trial EU");
        assertThat(r.get(1).betaEnabled()).isTrue();
        assertThat(btp.hits("POST", "/oauth/token")).isEqualTo(1);
        assertThat(btp.hits("GET", "/accounts/v1/subaccounts")).isEqualTo(1);
    }

    @Test
    void tokenIsCachedAcrossCalls() {
        btp.respondWith("POST", "/oauth/token", 200, "application/json", """
                {"access_token":"tok-abc","expires_in":3600}
                """);
        btp.respondWith("GET", "/accounts/v1/subaccounts", 200, "application/json",
                """
                {"value": []}
                """);

        cis.listSubaccounts(serviceKey());
        cis.listSubaccounts(serviceKey());
        cis.listSubaccounts(serviceKey());

        assertThat(btp.hits("POST", "/oauth/token")).isEqualTo(1);
        assertThat(btp.hits("GET", "/accounts/v1/subaccounts")).isEqualTo(3);
    }

    @Test
    void uaaFailure_isWrappedAsCisException() {
        btp.respondWith("POST", "/oauth/token", 401, "application/json", """
                {"error":"unauthorized","error_description":"Bad credentials"}
                """);

        //CisClient parses the body regardless of status and trips
        //on the missing access_token field
        assertThatThrownBy(() -> cis.listSubaccounts(serviceKey()))
                .isInstanceOf(CisException.class)
                .hasMessageContaining("access_token");
    }

    @Test
    void accountsServiceFailure_isWrappedAsCisException() {
        btp.respondWith("POST", "/oauth/token", 200, "application/json", """
                {"access_token":"tok","expires_in":3600}
                """);
        btp.respondWith("GET", "/accounts/v1/subaccounts", 500, "text/plain", "boom");

        assertThatThrownBy(() -> cis.listSubaccounts(serviceKey()))
                .isInstanceOf(CisException.class)
                .hasMessageContaining("HTTP 500");
    }

    @Test
    void missingUaaUrl_fails() {
        String bad = """
                {"sap.cloud.service":"com.sap.core.commercial.service.central",
                 "endpoints":{"accounts_service_url":"%s"},
                 "uaa":{"clientid":"c","clientsecret":"s","xsmasterappname":"cis-central"}}
                """.formatted(btp.baseUrl());
        assertThatThrownBy(() -> cis.listSubaccounts(bad))
                .isInstanceOf(CisException.class)
                .hasMessageContaining("url");
    }
}
