// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.enroll;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ninja.gruber.btpc.cis.CisTokenCache;
import ninja.gruber.btpc.cis.support.FakeBtpServer;
import ninja.gruber.btpc.support.TestcontainersConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestcontainersConfiguration.class)
class SubaccountFlowIT {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired JdbcTemplate jdbc;
    @Autowired CisTokenCache tokenCache;

    private FakeBtpServer btp;
    private static final String SA_GUID = "00000000-0000-4000-8000-000000000001";

    @BeforeEach
    void setUp() throws Exception {
        jdbc.execute("TRUNCATE TABLE containment_events, discovered_subaccounts, central_viewer_keys, " +
                "subaccount_credentials, action_snapshots, subaccount_contacts, subaccounts, " +
                "ias_tenants CASCADE");
        btp = new FakeBtpServer();
        btp.respondWith("POST", "/oauth/token", 200, "application/json",
                "{\"access_token\":\"t\",\"expires_in\":3600}");
        btp.respondWith("GET", "/accounts/v1/subaccounts", 200, "application/json", """
                {"value":[{
                  "guid":"%s","displayName":"Trial US Subaccount","region":"us10",
                  "subdomain":"trial-us","state":"OK"
                }]}
                """.formatted(SA_GUID));
        tokenCache.invalidate(tokenCache.key(btp.baseUrl(), "secret-client-id-DO-NOT-LEAK"));
    }

    @AfterEach
    void tearDown() { if (btp != null) btp.close(); }

    private String centralCisKey() {
        // CIS Central-Viewer key - uaa.url has a realistic region-bearing
        // hostname so the classifier can extract region=us10. Central keys
        // have NO target subaccountid, so callers must supply it explicitly.
        return """
                {
                  "sap.cloud.service": "com.sap.core.commercial.service.central",
                  "endpoints": { "accounts_service_url": "%s" },
                  "uaa": {
                    "url": "https://fake-trial-ga.authentication.us10.hana.ondemand.com",
                    "apiurl": "%s",
                    "identityzone": "fake-trial-ga",
                    "clientid": "secret-client-id-DO-NOT-LEAK",
                    "clientsecret": "secret-client-secret-DO-NOT-LEAK",
                    "xsmasterappname": "cis-central!b14"
                  }
                }
                """.formatted(btp.baseUrl(), btp.baseUrl());
    }

    private String iasKey() {
        return """
                {
                  "btp-tenant-api": "https://api.authentication.us10.hana.ondemand.com",
                  "app_tid": "%s",
                  "clientid": "ias-cid",
                  "clientsecret": "secret-ias-DO-NOT-LEAK",
                  "url": "https://t.trial-accounts.ondemand.com",
                  "domain": "accounts.ondemand.com"
                }
                """.formatted(SA_GUID);
    }

    @Test
    void enroll_thenList_thenDelete_endToEnd() throws Exception {
        // Stage B: pasting an IAS key at enrollment is silently ignored
        // (IAS lives in ias_tenants now). The per-subaccount IAS tenant
        // link was dropped in V4 - tenants are global to the deployment.
        Map<String, Object> body = Map.of(
                "subaccountGuid", SA_GUID,
                "cisDisplayName", "Trial US Subaccount",
                "region", "us10",
                "label", "Test label",
                "serviceKeys", List.of(centralCisKey(), iasKey()));
        MvcResult res = mvc.perform(post("/api/v1/subaccounts")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(body)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.cisDisplayName").value("Trial US Subaccount"))
                .andExpect(jsonPath("$.label").value("Test label"))
                .andExpect(jsonPath("$.region").value("us10"))
                .andExpect(jsonPath("$.capabilities.cis").value(true))
                .andExpect(jsonPath("$.capabilities.xsuaaApiaccess").value(false))
                .andExpect(jsonPath("$.contactCount").value(0))
                .andReturn();
        JsonNode created = mapper.readTree(res.getResponse().getContentAsByteArray());
        String id = created.get("id").asText();

        mvc.perform(get("/api/v1/subaccounts").headers(devAuth()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1));

        // Only the CIS cipher is stored. IAS at the per-subaccount slot is
        // gone in Stage B.
        List<byte[]> ciphers = jdbc.query(
                "SELECT cipher FROM subaccount_credentials WHERE subaccount_id = ?::uuid",
                (rs, n) -> rs.getBytes("cipher"), id);
        assertThat(ciphers).hasSize(1);
        for (byte[] c : ciphers) {
            String asText = new String(c, java.nio.charset.StandardCharsets.ISO_8859_1);
            assertThat(asText).doesNotContain("secret-client-secret-DO-NOT-LEAK");
        }

        // IAS tenant lifecycle is independent of subaccount enrollment now.
        // Creating a tenant still encrypts the credentials at rest; verify
        // the cipher doesn't leak either the password or the P12 payload.
        MvcResult tenantRes = mvc.perform(post("/api/v1/ias-tenants")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "displayName": "Trial IAS",
                                  "url": "https://t.trial-accounts.ondemand.com",
                                  "p12Base64": "TUlJVEVTVHBsYWNlaG9sZGVyLURPLU5PVC1MRUFL",
                                  "p12Password": "secret-ias-DO-NOT-LEAK"
                                }
                                """))
                .andExpect(status().isCreated())
                .andReturn();
        String tenantId = mapper.readTree(tenantRes.getResponse().getContentAsByteArray())
                .get("id").asText();

        List<byte[]> tenantCiphers = jdbc.query(
                "SELECT encrypted_creds FROM ias_tenants WHERE id = ?::uuid",
                (rs, n) -> rs.getBytes("encrypted_creds"), tenantId);
        assertThat(tenantCiphers).hasSize(1);
        for (byte[] c : tenantCiphers) {
            String asText = new String(c, java.nio.charset.StandardCharsets.ISO_8859_1);
            assertThat(asText).doesNotContain("secret-ias-DO-NOT-LEAK");
            assertThat(asText).doesNotContain("TUlJVEVTVHBsYWNlaG9sZGVyLURPLU5PVC1MRUFL");
        }

        mvc.perform(delete("/api/v1/subaccounts/" + id).headers(devAuth()))
                .andExpect(status().isNoContent());
        mvc.perform(get("/api/v1/subaccounts/" + id).headers(devAuth()))
                .andExpect(status().isNotFound());
    }

    @Test
    void enroll_rejects_missing_subaccountGuid() throws Exception {
        // With CIS-local gone, enroll cannot infer the target - caller must
        // supply subaccountGuid. The endpoint now 400s when it's missing.
        Map<String, Object> body = Map.of(
                "serviceKeys", List.of(centralCisKey()));
        mvc.perform(post("/api/v1/subaccounts")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(body)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void enroll_centralKey_withExplicitGuid_derivesFromKey() throws Exception {
        // Display name + region are optional - the server falls back to the
        // identityzone + region parsed from the CIS key when not provided.
        Map<String, Object> body = Map.of(
                "subaccountGuid", SA_GUID,
                "serviceKeys", List.of(centralCisKey()));
        mvc.perform(post("/api/v1/subaccounts")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(body)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.region").value("us10"));
    }

    @Test
    void updateLabel_andAttachCredential() throws Exception {
        Map<String, Object> body = Map.of(
                "subaccountGuid", SA_GUID,
                "cisDisplayName", "Trial US Subaccount",
                "region", "us10",
                "label", "initial",
                "serviceKeys", List.of(centralCisKey()));
        MvcResult res = mvc.perform(post("/api/v1/subaccounts")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(body)))
                .andExpect(status().isCreated())
                .andReturn();
        String id = mapper.readTree(res.getResponse().getContentAsByteArray()).get("id").asText();

        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch(
                        "/api/v1/subaccounts/" + id + "/label")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content("{\"label\":\"renamed\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.label").value("renamed"));

        // Pasting an IAS key at the generic /credentials endpoint is now
        // rejected - IAS lives in ias_tenants since Stage B. We get a 400
        // pointing at the new tenant flow.
        mvc.perform(post("/api/v1/subaccounts/" + id + "/credentials")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(Map.of("serviceKey", iasKey()))))
                .andExpect(status().isBadRequest());
    }

    private static org.springframework.http.HttpHeaders devAuth() {
        org.springframework.http.HttpHeaders h = new org.springframework.http.HttpHeaders();
        h.add("X-Test-User", "test-admin@example.com");
        h.add("X-Test-Scopes", "btpc.admin");
        return h;
    }
}
