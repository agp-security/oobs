// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.discovery;

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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestcontainersConfiguration.class)
class DiscoveryFlowIT {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired JdbcTemplate jdbc;
    @Autowired CisTokenCache tokenCache;

    private FakeBtpServer btp;

    private static final String SA_GUID_A = "00000000-0000-4000-8000-000000000001";
    private static final String SA_GUID_B = "8f7c5a91-1111-4222-9333-cd4444444444";
    private static final String GA_GUID   = "00000000-0000-4000-8000-000000000002";

    @BeforeEach
    void setUp() throws Exception {
        jdbc.execute("TRUNCATE TABLE discovered_subaccounts, central_viewer_keys, " +
                "containment_events, subaccount_credentials, action_snapshots, " +
                "subaccount_contacts, subaccounts CASCADE");
        btp = new FakeBtpServer();
        btp.respondWith("POST", "/oauth/token", 200, "application/json",
                "{\"access_token\":\"t\",\"expires_in\":3600}");
        // CIS-shape response with the new fields (globalAccountGUID,
        // usedForProduction, stateMessage) and two subaccounts under the
        // same global account.
        btp.respondWith("GET", "/accounts/v1/subaccounts", 200, "application/json", """
                {"value":[
                  {"guid":"%s","displayName":"trial-a","globalAccountGUID":"%s",
                   "parentGUID":"%s","parentType":"PROJECT","region":"us10",
                   "subdomain":"trial-a-sub","betaEnabled":false,"usedForProduction":"UNSET",
                   "description":null,"state":"OK","stateMessage":"Subaccount moved."},
                  {"guid":"%s","displayName":"trial-b","globalAccountGUID":"%s",
                   "parentGUID":"%s","parentType":"PROJECT","region":"eu10",
                   "subdomain":"trial-b-sub","betaEnabled":false,"usedForProduction":"USED_FOR_PRODUCTION",
                   "description":null,"state":"OK","stateMessage":null}
                ]}
                """.formatted(SA_GUID_A, GA_GUID, GA_GUID, SA_GUID_B, GA_GUID, GA_GUID));
        tokenCache.invalidate(tokenCache.key(btp.baseUrl(), "central-cid"));
    }

    @AfterEach
    void tearDown() { if (btp != null) btp.close(); }

    private String centralKey() {
        // Both `accounts_service_url` and `uaa.url` point at FakeBtpServer so
        // the probe-on-save AND the scheduled sync call hit the in-process
        // stub (CisClient uses uaa.url for the token call, accounts URL for
        // the list call).
        return """
                {
                  "sap.cloud.service": "com.sap.core.commercial.service.central",
                  "endpoints": { "accounts_service_url": "%s" },
                  "uaa": {
                    "url": "%s",
                    "apiurl": "%s",
                    "identityzone": "fake-ga",
                    "clientid": "central-cid",
                    "clientsecret": "central-secret-DO-NOT-LEAK",
                    "xsmasterappname": "cis-central!b14"
                  }
                }
                """.formatted(btp.baseUrl(), btp.baseUrl(), btp.baseUrl());
    }

    @Test
    void saveCentralKey_thenSync_thenPromote_endToEnd() throws Exception {
        // 1. Save the key. The probe-on-save call lists subaccounts; the
        //    response also populates the discovered_subaccounts table.
        MvcResult res = mvc.perform(post("/api/v1/discovery/keys")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(Map.of(
                                "serviceKey", centralKey(),
                                "label", "Prod GA",
                                "syncIntervalMinutes", 30,
                                "syncEnabled", true))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.label").value("Prod GA"))
                .andExpect(jsonPath("$.syncEnabled").value(true))
                .andExpect(jsonPath("$.syncIntervalMinutes").value(30))
                .andExpect(jsonPath("$.globalAccountId").value(GA_GUID))
                .andReturn();
        String keyId = mapper.readTree(res.getResponse().getContentAsByteArray()).get("id").asText();

        // Plaintext secret must not be discoverable in the persisted row.
        List<byte[]> ciphers = jdbc.query(
                "SELECT cipher FROM central_viewer_keys WHERE id = ?::uuid",
                (rs, n) -> rs.getBytes("cipher"), keyId);
        assertThat(ciphers).hasSize(1);
        String asText = new String(ciphers.get(0), java.nio.charset.StandardCharsets.ISO_8859_1);
        assertThat(asText).doesNotContain("central-secret-DO-NOT-LEAK");

        // 2. Trigger a sync (the save itself probes but doesn't write
        //    candidates - that happens in syncOne).
        mvc.perform(post("/api/v1/discovery/keys/" + keyId + "/sync").headers(devAuth()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ok").value(true))
                .andExpect(jsonPath("$.upserts").value(2));

        // 3. List the candidates - V12 has no status filter; default returns all.
        mvc.perform(get("/api/v1/discovery/candidates")
                        .param("onlyPromotable", "true").headers(devAuth()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2));

        // 4. Pick candidate A and look up its discovery row id.
        JsonNode candidates = mapper.readTree(mvc.perform(
                        get("/api/v1/discovery/candidates").headers(devAuth()))
                .andReturn().getResponse().getContentAsByteArray());
        String discoveredId = null;
        for (JsonNode c : candidates) {
            if (SA_GUID_A.equals(c.get("subaccountGuid").asText())) {
                discoveredId = c.get("id").asText();
                break;
            }
        }
        assertThat(discoveredId).isNotNull();

        // 5. Promote candidate A by enrolling. After enrollment, the candidate
        //    is excluded from the promotable list (JOIN finds the new sa row).
        MvcResult enrolled = mvc.perform(post("/api/v1/subaccounts")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(Map.of(
                                "subaccountGuid", SA_GUID_A,
                                "cisDisplayName", "trial-a",
                                "region", "us10",
                                "discoveredId", discoveredId,
                                "serviceKeys", List.of()))))
                .andExpect(status().isCreated())
                .andReturn();
        String enrolledSubaccountId = mapper.readTree(enrolled.getResponse().getContentAsByteArray())
                .get("id").asText();

        // V12: enrolledSubaccountId is the JOIN-derived field; non-null after enrollment.
        mvc.perform(get("/api/v1/discovery/candidates/" + discoveredId).headers(devAuth()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enrolledSubaccountId").value(enrolledSubaccountId));

        // 6. onlyPromotable=true now hides candidate A (it's enrolled) but
        //    still shows B (untouched).
        mvc.perform(get("/api/v1/discovery/candidates")
                        .param("onlyPromotable", "true").headers(devAuth()))
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].subaccountGuid").value(SA_GUID_B));

        // 7. Delete the enrolled subaccount - candidate A re-appears as promotable.
        //    This is the bug V12 fixed: the old state machine kept the row at
        //    status='enrolled' forever even after the subaccount was deleted.
        mvc.perform(delete("/api/v1/subaccounts/" + enrolledSubaccountId).headers(devAuth()))
                .andExpect(status().isNoContent());
        mvc.perform(get("/api/v1/discovery/candidates")
                        .param("onlyPromotable", "true").headers(devAuth()))
                .andExpect(jsonPath("$.length()").value(2));
    }

    @Test
    void saveCentralKey_rejectsLocalPlanKey() throws Exception {
        String localKey = """
                {
                  "sap.cloud.service": "com.sap.core.commercial.service.local",
                  "endpoints": { "accounts_service_url": "%s" },
                  "uaa": {
                    "url": "https://fake.authentication.us10.hana.ondemand.com",
                    "apiurl": "%s",
                    "subaccountid": "%s",
                    "clientid": "x",
                    "clientsecret": "y",
                    "xsmasterappname": "cis-local!b4"
                  }
                }
                """.formatted(btp.baseUrl(), btp.baseUrl(), SA_GUID_A);
        mvc.perform(post("/api/v1/discovery/keys")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(Map.of("serviceKey", localKey))))
                .andExpect(status().isBadRequest());
    }

    @Test
    void updateAndDeleteSavedKey() throws Exception {
        MvcResult res = mvc.perform(post("/api/v1/discovery/keys")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(Map.of(
                                "serviceKey", centralKey(),
                                "label", "initial"))))
                .andExpect(status().isCreated())
                .andReturn();
        String keyId = mapper.readTree(res.getResponse().getContentAsByteArray()).get("id").asText();

        mvc.perform(patch("/api/v1/discovery/keys/" + keyId)
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content("{\"syncEnabled\":false,\"syncIntervalMinutes\":120,\"label\":\"renamed\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.syncEnabled").value(false))
                .andExpect(jsonPath("$.syncIntervalMinutes").value(120))
                .andExpect(jsonPath("$.label").value("renamed"));

        mvc.perform(delete("/api/v1/discovery/keys/" + keyId).headers(devAuth()))
                .andExpect(status().isNoContent());
        mvc.perform(get("/api/v1/discovery/keys/" + keyId).headers(devAuth()))
                .andExpect(status().isNotFound());
    }

    @Test
    void duplicateKeyForSameGlobalAccount_isRejected() throws Exception {
        mvc.perform(post("/api/v1/discovery/keys")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(Map.of("serviceKey", centralKey()))))
                .andExpect(status().isCreated());

        mvc.perform(post("/api/v1/discovery/keys")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(Map.of("serviceKey", centralKey()))))
                .andExpect(status().isConflict());
    }

    private static org.springframework.http.HttpHeaders devAuth() {
        org.springframework.http.HttpHeaders h = new org.springframework.http.HttpHeaders();
        h.add("X-Test-User", "test-admin@example.com");
        h.add("X-Test-Scopes", "btpc.admin");
        return h;
    }
}
