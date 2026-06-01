// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.sod;

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
import org.springframework.http.HttpHeaders;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestcontainersConfiguration.class)
class SodScanIT {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired JdbcTemplate jdbc;
    @Autowired CisTokenCache tokenCache;

    private FakeBtpServer btp;
    private UUID subaccountId;

    private static final String SA_GUID = "00000000-0000-4000-8000-000000000001";//random uui4 sub id

    @BeforeEach
    void setUp() throws Exception {
        jdbc.execute("TRUNCATE TABLE containment_events, conflict_sets, protected_users, " +
                "subaccount_credentials, action_snapshots, subaccount_contacts, subaccounts CASCADE");
        btp = new FakeBtpServer();
        tokenCache.invalidate(tokenCache.key(btp.baseUrl(), "xsuaa-cid"));
        tokenCache.invalidate(tokenCache.key(btp.baseUrl(), "cis-cid"));

        subaccountId = enroll();
        seedConflictSet();
    }

    @AfterEach
    void tearDown() { if (btp != null) btp.close(); }

    @Test
    void scan_findsUserWithBothConflictingRoleCollections() throws Exception {
        // XSUAA token + user enumeration + per-user role collections
        btp.respondWith("POST", "/oauth/token", 200, "application/json",
                "{\"access_token\":\"xs-tok\",\"expires_in\":3600}");
        btp.respondWith("GET", "/Users", 200, "application/json", """
                {"Resources":[
                  {"id":"u-1","userName":"alice@example.com","origin":"ias"},
                  {"id":"u-2","userName":"bob@example.com","origin":"ias"}
                ],"totalResults":2}
                """);
        // /Groups gives us the full RC -> members map in one call. Both alice
        // and bob are members of both conflicting groups -> both flagged.
        btp.respondWith("GET", "/Groups", 200, "application/json", """
                {"resources":[
                  {"id":"g-admin","displayName":"Subaccount Administrator","members":[
                    {"origin":"ias","type":"USER","value":"u-1"},
                    {"origin":"ias","type":"USER","value":"u-2"}
                  ]},
                  {"id":"g-audit","displayName":"Subaccount Auditor","members":[
                    {"origin":"ias","type":"USER","value":"u-1"},
                    {"origin":"ias","type":"USER","value":"u-2"}
                  ]}
                ],"totalResults":2}
                """);

        MvcResult res = mvc.perform(post("/api/v1/sod/scan")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(Map.of(
                                "subaccountId", subaccountId.toString()))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.conflictSetCount").value(1))
                .andReturn();
        JsonNode r = mapper.readTree(res.getResponse().getContentAsByteArray());
        assertThat(r.get("findings").size()).isEqualTo(2);
        assertThat(r.get("findings").get(0).get("conflictSetName").asText())
                .isEqualTo("Admin vs Audit");

        // Audit: 1 sod_scan + 2 sod_finding rows
        Integer scans = jdbc.queryForObject(
                "SELECT count(*)::int FROM containment_events WHERE action = 'sod_scan' AND system_id = ?",
                Integer.class, subaccountId.toString());
        assertThat(scans).isGreaterThanOrEqualTo(1);
        Integer findings = jdbc.queryForObject(
                "SELECT count(*)::int FROM containment_events WHERE action = 'sod_finding' AND system_id = ?",
                Integer.class, subaccountId.toString());
        assertThat(findings).isEqualTo(2);
    }

    private UUID enroll() throws Exception {
        String cisKey = """
                {
                  "sap.cloud.service":"com.sap.core.commercial.service.central",
                  "endpoints":{"accounts_service_url":"%s"},
                  "uaa":{
                    "url":"https://fake-ga.authentication.us10.hana.ondemand.com",
                    "apiurl":"%s","identityzone":"fake-ga",
                    "clientid":"cis-cid","clientsecret":"cis-sec",
                    "xsmasterappname":"cis-central!b14"
                  }
                }
                """.formatted(btp.baseUrl(), btp.baseUrl());
        String xsuaaKey = """
                {
                  "tenantid":"%s","subaccountid":"%s",
                  "uaa":{
                    "url":"%s","apiurl":"%s",
                    "clientid":"xsuaa-cid","clientsecret":"xsuaa-sec",
                    "subaccountid":"%s","identityzone":"fake","xsappname":"xs"
                  }
                }
                """.formatted(SA_GUID, SA_GUID, btp.baseUrl(), btp.baseUrl(), SA_GUID);
        Map<String, Object> body = Map.of(
                "subaccountGuid", SA_GUID,
                "cisDisplayName", "Test SA",
                "region", "us10",
                "serviceKeys", List.of(cisKey, xsuaaKey));
        MvcResult res = mvc.perform(post("/api/v1/subaccounts")
                        .headers(devAuth()).contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(body)))
                .andExpect(status().isCreated())
                .andReturn();
        return UUID.fromString(mapper.readTree(res.getResponse().getContentAsByteArray()).get("id").asText());
    }

    private void seedConflictSet() throws Exception {
        mvc.perform(post("/api/v1/sod/conflict-sets")
                        .headers(devAuth()).contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(Map.of(
                                "name", "Admin vs Audit",
                                "severity", "high",
                                "scopeLevel", "subaccount",
                                "roleCollections", List.of(
                                        "Subaccount Administrator", "Subaccount Auditor")))))
                .andExpect(status().isCreated());
    }

    private static HttpHeaders devAuth() {
        HttpHeaders h = new HttpHeaders();
        h.add("X-Test-User", "admin@example.com");
        h.add("X-Test-Scopes", "btpc.admin");
        return h;
    }
}
