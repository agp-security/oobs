// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.containment;

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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestcontainersConfiguration.class)
class ContainmentFlowIT {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired JdbcTemplate jdbc;
    @Autowired CisTokenCache tokenCache;

    private FakeBtpServer btp;
    private UUID subaccountId;

    private static final String SA_GUID = "00000000-0000-4000-8000-000000000001";

    @BeforeEach
    void setUp() throws Exception {
        jdbc.execute("TRUNCATE TABLE containment_events, protected_users, " +
                "subaccount_credentials, action_snapshots, subaccount_contacts, subaccounts, " +
                "ias_tenants CASCADE");
        btp = new FakeBtpServer();
        // Wipe any cached tokens from prior tests
        tokenCache.invalidate(tokenCache.key(btp.baseUrl(), "ias-cid"));
        tokenCache.invalidate(tokenCache.key(btp.baseUrl(), "xsuaa-cid"));
        tokenCache.invalidate(tokenCache.key(btp.baseUrl(), "cis-cid"));
        subaccountId = enrollWithAllKeys();
    }

    @AfterEach
    void tearDown() { if (btp != null) btp.close(); }

    @Test
    void containment_dryRun_writesAuditButNoSnapshotsOrUpstreamMutation() throws Exception {
        // Stub IAS user lookup so the orchestrator can resolve the user.
        // IAS uses HTTP Basic - no /oauth2/token round-trip needed.
        btp.respondWith("GET", "/scim/Users", 200, "application/json", """
                {"Resources":[{"id":"ias-user-1","userName":"target@example.com","active":true}]}
                """);
        // Stub XSUAA token + shadow user lookup + role-collections list.
        btp.respondWith("POST", "/oauth/token", 200, "application/json",
                "{\"access_token\":\"xs-tok\",\"expires_in\":3600}");
        btp.respondWith("GET", "/Users", 200, "application/json", """
                {"Resources":[{"id":"sh-user-1","userName":"target@example.com","origin":"ias"}]}
                """);
        btp.respondWith("GET", "/Groups", 200, "application/json", """
                {"resources":[{"id":"g-1","displayName":"Subaccount Administrator","members":[
                  {"origin":"ias","type":"USER","value":"sh-user-1"}
                ]}],"totalResults":1}
                """);

        // All actions explicit in one list; ias_deactivate is per-tenant,
        // xsuaa_* are per-subaccount. Subaccount list defaults to "all
        // enrolled" when omitted; here we pin it for determinism.
        Map<String, Object> body = Map.of(
                "subaccountIds", List.of(subaccountId.toString()),
                "userEmail", "target@example.com",
                "actions", List.of("ias_deactivate", "xsuaa_strip_roles", "xsuaa_delete_shadow"),
                "dryRun", true);

        MvcResult res = mvc.perform(post("/api/v1/containment")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(body)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.dryRun").value(true))
                .andExpect(jsonPath("$.iasResults[0].outcome").value("dry-run"))
                .andExpect(jsonPath("$.perSubaccount.length()").value(1))
                .andExpect(jsonPath("$.perSubaccount[0].blockedByProtection").value(false))
                .andExpect(jsonPath("$.perSubaccount[0].results.length()").value(2))
                .andReturn();
        JsonNode r = mapper.readTree(res.getResponse().getContentAsByteArray());
        for (JsonNode ar : r.get("perSubaccount").get(0).get("results")) {
            assertThat(ar.get("outcome").asText()).isEqualTo("dry-run");
        }

        // No upstream MUTATION called. Reads (token + lookup) are fine.
        assertThat(btp.hits("PATCH", "/scim/Users/ias-user-1")).isZero();
        assertThat(btp.hits("DELETE", "/Users/sh-user-1")).isZero();

        // Audit rows exist. ias_deactivate writes a tenant-scoped row
        // (system_type='IAS', system_id=iasTenantId); xsuaa_* rows are
        // per-subaccount (system_type='SUBACCOUNT', system_id=subaccountId).
        Integer xsuaaAudit = jdbc.queryForObject("""
                SELECT count(*)::int FROM containment_events
                WHERE system_type = 'SUBACCOUNT' AND system_id = ?
                  AND action IN ('xsuaa_strip_roles','xsuaa_delete_shadow')
                """, Integer.class, subaccountId.toString());
        assertThat(xsuaaAudit).isEqualTo(2);
        Integer iasAudit = jdbc.queryForObject("""
                SELECT count(*)::int FROM containment_events
                WHERE system_type = 'IAS' AND action = 'ias_deactivate'
                """, Integer.class);
        assertThat(iasAudit).isEqualTo(1);

        Integer xsuaaSnaps = jdbc.queryForObject(
                "SELECT count(*)::int FROM action_snapshots WHERE system_type = 'SUBACCOUNT' AND system_id = ?",
                Integer.class, subaccountId.toString());
        assertThat(xsuaaSnaps).isZero();
        Integer iasSnaps = jdbc.queryForObject(
                "SELECT count(*)::int FROM action_snapshots WHERE system_type = 'IAS'",
                Integer.class);
        assertThat(iasSnaps).isZero();
    }

    @Test
    void unlock_dryRun_returnsDryRun_andLeavesSnapshotsUnconsumed() throws Exception {
        btp.respondWith("GET", "/scim/Users", 200, "application/json", """
                {"Resources":[{"id":"ias-user-1","userName":"target@example.com","active":true}]}
                """);
        // Stub upstream mutations the live seed run will actually call:
        // PATCH /scim/Users/ias-user-1 (IAS deactivate) and PATCH /Groups/g-1
        // (XSUAA strip role membership). 204 = no content, standard SCIM.
        btp.respondWith("PATCH", "/scim/Users/ias-user-1", 204, "application/json", "");
        btp.respondWith("PATCH", "/Groups/g-1", 204, "application/json", "");
        btp.respondWith("POST", "/oauth/token", 200, "application/json",
                "{\"access_token\":\"xs-tok\",\"expires_in\":3600}");
        btp.respondWith("GET", "/Users", 200, "application/json", """
                {"Resources":[{"id":"sh-user-1","userName":"target@example.com","origin":"ias"}]}
                """);
        btp.respondWith("GET", "/Groups", 200, "application/json", """
                {"resources":[{"id":"g-1","displayName":"Subaccount Administrator","members":[
                  {"origin":"ias","type":"USER","value":"sh-user-1"}
                ]}],"totalResults":1}
                """);
        mvc.perform(post("/api/v1/containment")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(Map.of(
                                "subaccountIds", List.of(subaccountId.toString()),
                                "userEmail", "target@example.com",
                                "actions", List.of("ias_deactivate", "xsuaa_strip_roles"),
                                "dryRun", false))))
                .andExpect(status().isOk());

        Integer snapsBefore = jdbc.queryForObject(
                "SELECT count(*)::int FROM action_snapshots WHERE consumed_at IS NULL",
                Integer.class);
        assertThat(snapsBefore).isGreaterThanOrEqualTo(2);

        // Capture upstream hit counts BEFORE the unlock so we can verify the
        // unlock dry-run added nothing on top (the seed naturally hit PATCH).
        int iasPatchBeforeUnlock = btp.hits("PATCH", "/scim/Users/ias-user-1");
        int groupPatchBeforeUnlock = btp.hits("PATCH", "/Groups/g-1");

        // Now unlock with dryRun (default).
        mvc.perform(post("/api/v1/containment/unlock")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(Map.of(
                                "subaccountIds", List.of(subaccountId.toString()),
                                "userEmail", "target@example.com",
                                "actions", List.of("ias_activate", "xsuaa_restore_roles"),
                                "dryRun", true))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.dryRun").value(true))
                // Multi-tenant unlock: iasResults is a list, one entry per
                // tenant. xsuaa_restore_roles lives in perSubaccount.
                .andExpect(jsonPath("$.iasResults[0].outcome").value("dry-run"))
                .andExpect(jsonPath("$.perSubaccount[0].results[*].outcome")
                        .value(org.hamcrest.Matchers.everyItem(
                                org.hamcrest.Matchers.is("dry-run"))));

        // Snapshots still NOT consumed because the unlock was a dry-run.
        Integer snapsAfter = jdbc.queryForObject(
                "SELECT count(*)::int FROM action_snapshots WHERE consumed_at IS NULL",
                Integer.class);
        assertThat(snapsAfter).isEqualTo(snapsBefore);

        // Audit rows for ias_activate + xsuaa_restore_roles exist.
        Integer unlockEvents = jdbc.queryForObject("""
                SELECT count(*)::int FROM containment_events
                 WHERE action IN ('ias_activate','xsuaa_restore_roles')
                """, Integer.class);
        assertThat(unlockEvents).isEqualTo(2);

        // No NEW upstream PATCH after unlock (counts unchanged from before).
        assertThat(btp.hits("PATCH", "/scim/Users/ias-user-1")).isEqualTo(iasPatchBeforeUnlock);
        assertThat(btp.hits("PATCH", "/Groups/g-1")).isEqualTo(groupPatchBeforeUnlock);
    }

    @Test
    void containment_protectedUser_isBlocked() throws Exception {
        // Add a global protection for the target user.
        mvc.perform(post("/api/v1/protected-users")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(Map.of(
                                "userEmail", "target@example.com",
                                "reason", "break-glass - never lock"))))
                .andExpect(status().isCreated());

        Map<String, Object> body = Map.of(
                "subaccountIds", List.of(subaccountId.toString()),
                "userEmail", "target@example.com",
                "actions", List.of("ias_deactivate", "xsuaa_strip_roles"),
                "dryRun", false);

        mvc.perform(post("/api/v1/containment")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(body)))
                .andExpect(status().isOk())
                // Global protection -> hard-exit. iasResults and perSubaccount
                // are empty; the response carries globalProtectionReasons.
                .andExpect(jsonPath("$.globalProtectionReasons[0]")
                        .value("break-glass - never lock"))
                .andExpect(jsonPath("$.iasResults.length()").value(0))
                .andExpect(jsonPath("$.perSubaccount.length()").value(0));

        // No upstream calls at all when blocked. IAS is HTTP Basic, so the
        // proof of "didn't dial IAS" is zero hits on the SCIM endpoint.
        assertThat(btp.hits("GET", "/scim/Users")).isZero();
        assertThat(btp.hits("POST", "/oauth/token")).isZero();

        // One INTERNAL-scoped protect_block audit row (system_id IS NULL,
        // system_type = 'INTERNAL').
        Integer blocked = jdbc.queryForObject("""
                SELECT count(*)::int FROM containment_events
                 WHERE system_id IS NULL
                   AND system_type = 'INTERNAL'
                   AND action = 'protect_block'
                """, Integer.class);
        assertThat(blocked).isEqualTo(1);
    }

    @Test
    void liveStripRoles_noRights_failsAndLeavesNoOrphanSnapshot() throws Exception {
        // Token + shadow-user + group-membership lookups all resolve fine...
        btp.respondWith("POST", "/oauth/token", 200, "application/json",
                "{\"access_token\":\"xs-tok\",\"expires_in\":3600}");
        btp.respondWith("GET", "/Users", 200, "application/json", """
                {"Resources":[{"id":"sh-user-1","userName":"target@example.com","origin":"ias"}]}
                """);
        btp.respondWith("GET", "/Groups", 200, "application/json", """
                {"resources":[{"id":"g-1","displayName":"Subaccount Administrator","members":[
                  {"origin":"ias","type":"USER","value":"sh-user-1"}
                ]}],"totalResults":1}
                """);
        // ...but the membership-removing PATCH is rejected: the technical user
        // lacks the rights. Snapshot-before-mutate writes a row first; the failed
        // mutation must then clean it up.
        btp.respondWith("PATCH", "/Groups/g-1", 403, "application/json",
                "{\"error\":\"insufficient_scope\"}");

        mvc.perform(post("/api/v1/containment")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(Map.of(
                                "subaccountIds", List.of(subaccountId.toString()),
                                "userEmail", "target@example.com",
                                "actions", List.of("xsuaa_strip_roles"),
                                "dryRun", false))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.perSubaccount[0].results[0].outcome").value("failed"));

        // No orphan snapshot left behind - otherwise a later /unlock would
        // re-grant role collections that were never actually stripped.
        Integer snaps = jdbc.queryForObject(
                "SELECT count(*)::int FROM action_snapshots WHERE system_type = 'SUBACCOUNT' AND system_id = ?",
                Integer.class, subaccountId.toString());
        assertThat(snaps).isZero();
    }

    // ----- helpers -----

    private UUID enrollWithAllKeys() throws Exception {
        String cisKey = """
                {
                  "sap.cloud.service":"com.sap.core.commercial.service.central",
                  "endpoints":{"accounts_service_url":"%s"},
                  "uaa":{
                    "url":"https://fake-trial-ga.authentication.us10.hana.ondemand.com",
                    "apiurl":"%s",
                    "identityzone":"fake-trial-ga",
                    "clientid":"cis-cid",
                    "clientsecret":"cis-sec",
                    "xsmasterappname":"cis-central!b14"
                  }
                }
                """.formatted(btp.baseUrl(), btp.baseUrl());
        // IAS key - distinguished by top-level btp-tenant-api + app_tid.
        String iasKey = """
                {
                  "btp-tenant-api":"https://api.authentication.us10.hana.ondemand.com",
                  "app_tid":"%s",
                  "clientid":"ias-cid",
                  "clientsecret":"ias-sec",
                  "url":"%s",
                  "domain":"accounts.ondemand.com"
                }
                """.formatted(SA_GUID, btp.baseUrl());
        // XSUAA api-access key - uaa with apiurl, no sap.cloud.service.
        String xsuaaKey = """
                {
                  "tenantid":"%s",
                  "subaccountid":"%s",
                  "uaa":{
                    "url":"%s",
                    "apiurl":"%s",
                    "clientid":"xsuaa-cid",
                    "clientsecret":"xsuaa-sec",
                    "subaccountid":"%s",
                    "identityzone":"fake-trial",
                    "xsappname":"xs-app"
                  }
                }
                """.formatted(SA_GUID, SA_GUID, btp.baseUrl(), btp.baseUrl(), SA_GUID);

        Map<String, Object> body = Map.of(
                "subaccountGuid", SA_GUID,
                "cisDisplayName", "Test SA",
                "region", "us10",
                "serviceKeys", List.of(cisKey, xsuaaKey));

        MvcResult r = mvc.perform(post("/api/v1/subaccounts")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(body)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.capabilities.cis").value(true))
                .andExpect(jsonPath("$.capabilities.xsuaaApiaccess").value(true))
                .andReturn();
        String id = mapper.readTree(r.getResponse().getContentAsByteArray()).get("id").asText();

        // Create the IAS tenant pointing at the fake BTP server. There is no
        // per-subaccount link anymore (V4); ContainmentService resolves IAS
        // tenants from the request's explicit list or falls back to every
        // enrolled tenant - so this single tenant is what gets touched on a
        // request that doesn't pass iasTenantIds.
        // URL is http://localhost so IasClient takes the plain-HTTP branch
        // and never parses the P12 - a base64 placeholder satisfies the
        // shape check in validate().
        mvc.perform(post("/api/v1/ias-tenants")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(String.format("""
                                {
                                  "displayName": "Test IAS",
                                  "url": "%s",
                                  "p12Base64": "TUlJVEVTVHBsYWNlaG9sZGVy",
                                  "p12Password": ""
                                }
                                """, btp.baseUrl())))
                .andExpect(status().isCreated());

        return UUID.fromString(id);
    }

    private static HttpHeaders devAuth() {
        HttpHeaders h = new HttpHeaders();
        h.add("X-Test-User", "admin@example.com");
        h.add("X-Test-Scopes", "btpc.admin");
        return h;
    }
}
