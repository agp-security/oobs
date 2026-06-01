// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.protect;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ninja.gruber.btpc.support.TestcontainersConfiguration;
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

import java.util.Map;
import java.util.UUID;

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
class ProtectedUserFlowIT {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired JdbcTemplate jdbc;

    @BeforeEach
    void clean() {
        jdbc.execute("TRUNCATE TABLE containment_events, protected_users, " +
                "subaccount_credentials, action_snapshots, subaccount_contacts, subaccounts CASCADE");
    }

    @Test
    void addGlobalProtection_andCheckMatches() throws Exception {
        addProtection(null, "ceo@example.com", "always exec", "manual", null);

        mvc.perform(get("/api/v1/protected-users/check")
                        .headers(devAuth())
                        .param("email", "ceo@example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.isProtected").value(true))
                .andExpect(jsonPath("$.matches[0].isGlobal").value(true));

        mvc.perform(get("/api/v1/protected-users/check")
                        .headers(devAuth())
                        .param("email", "someone-else@example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.isProtected").value(false));
    }

    @Test
    void perSubaccountAndGlobal_canCoexist() throws Exception {
        UUID saId = seedSubaccount();
        addProtection(null, "bob@example.com", "global break-glass", "manual", null);
        addProtection(saId, "bob@example.com", "local admin in this subaccount", "manual", null);

        mvc.perform(get("/api/v1/protected-users/check")
                        .headers(devAuth())
                        .param("email", "bob@example.com")
                        .param("subaccountId", saId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.isProtected").value(true))
                .andExpect(jsonPath("$.matches.length()").value(2));
    }

    @Test
    void duplicateActiveProtection_isRejected() throws Exception {
        addProtection(null, "alice@example.com", "exec", "manual", null);
        mvc.perform(post("/api/v1/protected-users")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(Map.of(
                                "userEmail", "alice@example.com",
                                "reason", "trying again"))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("conflict"));
    }

    @Test
    void disabledProtection_doesNotMatch() throws Exception {
        String id = addProtection(null, "dave@example.com", "test", "manual", null);
        mvc.perform(delete("/api/v1/protected-users/" + id).headers(devAuth()))
                .andExpect(status().isNoContent());
        mvc.perform(get("/api/v1/protected-users/check")
                        .headers(devAuth())
                        .param("email", "dave@example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.isProtected").value(false));
    }

    private UUID seedSubaccount() {
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO subaccounts
                  (id, subaccount_guid, cis_display_name, region, enrolled_by)
                VALUES (?, ?, 'Test SA', 'us10', 'test')
                """, id, UUID.randomUUID());
        return id;
    }

    private String addProtection(UUID subId, String email, String reason, String origin,
                                 String expiresAt) throws Exception {
        var body = new java.util.HashMap<String, Object>();
        body.put("userEmail", email);
        body.put("reason", reason);
        body.put("origin", origin);
        if (subId != null) body.put("subaccountId", subId.toString());
        if (expiresAt != null) body.put("expiresAt", expiresAt);
        var res = mvc.perform(post("/api/v1/protected-users")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(body)))
                .andExpect(status().isCreated())
                .andReturn();
        JsonNode created = mapper.readTree(res.getResponse().getContentAsByteArray());
        return created.get("id").asText();
    }

    private static HttpHeaders devAuth() {
        HttpHeaders h = new HttpHeaders();
        h.add("X-Test-User", "admin@example.com");
        h.add("X-Test-Scopes", "btpc.admin");
        return h;
    }
}
