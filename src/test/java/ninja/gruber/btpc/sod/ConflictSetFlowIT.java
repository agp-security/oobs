// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.sod;

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
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;
import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestcontainersConfiguration.class)
class ConflictSetFlowIT {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired JdbcTemplate jdbc;

    @BeforeEach
    void clean() {
        jdbc.execute("TRUNCATE TABLE containment_events, conflict_sets, " +
                "protected_users, subaccount_credentials, action_snapshots, " +
                "subaccount_contacts, subaccounts CASCADE");
    }

    @Test
    void create_update_disable_delete_roundTrip() throws Exception {
        // CREATE
        MvcResult res = mvc.perform(post("/api/v1/sod/conflict-sets")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(Map.of(
                                "name", "Admin separation",
                                "description", "user must not hold both subaccount admin and audit",
                                "severity", "high",
                                "roleCollections", List.of("Subaccount Administrator", "Subaccount Auditor"),
                                "scopeLevel", "subaccount"))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value("Admin separation"))
                .andExpect(jsonPath("$.severity").value("high"))
                .andExpect(jsonPath("$.enabled").value(true))
                .andReturn();
        JsonNode created = mapper.readTree(res.getResponse().getContentAsByteArray());
        String id = created.get("id").asText();

        // UPDATE
        mvc.perform(put("/api/v1/sod/conflict-sets/" + id)
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(Map.of(
                                "name", "Admin separation v2",
                                "severity", "critical",
                                "roleCollections", List.of("Subaccount Administrator", "Subaccount Auditor", "Connectivity Admin"),
                                "scopeLevel", "subaccount"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.severity").value("critical"))
                .andExpect(jsonPath("$.roleCollections.length()").value(3));

        // DISABLE via PATCH
        mvc.perform(patch("/api/v1/sod/conflict-sets/" + id + "/enabled")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content("{\"enabled\":false}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(false));

        // DELETE
        mvc.perform(delete("/api/v1/sod/conflict-sets/" + id).headers(devAuth()))
                .andExpect(status().isNoContent());
        mvc.perform(get("/api/v1/sod/conflict-sets/" + id).headers(devAuth()))
                .andExpect(status().isNotFound());
    }

    @Test
    void duplicateName_isConflict() throws Exception {
        Map<String, Object> body = Map.of(
                "name", "Dup",
                "severity", "low",
                "roleCollections", List.of("A", "B"));
        mvc.perform(post("/api/v1/sod/conflict-sets")
                        .headers(devAuth()).contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(body)))
                .andExpect(status().isCreated());
        mvc.perform(post("/api/v1/sod/conflict-sets")
                        .headers(devAuth()).contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(body)))
                .andExpect(status().isConflict());
    }

    @Test
    void rejectsTooFewRoleCollections() throws Exception {
        mvc.perform(post("/api/v1/sod/conflict-sets")
                        .headers(devAuth()).contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(Map.of(
                                "name", "Solo",
                                "severity", "low",
                                "roleCollections", List.of("OnlyOne")))))
                .andExpect(status().isBadRequest());
    }

    private static HttpHeaders devAuth() {
        HttpHeaders h = new HttpHeaders();
        h.add("X-Test-User", "admin@example.com");
        h.add("X-Test-Scopes", "btpc.admin");
        return h;
    }
}
