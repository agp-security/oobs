// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.contacts;

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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestcontainersConfiguration.class)
class ContactFlowIT {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired JdbcTemplate jdbc;

    private UUID subId;

    @BeforeEach
    void clean() {
        jdbc.execute("TRUNCATE TABLE containment_events, protected_users, discovered_subaccounts, " +
                "central_viewer_keys, subaccount_credentials, action_snapshots, " +
                "subaccount_contacts, subaccounts CASCADE");
        subId = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO subaccounts
                  (id, subaccount_guid, cis_display_name, region, enrolled_by)
                VALUES (?, ?, 'Test SA', 'eu10', 'test')
                """, subId, UUID.randomUUID());
    }

    @Test
    void addUpdateDelete_endToEnd() throws Exception {
        // POST
        var res = mvc.perform(post("/api/v1/subaccounts/" + subId + "/contacts")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(Map.of(
                                "name", "Bob Smith",
                                "email", "bob@example.com",
                                "role", "security",
                                "notes", "primary IR contact"))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value("Bob Smith"))
                .andReturn();
        JsonNode created = mapper.readTree(res.getResponse().getContentAsByteArray());
        String id = created.get("id").asText();

        // LIST
        mvc.perform(get("/api/v1/subaccounts/" + subId + "/contacts").headers(devAuth()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1));

        // UPDATE
        mvc.perform(put("/api/v1/subaccounts/" + subId + "/contacts/" + id)
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(Map.of(
                                "name", "Robert Smith",
                                "email", "bob@example.com",
                                "role", "security"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Robert Smith"));

        // DELETE
        mvc.perform(delete("/api/v1/subaccounts/" + subId + "/contacts/" + id).headers(devAuth()))
                .andExpect(status().isNoContent());
        mvc.perform(get("/api/v1/subaccounts/" + subId + "/contacts").headers(devAuth()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0));
    }

    @Test
    void rejectsInvalidRole() throws Exception {
        mvc.perform(post("/api/v1/subaccounts/" + subId + "/contacts")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(Map.of(
                                "name", "X",
                                "email", "x@example.com",
                                "role", "ceo"))))
                .andExpect(status().isBadRequest());
    }

    private static HttpHeaders devAuth() {
        HttpHeaders h = new HttpHeaders();
        h.add("X-Test-User", "admin@example.com");
        h.add("X-Test-Scopes", "btpc.admin");
        return h;
    }
}
