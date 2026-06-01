// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import ninja.gruber.btpc.support.TestcontainersConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestcontainersConfiguration.class)
class ScopeEnforcementIT {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;

    @Test
    void viewerCannotEnrollSubaccount() throws Exception {
        mvc.perform(post("/api/v1/subaccounts")
                        .headers(scopes("btpc.viewer"))
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(Map.of(
                                "serviceKeys", List.of("{}")))))
                .andExpect(status().isForbidden());
    }

    @Test
    void viewerCannotRunContainment() throws Exception {
        mvc.perform(post("/api/v1/containment")
                        .headers(scopes("btpc.viewer"))
                        .contentType(APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void responderCanRunContainment_butCannotEnroll() throws Exception {
        // Responder hits containment OK (request itself will 400 on bad body - that's still past the scope gate)
        mvc.perform(post("/api/v1/containment")
                        .headers(scopes("btpc.responder"))
                        .contentType(APPLICATION_JSON)
                        .content("{}"))
                .andExpect(result -> {
                    int s = result.getResponse().getStatus();
                    if (s == 401 || s == 403) {
                        throw new AssertionError("responder should pass scope gate; got " + s);
                    }
                });
        // But enrollment is admin-only
        mvc.perform(post("/api/v1/subaccounts")
                        .headers(scopes("btpc.responder"))
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(Map.of("serviceKeys", List.of("{}")))))
                .andExpect(status().isForbidden());
    }

    @Test
    void viewerCanRead() throws Exception {
        mvc.perform(get("/api/v1/subaccounts").headers(scopes("btpc.viewer")))
                .andExpect(status().isOk());
        mvc.perform(get("/api/v1/protected-users").headers(scopes("btpc.viewer")))
                .andExpect(status().isOk());
    }

    @Test
    void adminCanDelete() throws Exception {
        // No real subaccount; admin scope passes, controller returns 404.
        mvc.perform(delete("/api/v1/subaccounts/00000000-0000-0000-0000-000000000001")
                        .headers(scopes("btpc.admin")))
                .andExpect(status().isNotFound());
    }

    private static HttpHeaders scopes(String scopes) {
        HttpHeaders h = new HttpHeaders();
        h.add("X-Test-User", "test@example.com");
        h.add("X-Test-Scopes", scopes);
        return h;
    }
}
