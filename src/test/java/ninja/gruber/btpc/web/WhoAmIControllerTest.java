// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.web;

import ninja.gruber.btpc.support.TestcontainersConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestcontainersConfiguration.class)
class WhoAmIControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Test
    void whoamiReturnsUserAndScopes_whenDevAuthHeadersPresent() throws Exception {
        mockMvc.perform(get("/api/v1/whoami")
                        .header("X-Test-User", "alice@example.com")
                        .header("X-Test-Scopes", "btpc.admin,btpc.responder"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authenticated").value(true))
                .andExpect(jsonPath("$.user").value("alice@example.com"))
                .andExpect(jsonPath("$.scopes[0]").value("btpc.admin"))
                .andExpect(jsonPath("$.scopes[1]").value("btpc.responder"));
    }

    @Test
    void whoamiReturns401_whenNoHeaders() throws Exception {
        mockMvc.perform(get("/api/v1/whoami"))
                .andExpect(status().isUnauthorized());
    }
}
