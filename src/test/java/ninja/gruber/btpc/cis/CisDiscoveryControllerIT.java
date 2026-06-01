// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.cis;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestcontainersConfiguration.class)
class CisDiscoveryControllerIT {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired CisTokenCache tokenCache;

    private FakeBtpServer btp;

    @BeforeEach
    void setUp() throws Exception {
        btp = new FakeBtpServer();
        tokenCache.invalidate(tokenCache.key(btp.baseUrl(), "cid"));
    }

    @AfterEach
    void tearDown() { btp.close(); }

    @Test
    void discover_returnsCandidatesForCentralPlanKey() throws Exception {
        btp.respondWith("POST", "/oauth/token", 200, "application/json", """
                {"access_token":"t","expires_in":3600}
                """);
        btp.respondWith("GET", "/accounts/v1/subaccounts", 200, "application/json", """
                {"value": [
                  {"guid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","displayName":"S-One","region":"eu10","state":"OK"},
                  {"guid":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","displayName":"S-Two","region":"us10","state":"OK"}
                ]}
                """);

        String key = """
                {
                  "sap.cloud.service":"com.sap.core.commercial.service.central",
                  "endpoints":{"accounts_service_url":"%s"},
                  "uaa":{"url":"%s","apiurl":"%s","clientid":"cid","clientsecret":"sec","xsmasterappname":"cis-central!b14"}
                }
                """.formatted(btp.baseUrl(), btp.baseUrl(), btp.baseUrl());

        mvc.perform(post("/api/v1/cis/discover")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(Map.of("serviceKey", key))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.count").value(2))
                .andExpect(jsonPath("$.subaccounts[0].displayName").value("S-One"))
                .andExpect(jsonPath("$.subaccounts[1].region").value("us10"));
    }

    @Test
    void discover_rejectsLocalPlanKey() throws Exception {
        String key = """
                {
                  "sap.cloud.service":"com.sap.core.commercial.service.local",
                  "endpoints":{"accounts_service_url":"%s"},
                  "uaa":{"url":"%s","apiurl":"%s","subaccountid":"00000000-0000-4000-8000-000000000001",
                         "clientid":"cid","clientsecret":"sec","xsmasterappname":"cis-local!b4"}
                }
                """.formatted(btp.baseUrl(), btp.baseUrl(), btp.baseUrl());

        mvc.perform(post("/api/v1/cis/discover")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(Map.of("serviceKey", key))))
                .andExpect(status().isBadRequest());
    }

    @Test
    void discover_uaaFailureBecomes502() throws Exception {
        btp.respondWith("POST", "/oauth/token", 401, "application/json",
                "{\"error\":\"unauthorized\"}");

        String key = """
                {
                  "sap.cloud.service":"com.sap.core.commercial.service.central",
                  "endpoints":{"accounts_service_url":"%s"},
                  "uaa":{"url":"%s","apiurl":"%s","clientid":"cid","clientsecret":"WRONG","xsmasterappname":"cis-central!b14"}
                }
                """.formatted(btp.baseUrl(), btp.baseUrl(), btp.baseUrl());

        mvc.perform(post("/api/v1/cis/discover")
                        .headers(devAuth())
                        .contentType(APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(Map.of("serviceKey", key))))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.error").value("cis_upstream"));
    }

    private static HttpHeaders devAuth() {
        HttpHeaders h = new HttpHeaders();
        h.add("X-Test-User", "admin@example.com");
        h.add("X-Test-Scopes", "btpc.admin");
        return h;
    }
}
