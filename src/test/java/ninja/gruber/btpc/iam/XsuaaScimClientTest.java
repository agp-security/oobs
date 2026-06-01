// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import ninja.gruber.btpc.cis.CisException;
import ninja.gruber.btpc.cis.CisTokenCache;
import ninja.gruber.btpc.cis.support.FakeBtpServer;
import ninja.gruber.btpc.support.Allowlists;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class XsuaaScimClientTest {

    private FakeBtpServer btp;
    private XsuaaScimClient client;

    @BeforeEach
    void setUp() throws Exception {
        btp = new FakeBtpServer();
        client = new XsuaaScimClient(new ObjectMapper(), new CisTokenCache(), Allowlists.permissive());
    }

    @AfterEach
    void tearDown() { btp.close(); }

    private String xsuaaKey() {
        // url + apiurl point at the same fake server (port-wise) - the client
        // uses url for oauth and apiurl for /Users etc.
        return """
                {
                  "uaa": {
                    "url": "%s",
                    "apiurl": "%s",
                    "clientid": "cid",
                    "clientsecret": "sec",
                    "subaccountid": "00000000-0000-4000-8000-000000000001",
                    "identityzone": "trial"
                  }
                }
                """.formatted(btp.baseUrl(), btp.baseUrl());
    }

    @Test
    void findUserByEmail_returnsShadow() {
        btp.respondWith("POST", "/oauth/token", 200, "application/json",
                "{\"access_token\":\"t\",\"expires_in\":3600}");
        btp.respondWith("GET", "/Users", 200, "application/json", """
                {"Resources":[{"id":"x-1","userName":"alice@example.com","origin":"ias"}]}
                """);
        Optional<XsuaaScimClient.ShadowUser> u = client.findUserByEmail(xsuaaKey(), "alice@example.com");
        assertThat(u).isPresent();
        assertThat(u.get().id()).isEqualTo("x-1");
        assertThat(u.get().origin()).isEqualTo("ias");
    }

    @Test
    void listGroups_returnsGroupsAndMembers() {
        btp.respondWith("POST", "/oauth/token", 200, "application/json",
                "{\"access_token\":\"t\",\"expires_in\":3600}");
        btp.respondWith("GET", "/Groups", 200, "application/json", """
                {"resources":[
                  {"id":"g-admin","displayName":"Subaccount Administrator","members":[
                    {"origin":"ias","type":"USER","value":"u-1"},
                    {"origin":"subaccount-b-platform","type":"USER","value":"u-2"}
                  ]},
                  {"id":"g-cnd","displayName":"Connectivity and Destination Administrator","members":[
                    {"origin":"sap.default","type":"USER","value":"u-3"}
                  ]}
                ],"totalResults":2}
                """);
        List<XsuaaScimClient.Group> groups = client.listGroups(xsuaaKey());
        assertThat(groups).hasSize(2);
        assertThat(groups.get(0).displayName()).isEqualTo("Subaccount Administrator");
        assertThat(groups.get(0).members()).hasSize(2);
        assertThat(groups.get(0).members().get(1).origin()).isEqualTo("subaccount-b-platform");
        assertThat(groups.get(0).members().get(1).userId()).isEqualTo("u-2");
    }

    @Test
    void removeMember_sendsScimDeletePatch() {
        btp.respondWith("POST", "/oauth/token", 200, "application/json",
                "{\"access_token\":\"t\",\"expires_in\":3600}");
        btp.respondWith("PATCH", "/Groups/g-admin", 204, "application/json", "");
        client.removeMember(xsuaaKey(), "g-admin", "u-1");
        assertThat(btp.hits("PATCH", "/Groups/g-admin")).isEqualTo(1);
    }

    @Test
    void removeMember_treats404AsIdempotentSuccess() {
        btp.respondWith("POST", "/oauth/token", 200, "application/json",
                "{\"access_token\":\"t\",\"expires_in\":3600}");
        btp.respondWith("PATCH", "/Groups/g-gone", 404, "application/json",
                "{\"error\":\"group not found\"}");
        // No throw: the group is gone, so the membership is also gone - done.
        client.removeMember(xsuaaKey(), "g-gone", "u-1");
        assertThat(btp.hits("PATCH", "/Groups/g-gone")).isEqualTo(1);
    }

    @Test
    void removeMember_propagatesNon404Errors() {
        btp.respondWith("POST", "/oauth/token", 200, "application/json",
                "{\"access_token\":\"t\",\"expires_in\":3600}");
        btp.respondWith("PATCH", "/Groups/g-admin", 500, "application/json",
                "{\"error\":\"boom\"}");
        assertThatThrownBy(() -> client.removeMember(xsuaaKey(), "g-admin", "u-1"))
                .isInstanceOf(CisException.class)
                .hasMessageContaining("500");
    }

    @Test
    void addMember_sendsScimAddPatch() {
        btp.respondWith("POST", "/oauth/token", 200, "application/json",
                "{\"access_token\":\"t\",\"expires_in\":3600}");
        btp.respondWith("PATCH", "/Groups/g-admin", 200, "application/json",
                "{\"id\":\"g-admin\"}");
        client.addMember(xsuaaKey(), "g-admin", "u-1", "ias");
        assertThat(btp.hits("PATCH", "/Groups/g-admin")).isEqualTo(1);
    }

    @Test
    void deleteShadowUser_callsDelete() {
        btp.respondWith("POST", "/oauth/token", 200, "application/json",
                "{\"access_token\":\"t\",\"expires_in\":3600}");
        btp.respondWith("DELETE", "/Users/x-1", 204, "application/json", "");
        client.deleteShadowUser(xsuaaKey(), "x-1");
        assertThat(btp.hits("DELETE", "/Users/x-1")).isEqualTo(1);
    }
}
