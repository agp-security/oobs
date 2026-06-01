// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.cf;

import com.fasterxml.jackson.databind.ObjectMapper;
import ninja.gruber.btpc.cis.CisTokenCache;
import ninja.gruber.btpc.cis.support.FakeBtpServer;
import ninja.gruber.btpc.support.Allowlists;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CfApiClientTest {

    private FakeBtpServer btp;
    private CisTokenCache tokenCache;
    private CfApiClient client;

    @BeforeEach
    void setUp() throws Exception {
        btp = new FakeBtpServer();
        tokenCache = new CisTokenCache();
        client = new CfApiClient(new ObjectMapper(), tokenCache, Allowlists.permissive());
        tokenCache.put(
                tokenCache.key(btp.baseUrl() + "#passcode", "btpc-bot@example.com"),
                "t",
                Duration.ofMinutes(10));
    }

    @AfterEach
    void tearDown() { if (btp != null) btp.close(); }

    @Test
    void listOrganizations_parsesV3PaginatedResponse() {
        btp.respondWith("GET", "/v3/organizations", 200, "application/json", """
                {
                  "pagination": { "next": null },
                  "resources": [
                    {"guid":"org-aaa","name":"Acme-Prod"},
                    {"guid":"org-bbb","name":"Acme-Dev"}
                  ]
                }
                """);
        List<CfApiClient.Organization> orgs = client.listOrganizations(passcodeCreds());
        assertThat(orgs).hasSize(2);
        assertThat(orgs.get(0).guid()).isEqualTo("org-aaa");
        assertThat(orgs.get(1).name()).isEqualTo("Acme-Dev");
    }

    @Test
    void listRolesForUser_filtersByOrg() {
        btp.respondWith("GET", "/v3/roles", 200, "application/json", """
                {
                  "pagination": { "next": null },
                  "resources": [
                    {"guid":"role-1","type":"organization_manager"},
                    {"guid":"role-2","type":"organization_billing_manager"}
                  ]
                }
                """);
        List<CfApiClient.RoleEntry> roles = client.listRolesForUser(
                passcodeCreds(), "user-xxx", "org-aaa", null);
        assertThat(roles).hasSize(2);
        assertThat(roles.get(0).type()).isEqualTo("organization_manager");
        assertThat(roles.get(0).orgGuid()).isEqualTo("org-aaa");
        assertThat(roles.get(0).userGuid()).isEqualTo("user-xxx");
    }

    @Test
    void deleteRole_issuesDeleteCall() {
        btp.respondWith("DELETE", "/v3/roles/role-1", 202, "application/json", "");
        client.deleteRole(passcodeCreds(), "role-1");
        // No exception = the route was registered, FakeBtpServer responded 202.
    }

    @Test
    void findUserByUsername_passesOriginsFilter() {
        btp.respondWith("GET", "/v3/users", 200, "application/json", """
                {"pagination":{"next":null},"resources":[
                  {"guid":"u-1","username":"alice@contoso.com","origin":"sap.default"}
                ]}
                """);
        List<CfApiClient.CfUser> users = client.findUserByUsername(passcodeCreds(),
                "alice@contoso.com", "sap.default,subaccount-a-platform");
        assertThat(users).hasSize(1);
        assertThat(btp.hits("GET", "/v3/users")).isEqualTo(1);
    }

    @Test
    void findUsersAcrossOrgs_walksOrgsAndSpaces_andDedupes() {
        btp.respondWith("GET", "/v3/organizations", 200, "application/json", """
                {"pagination":{"next":null},"resources":[{"guid":"org-a","name":"Acme"}]}
                """);
        btp.respondWith("GET", "/v3/spaces", 200, "application/json", """
                {"pagination":{"next":null},"resources":[{"guid":"sp-1","name":"dev"}]}
                """);
        btp.respondWith("GET", "/v3/roles", 200, "application/json", """
                {"pagination":{"next":null},
                 "resources":[
                   {"guid":"r-1","type":"organization_manager","relationships":{"user":{"data":{"guid":"u-1"}}}},
                   {"guid":"r-2","type":"space_developer","relationships":{"user":{"data":{"guid":"u-1"}}}},
                   {"guid":"r-3","type":"organization_auditor","relationships":{"user":{"data":{"guid":"u-2"}}}}
                 ],
                 "included":{"users":[
                   {"guid":"u-1","username":"target@contoso.com","origin":"subaccount-b-platform"},
                   {"guid":"u-2","username":"someone-else@example.com","origin":"sap.default"}
                 ]}}
                """);
        List<CfApiClient.CfUser> matches = client.findUsersAcrossOrgs(passcodeCreds(),
                "target@contoso.com");
        assertThat(matches).hasSize(1);
        assertThat(matches.get(0).guid()).isEqualTo("u-1");
        assertThat(matches.get(0).origin()).isEqualTo("subaccount-b-platform");
    }

    @Test
    void findUsersAcrossOrgs_returnsEmptyWhenNoMatch() {
        btp.respondWith("GET", "/v3/organizations", 200, "application/json", """
                {"pagination":{"next":null},"resources":[]}
                """);
        assertThat(client.findUsersAcrossOrgs(passcodeCreds(), "nobody@example.com"))
                .isEmpty();
    }

    @Test
    void listUsersInOrg_dedupesViaIncludedUsers() {
        btp.respondWith("GET", "/v3/roles", 200, "application/json", """
                {
                  "pagination": { "next": null },
                  "resources": [
                    {"guid":"role-1","type":"organization_manager","relationships":{"user":{"data":{"guid":"u-1"}}}},
                    {"guid":"role-2","type":"organization_billing_manager","relationships":{"user":{"data":{"guid":"u-1"}}}},
                    {"guid":"role-3","type":"organization_auditor","relationships":{"user":{"data":{"guid":"u-2"}}}}
                  ],
                  "included": {
                    "users": [
                      {"guid":"u-1","username":"alice@contoso.com","origin":"ias"},
                      {"guid":"u-2","username":"bob@external.example","origin":"ias"}
                    ]
                  }
                }
                """);
        List<CfApiClient.CfUser> users = client.listUsersInOrg(passcodeCreds(), "org-aaa");
        assertThat(users).hasSize(2);
        assertThat(users.get(0).username()).isEqualTo("alice@contoso.com");
        assertThat(users.get(1).username()).isEqualTo("bob@external.example");
    }

    @Test
    void obtainToken_returnsCachedTokenWithoutHittingPasscodeFlow() {
        assertThat(client.obtainToken(passcodeCreds())).isEqualTo("t");
    }

    private String passcodeCreds() {
        return """
                {
                  "cfApiUrl": "%s",
                  "cfUaaUrl": "%s",
                  "username": "btpc-bot@example.com",
                  "origin": "sap.default",
                  "iasPasscodeUrl": "%s/service/users/passcode",
                  "p12Base64": "",
                  "p12Password": "ignored"
                }
                """.formatted(btp.baseUrl(), btp.baseUrl(), btp.baseUrl());
    }
}
