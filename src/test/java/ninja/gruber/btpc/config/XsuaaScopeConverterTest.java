// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.config;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class XsuaaScopeConverterTest {

    @Test
    void stripsXsappnamePrefix_andYieldsSCOPE_authorities() {
        XsuaaJwtConfig.XsuaaBinding b = new XsuaaJwtConfig.XsuaaBinding(
                "https://example.authentication.eu10.hana.ondemand.com",
                "btp-containment!t123",
                "sb-btp-containment!t123",
                null,
                "authentication.eu10.hana.ondemand.com");
        JwtAuthenticationConverter conv = new XsuaaJwtConfig().jwtAuthenticationConverter(b);

        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject("u-1")
                .claim("user_name", "alice@example.com")
                .claim("scope", List.of(
                        "btp-containment!t123.btpc.admin",
                        "btp-containment!t123.btpc.responder",
                        "openid",                  // unrelated, no prefix
                        "uaa.user"))               // unrelated, no prefix
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();

        var auth = conv.convert(jwt);
        Set<String> authorities = AuthorityUtils.authorityListToSet(auth.getAuthorities());

        assertThat(authorities).contains("SCOPE_btpc.admin", "SCOPE_btpc.responder",
                "SCOPE_openid", "SCOPE_uaa.user");
        assertThat(auth.getName()).isEqualTo("alice@example.com");
    }

    @Test
    void emptyScopeClaim_yieldsNoAuthorities() {
        XsuaaJwtConfig.XsuaaBinding b = new XsuaaJwtConfig.XsuaaBinding(
                "https://example.authentication.eu10.hana.ondemand.com",
                "btp-containment!t123",
                "sb-btp-containment!t123",
                null, null);
        JwtAuthenticationConverter conv = new XsuaaJwtConfig().jwtAuthenticationConverter(b);

        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject("u-1")
                .claim("user_name", "bob@example.com")
                .claim("scope", List.<String>of())
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();

        var auth = conv.convert(jwt);
        assertThat(auth.getAuthorities()).isEmpty();
        assertThat(auth.getName()).isEqualTo("bob@example.com");
    }
}
