// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Configuration
@Profile("cloud")
public class XsuaaJwtConfig {

    private static final Logger log = LoggerFactory.getLogger(XsuaaJwtConfig.class);

    @Bean
    XsuaaBinding xsuaaBinding(Environment env, ObjectMapper mapper) {
        String vcap = env.getProperty("VCAP_SERVICES");
        if (vcap == null || vcap.isBlank()) {
            throw new IllegalStateException(
                    "cloud profile requires VCAP_SERVICES env var with an xsuaa binding");
        }
        try {
            JsonNode root = mapper.readTree(vcap);
            JsonNode arr = root.path("xsuaa");
            if (!arr.isArray() || arr.isEmpty()) {
                throw new IllegalStateException("VCAP_SERVICES.xsuaa[0] is missing");
            }
            JsonNode cred = arr.get(0).path("credentials");
            String url             = required(cred, "url");
            String xsappname       = required(cred, "xsappname");
            String clientId        = required(cred, "clientid");
            String clientSecret    = optional(cred, "clientsecret");
            String uaadomain       = optional(cred, "uaadomain");
            log.info("XSUAA binding: url={} xsappname={} uaadomain={} hasClientSecret={}",
                    url, xsappname, uaadomain, clientSecret != null);
            return new XsuaaBinding(url, xsappname, clientId, clientSecret, uaadomain);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("failed to parse VCAP_SERVICES: " + e.getMessage(), e);
        }
    }

    // Verify against XSUAA's published JWK set (<url>/token_keys) rather than a
    // static offline verificationkey. Nimbus caches the key set and refetches on
    // an unknown `kid`, so XSUAA signing-key rotation is handled transparently -
    // a rotated key no longer breaks auth or pins us to a key we can't revoke.
    @Bean
    JwtDecoder jwtDecoder(XsuaaBinding b) {
        String jwksUri = b.url().replaceAll("/+$", "") + "/token_keys";
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwksUri).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithValidators(
                new XsuaaAudienceValidator(b.clientId())));
        log.info("XSUAA JWT decoder using JWKS endpoint {} (keys refreshed on rotation)", jwksUri);
        return decoder;
    }

    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter(XsuaaBinding b) {
        String prefix = b.xsappname() + ".";
        JwtGrantedAuthoritiesConverter inner = new JwtGrantedAuthoritiesConverter();
        inner.setAuthoritiesClaimName("scope");
        inner.setAuthorityPrefix("");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setPrincipalClaimName("user_name");
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Collection<GrantedAuthority> out = new ArrayList<>();
            Collection<GrantedAuthority> raw = inner.convert(jwt);
            for (GrantedAuthority a : raw) {
                String s = a.getAuthority();
                if (s == null) continue;
                if (s.startsWith(prefix)) {
                    out.add(new SimpleGrantedAuthority("SCOPE_" + s.substring(prefix.length())));
                } else {
                    out.add(new SimpleGrantedAuthority("SCOPE_" + s));
                }
            }
            return out;
        });
        return converter;
    }

    static class XsuaaAudienceValidator implements OAuth2TokenValidator<Jwt> {
        private final String clientId;
        XsuaaAudienceValidator(String clientId) { this.clientId = clientId; }
        @Override
        public OAuth2TokenValidatorResult validate(Jwt jwt) {
            Object cid = jwt.getClaims().get("cid");
            if (cid != null && clientId.equals(cid.toString())) {
                return OAuth2TokenValidatorResult.success();
            }
            List<String> auds = jwt.getAudience();
            if (auds != null && auds.contains(clientId)) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                    "invalid_audience",
                    "token's cid/aud does not match this app's clientid",
                    null));
        }
    }

    private static String required(JsonNode n, String f) {
        JsonNode v = n.path(f);
        if (!v.isTextual() || v.asText().isBlank()) {
            throw new IllegalStateException("VCAP_SERVICES.xsuaa[0].credentials." + f + " is missing");
        }
        return v.asText();
    }
    private static String optional(JsonNode n, String f) {
        JsonNode v = n.path(f);
        return v.isTextual() ? v.asText() : null;
    }

    @ConfigurationProperties(prefix = "btpc.xsuaa")
    public record XsuaaBinding(
            String url,
            String xsappname,
            String clientId,
            String clientSecret,
            String uaadomain) {}
}
