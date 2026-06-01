// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

@Configuration
public class SecurityConfig {

    private static final String[] PUBLIC_PATHS = new String[] {
            "/api/v1/health",
            "/", "/index.html",
            "/ui/**",
            "/favicon.ico", "/favicon.svg"
    };
    private static final String UI5_CDN = "https://sapui5.hana.ondemand.com";

    private static final String CONNECT_SRC_CLOUD = "connect-src 'self' " + UI5_CDN;
    private static final String CONNECT_SRC_DEV   = "connect-src 'self' " + UI5_CDN + " * data: blob:";

    private static String csp(String connectSrcDirective) {
        return String.join("; ",
                "default-src 'self'",
                "script-src 'self' https://sapui5.hana.ondemand.com 'unsafe-inline' 'unsafe-eval'",
                "style-src 'self' https://sapui5.hana.ondemand.com 'unsafe-inline'",
                "font-src 'self' https://sapui5.hana.ondemand.com data:",
                "img-src 'self' https://sapui5.hana.ondemand.com data:",
                connectSrcDirective,
                "frame-ancestors 'none'",
                "base-uri 'self'",
                "form-action 'self'"
        );
    }

    private static void applyCommonHeaders(HttpSecurity http, String cspPolicy) throws Exception {
        http.headers(h -> h
                .contentSecurityPolicy(c -> c.policyDirectives(cspPolicy))
                .frameOptions(Customizer.withDefaults())
                .referrerPolicy(r -> r.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                .httpStrictTransportSecurity(Customizer.withDefaults()) //hsts -> maybe preload but dont care
                .permissionsPolicyHeader(p -> p.policy("camera=(), microphone=(), geolocation=()")));
    }

    @Configuration
    @Profile("!cloud")
    static class DevSecurity {

        private final DevAuthFilter devAuthFilter;

        DevSecurity(DevAuthFilter devAuthFilter) {
            this.devAuthFilter = devAuthFilter;
        }

        @Bean
        SecurityFilterChain devFilterChain(HttpSecurity http) throws Exception {
            http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                    .requestMatchers(PUBLIC_PATHS).permitAll()
                    .anyRequest().authenticated()
                )
                .addFilterBefore(devAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(eh -> eh
                    .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable);
            applyCommonHeaders(http, csp(CONNECT_SRC_DEV));
            return http.build();
        }
    }

    @Configuration
    @Profile("cloud")
    static class CloudSecurity {

        private final JwtAuthenticationConverter jwtConverter;

        CloudSecurity(JwtAuthenticationConverter jwtConverter) {
            this.jwtConverter = jwtConverter;
        }

        @Bean
        SecurityFilterChain cloudFilterChain(HttpSecurity http) throws Exception {
            http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                    .requestMatchers(PUBLIC_PATHS).permitAll()
                    .anyRequest().authenticated()
                )
                .oauth2ResourceServer(o -> o.jwt(j -> j.jwtAuthenticationConverter(jwtConverter)))
                .exceptionHandling(eh -> eh
                    .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable);
            applyCommonHeaders(http, csp(CONNECT_SRC_CLOUD));
            return http.build();
        }
    }
}
