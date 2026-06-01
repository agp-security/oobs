// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Component
@Profile("!cloud")
public class DevAuthFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(DevAuthFilter.class);

    private final boolean enabled;

    public DevAuthFilter(@Value("${btpc.dev-auth.enabled:false}") boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        if (enabled) { //ignore in cloud profile only for local deployment without xsuaa vcap_service env stuff.
            String user = req.getHeader("X-Test-User");
            String scopes = req.getHeader("X-Test-Scopes");
            if (user != null && !user.isBlank()) {
                List<SimpleGrantedAuthority> authorities = parseScopes(scopes);
                UsernamePasswordAuthenticationToken auth =
                        new UsernamePasswordAuthenticationToken(user, "testing no creds as local profile..", authorities);
                SecurityContextHolder.getContext().setAuthentication(auth);
                log.debug("local-dev-auth: {} {} -> user={} scopes={}",
                        req.getMethod(), req.getRequestURI(), user, scopes);
            }
        }
        chain.doFilter(req, res);
    }

    private static List<SimpleGrantedAuthority> parseScopes(String header) {
        if (header == null || header.isBlank()) {
            return List.of();
        }
        return Arrays.stream(header.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(s -> "SCOPE_" + s)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}
