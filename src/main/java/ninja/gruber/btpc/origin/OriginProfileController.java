// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.origin;

import ninja.gruber.btpc.origin.domain.OriginProfile;

import ninja.gruber.btpc.config.MethodSecurityConfig;
import ninja.gruber.btpc.iam.IdentityProviderService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/origin-profiles")
public class OriginProfileController {

    private static final Logger log = LoggerFactory.getLogger(OriginProfileController.class);

    private final OriginProfileRepo repo;
    private final IdentityProviderService identityProviders;

    public OriginProfileController(OriginProfileRepo repo, IdentityProviderService identityProviders) {
        this.repo = repo;
        this.identityProviders = identityProviders;
    }

    @GetMapping
    @PreAuthorize(MethodSecurityConfig.VIEWER)
    public List<OriginProfile> list() { return repo.list(); }

    @PostMapping
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public OriginProfile create(@RequestBody Body body, Authentication auth) {
        validate(body);
        List<String> keys = sanitize(body.originKeys);
        checkOrigins(keys, body.subaccountIds);
        try {
            return repo.insert(body.name.trim(), trim(body.description), keys,
                    auth != null ? auth.getName() : "unknown");
        } catch (DuplicateKeyException e) {
            throw new IllegalArgumentException(
                    "an origin profile named '" + body.name + "' already exists");
        }
    }

    @PutMapping("/{id}")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public OriginProfile update(@PathVariable UUID id, @RequestBody Body body,
                                Authentication auth) {
        validate(body);
        List<String> keys = sanitize(body.originKeys);
        checkOrigins(keys, body.subaccountIds);
        try {
            return repo.update(id, body.name.trim(), trim(body.description), keys,
                    auth != null ? auth.getName() : "unknown");
        } catch (DuplicateKeyException e) {
            throw new IllegalArgumentException(
                    "an origin profile named '" + body.name + "' already exists");
        } catch (NoSuchElementException e) {
            throw new NoSuchElementException("origin profile " + id + " not found");
        }
    }

    private void checkOrigins(List<String> keys, List<UUID> subaccountIds) {
        IdentityProviderService.OriginValidation v =
                identityProviders.validateOrigins(keys, subaccountIds);
        if (v.unknownOrigins().isEmpty()) return;
        if (!v.conclusive()) {
            log.warn("origin-profile save: {} origin key(s) not found in discovery, but discovery "
                            + "was inconclusive ({} subaccount error(s)) - saving anyway: {}",
                    v.unknownOrigins().size(), v.errors().size(), v.unknownOrigins());
            return;
        }
        throw new IllegalArgumentException(
                "unknown origin key(s) - not found as an identity provider in any enrolled "
                        + "subaccount (reserved built-ins sap.default/sap.custom/ldap/uaa are always "
                        + "allowed): " + String.join(", ", v.unknownOrigins()));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public void delete(@PathVariable UUID id) { repo.delete(id); }

    private static void validate(Body b) {
        if (b == null) throw new IllegalArgumentException("body is required");
        if (b.name == null || b.name.trim().isEmpty())
            throw new IllegalArgumentException("name is required");
        if (b.originKeys == null || b.originKeys.isEmpty())
            throw new IllegalArgumentException("originKeys must be a non-empty list");
    }

    private static String trim(String s) { return s == null ? null : s.trim(); }

    private static List<String> sanitize(List<String> in) {
        List<String> out = new ArrayList<>();
        for (String s : in) {
            if (s == null) continue;
            String t = s.trim();
            if (!t.isEmpty() && !out.contains(t)) out.add(t);
        }
        return out;
    }

    public static class Body {
        public String name;
        public String description;
        public List<String> originKeys;
        public List<UUID> subaccountIds;
    }
}
