// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.discovery;

import ninja.gruber.btpc.discovery.domain.DiscoveredSubaccount;

import ninja.gruber.btpc.config.MethodSecurityConfig;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/discovery/candidates")
public class DiscoveryController {

    private final DiscoveredSubaccountRepo repo;

    public DiscoveryController(DiscoveredSubaccountRepo repo) {
        this.repo = repo;
    }

    @GetMapping
    @PreAuthorize(MethodSecurityConfig.VIEWER)
    public List<DiscoveredSubaccount> list(
            @RequestParam(value = "onlyPromotable", required = false, defaultValue = "false")
                    boolean onlyPromotable,
            @RequestParam(value = "centralKeyId", required = false) UUID centralKeyId) {
        return repo.list(onlyPromotable, centralKeyId);
    }

    @GetMapping("/{id}")
    @PreAuthorize(MethodSecurityConfig.VIEWER)
    public DiscoveredSubaccount get(@PathVariable UUID id) {
        return repo.findById(id)
                .orElseThrow(() -> new NoSuchElementException("discovery candidate not found: " + id));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable UUID id) {
        repo.delete(id);
    }
}
