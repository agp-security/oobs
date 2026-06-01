// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.discovery;

import ninja.gruber.btpc.discovery.domain.CentralViewerKey;

import ninja.gruber.btpc.audit.IAuditForward.ActorSource;
import ninja.gruber.btpc.config.MethodSecurityConfig;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/discovery/keys")
public class CentralKeyController {

    private final CentralKeyService keys;
    private final DiscoveryService discovery;

    public CentralKeyController(CentralKeyService keys, DiscoveryService discovery) {
        this.keys = keys;
        this.discovery = discovery;
    }

    @GetMapping
    @PreAuthorize(MethodSecurityConfig.VIEWER)
    public List<CentralViewerKey> list() {
        return keys.list();
    }

    @PostMapping
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public ResponseEntity<CentralViewerKey> save(
            @RequestBody CentralKeyService.SaveRequest req,
            Authentication auth) {
        return ResponseEntity.status(HttpStatus.CREATED).body(keys.save(req, actorOf(auth)));
    }

    @GetMapping("/{id}")
    @PreAuthorize(MethodSecurityConfig.VIEWER)
    public CentralViewerKey get(@PathVariable UUID id) {
        return keys.get(id);
    }

    @PatchMapping("/{id}")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public CentralViewerKey patch(@PathVariable UUID id,
                                  @RequestBody CentralKeyService.UpdateRequest req) {
        return keys.updateSettings(id, req);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable UUID id) {
        keys.delete(id);
    }

    @PostMapping("/{id}/sync")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public DiscoveryService.SyncResult triggerSync(
            @PathVariable UUID id,
            Authentication auth,
            @RequestHeader(value = "X-Caller-Source", required = false) String sourceHeader) {
        return discovery.syncOne(id, actorOf(auth), parseSource(sourceHeader));
    }

    private static String actorOf(Authentication auth) {
        return auth != null && auth.getName() != null ? auth.getName() : "unknown";
    }

    private static ActorSource parseSource(String header) {
        if (header == null || header.isBlank()) return ActorSource.UI;
        return switch (header.toLowerCase()) {
            case "soar", "soar-api" -> ActorSource.SOAR_API;
            case "system" -> ActorSource.SYSTEM;
            default -> ActorSource.UI;
        };
    }
}
