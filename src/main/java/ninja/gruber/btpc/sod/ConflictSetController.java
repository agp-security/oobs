// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.sod;

import ninja.gruber.btpc.audit.IAuditForward.ActorSource;
import ninja.gruber.btpc.config.MethodSecurityConfig;
import ninja.gruber.btpc.domain.ConflictSet;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/sod/conflict-sets")
public class ConflictSetController {

    private final ConflictSetService service;

    public ConflictSetController(ConflictSetService service) {
        this.service = service;
    }

    @GetMapping
    @PreAuthorize(MethodSecurityConfig.VIEWER)
    public List<ConflictSet> list() { return service.list(); }

    @GetMapping("/{id}")
    @PreAuthorize(MethodSecurityConfig.VIEWER)
    public ConflictSet get(@PathVariable UUID id) { return service.get(id); }

    @PostMapping
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public ResponseEntity<ConflictSet> create(
            @RequestBody ConflictSetService.Payload body,
            Authentication auth,
            @RequestHeader(value = "X-Caller-Source", required = false) String src) {
        return ResponseEntity.status(HttpStatus.CREATED).body(
                service.create(body, actor(auth), parseSource(src)));
    }

    @PutMapping("/{id}")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public ConflictSet update(
            @PathVariable UUID id,
            @RequestBody ConflictSetService.Payload body,
            Authentication auth,
            @RequestHeader(value = "X-Caller-Source", required = false) String src) {
        return service.update(id, body, actor(auth), parseSource(src));
    }

    @PatchMapping("/{id}/enabled")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public ConflictSet setEnabled(
            @PathVariable UUID id,
            @RequestBody EnabledPatch body,
            Authentication auth,
            @RequestHeader(value = "X-Caller-Source", required = false) String src) {
        return service.setEnabled(id, body.enabled, actor(auth), parseSource(src));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(
            @PathVariable UUID id,
            Authentication auth,
            @RequestHeader(value = "X-Caller-Source", required = false) String src) {
        service.delete(id, actor(auth), parseSource(src));
    }

    public static class EnabledPatch { public boolean enabled; }

    private static String actor(Authentication a) { return a != null && a.getName() != null ? a.getName() : "unknown"; }
    private static ActorSource parseSource(String s) {
        if (s == null || s.isBlank()) return ActorSource.UI;
        return switch (s.toLowerCase()) {
            case "soar", "soar-api" -> ActorSource.SOAR_API;
            case "system" -> ActorSource.SYSTEM;
            default -> ActorSource.UI;
        };
    }
}
