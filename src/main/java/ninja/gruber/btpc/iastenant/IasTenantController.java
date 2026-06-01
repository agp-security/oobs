// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.iastenant;

import ninja.gruber.btpc.iastenant.domain.IasTenant;

import ninja.gruber.btpc.config.MethodSecurityConfig;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/ias-tenants")
public class IasTenantController {

    private final IasTenantService service;

    public IasTenantController(IasTenantService service) { this.service = service; }

    @GetMapping
    @PreAuthorize(MethodSecurityConfig.VIEWER)
    public List<Dto> list() {
        return service.list().stream().map(this::toDto).toList();
    }

    @GetMapping("/{id}")
    @PreAuthorize(MethodSecurityConfig.VIEWER)
    public Dto get(@PathVariable UUID id) {
        return toDto(service.get(id));
    }

    @PostMapping
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public ResponseEntity<Dto> create(@RequestBody IasTenantService.CreatePayload body,
                                      Authentication auth) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(toDto(service.create(body, actorOf(auth))));
    }

    @PatchMapping("/{id}/meta")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public Dto updateMeta(@PathVariable UUID id, @RequestBody MetaBody body,
                          Authentication auth) {
        return toDto(service.updateMeta(id, body.displayName, actorOf(auth)));
    }

    @PutMapping("/{id}/credentials")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public Dto updateCreds(@PathVariable UUID id,
                           @RequestBody IasTenantService.CreatePayload body,
                           Authentication auth) {
        return toDto(service.updateCreds(id, body, actorOf(auth)));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable UUID id, Authentication auth) {
        service.delete(id, actorOf(auth));
    }

    private Dto toDto(IasTenant t) {
        return new Dto(t.id(), t.displayName(), t.iasHost(),
                t.createdAt(), t.createdBy(), t.updatedAt(), t.updatedBy());
    }

    public record Dto(
            UUID id, String displayName, String iasHost,
            OffsetDateTime createdAt, String createdBy,
            OffsetDateTime updatedAt, String updatedBy
    ) {}

    public static class MetaBody { public String displayName; }

    private static String actorOf(Authentication auth) {
        return auth != null && auth.getName() != null ? auth.getName() : "unknown";
    }
}
