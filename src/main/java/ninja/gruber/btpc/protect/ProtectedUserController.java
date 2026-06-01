// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.protect;

import ninja.gruber.btpc.protect.domain.ProtectedUserDto;

import ninja.gruber.btpc.audit.IAuditForward.ActorSource;
import ninja.gruber.btpc.config.MethodSecurityConfig;
import ninja.gruber.btpc.domain.ProtectedUserOrigin;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/protected-users")
public class ProtectedUserController {

    private final ProtectedUserService service;

    public ProtectedUserController(ProtectedUserService service) {
        this.service = service;
    }

    @GetMapping
    @PreAuthorize(MethodSecurityConfig.VIEWER)
    public List<ProtectedUserDto> list() {
        return service.list().stream().map(ProtectedUserDto::from).toList();
    }

    @GetMapping("/{id}")
    @PreAuthorize(MethodSecurityConfig.VIEWER)
    public ProtectedUserDto get(@PathVariable UUID id) {
        return ProtectedUserDto.from(service.get(id));
    }

    @PostMapping
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public ResponseEntity<ProtectedUserDto> add(
            @RequestBody AddBody body,
            Authentication auth,
            @RequestHeader(value = "X-Caller-Source", required = false) String src) {
        ProtectedUserService.AddRequest r = new ProtectedUserService.AddRequest();
        r.subaccountId = body.subaccountId;
        r.iasTenantId = body.iasTenantId;
        r.userEmail = body.userEmail;
        r.reason = body.reason;
        r.origin = body.origin == null ? null : ProtectedUserOrigin.fromDb(body.origin);
        r.expiresAt = body.expiresAt;
        var added = service.add(r, actorOf(auth), parseSource(src));
        return ResponseEntity.status(HttpStatus.CREATED).body(ProtectedUserDto.from(added));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(
            @PathVariable UUID id,
            Authentication auth,
            @RequestHeader(value = "X-Caller-Source", required = false) String src) {
        service.delete(id, actorOf(auth), parseSource(src));
    }

    @GetMapping("/check")
    @PreAuthorize(MethodSecurityConfig.RESPONDER)
    public CheckBody check(
            @RequestParam String email,
            @RequestParam(required = false) UUID subaccountId) {
        var r = service.check(email, subaccountId);
        return new CheckBody(r.isProtected(),
                r.matches().stream().map(ProtectedUserDto::from).toList());
    }

    public record CheckBody(boolean isProtected, List<ProtectedUserDto> matches) {}

    public static class AddBody {
        public UUID subaccountId;
        public UUID iasTenantId;
        public String userEmail;
        public String reason;
        public String origin;
        public OffsetDateTime expiresAt;
    }

    private static String actorOf(Authentication auth) {
        return auth != null && auth.getName() != null ? auth.getName() : "unknown";
    }

    private static ActorSource parseSource(String src) {
        if (src == null || src.isBlank()) return ActorSource.UI;
        return switch (src.toLowerCase()) {
            case "soar", "soar-api" -> ActorSource.SOAR_API;
            case "system" -> ActorSource.SYSTEM;
            default -> ActorSource.UI;
        };
    }
}
