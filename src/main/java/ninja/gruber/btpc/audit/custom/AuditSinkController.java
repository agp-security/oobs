// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.audit.custom;

import ninja.gruber.btpc.audit.custom.domain.AuditSinkConfig;

import com.fasterxml.jackson.databind.JsonNode;
import ninja.gruber.btpc.audit.custom.sinks.AuditForwarder;
import ninja.gruber.btpc.config.MethodSecurityConfig;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.OffsetDateTime;
import java.util.List;

@RestController
@RequestMapping("/api/v1/audit-sinks")
public class AuditSinkController {

    private final AuditSinkService service;
    private final List<AuditForwarder> forwarders;

    public AuditSinkController(AuditSinkService service, List<AuditForwarder> forwarders) {
        this.service = service;
        this.forwarders = forwarders;
    }

    @GetMapping
    @PreAuthorize(MethodSecurityConfig.VIEWER)
    public List<Dto> list() {
        return service.list().stream().map(Dto::from).toList();
    }

    @PutMapping("/{kind}")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public Dto upsert(
            @PathVariable String kind,
            @RequestBody UpsertBody body,
            Authentication auth) {
        AuditSinkConfig.Kind k = AuditSinkConfig.Kind.fromDb(kind);
        AuditSinkConfig saved = service.upsert(k, body.enabled, body.config, body.secret,
                auth.getName());
        return Dto.from(saved);
    }

    @DeleteMapping("/{kind}")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public void delete(@PathVariable String kind) {
        service.delete(AuditSinkConfig.Kind.fromDb(kind));
    }

    @PostMapping("/{kind}/test")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public TestResult test(@PathVariable String kind) {
        AuditSinkConfig.Kind k = AuditSinkConfig.Kind.fromDb(kind);
        AuditForwarder f = forwarders.stream().filter(x -> x.kind() == k).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("no forwarder for kind " + kind));
        try {
            String msg = f.testConnection();
            service.recordTestResult(k, true, msg);
            return new TestResult(true, msg);
        } catch (Exception e) {
            service.recordTestResult(k, false, e.getMessage());
            return new TestResult(false, e.getMessage());
        }
    }

    public record Dto(
            String kind,
            boolean enabled,
            JsonNode config,
            boolean hasSecret,
            OffsetDateTime lastTestAt,
            String lastTestStatus,
            String lastTestMessage,
            OffsetDateTime updatedAt,
            String updatedBy
    ) {
        public static Dto from(AuditSinkConfig c) {
            return new Dto(c.kind().dbValue(), c.enabled(), c.configPlaintext(),
                    c.hasSecret(), c.lastTestAt(), c.lastTestStatus(), c.lastTestMessage(),
                    c.updatedAt(), c.updatedBy());
        }
    }

    public static class UpsertBody {
        public boolean enabled;
        public JsonNode config;
        public String secret;
    }

    public record TestResult(boolean ok, String message) {}
}
