// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.sod;

import ninja.gruber.btpc.audit.IAuditForward;
import ninja.gruber.btpc.audit.IAuditForward.ActorSource;
import ninja.gruber.btpc.audit.IAuditForward.AuditEvent;
import ninja.gruber.btpc.audit.IAuditForward.Outcome;
import ninja.gruber.btpc.domain.ConflictSet;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;

@Service
public class ConflictSetService {

    private static final Set<String> SEVERITY = Set.of("low", "medium", "high", "critical");
    private static final Set<String> SCOPE   = Set.of("subaccount", "space", "org", "global");
    static final Set<String> KIND          = Set.of("sod", "critical", "threshold", "external_email");

    private final ConflictSetRepo repo;
    private final IAuditForward audit;

    public ConflictSetService(ConflictSetRepo repo, IAuditForward audit) {
        this.repo = repo;
        this.audit = audit;
    }

    @Transactional
    public ConflictSet create(Payload p, String actor, ActorSource source) {
        validate(p);
        UUID id;
        try {
            id = repo.insert(p.name.trim(), nullSafe(p.description),
                    p.severity, defaultKind(p.kind), p.roleCollections, p.thresholdCount,
                    p.scopeLevel == null ? "subaccount" : p.scopeLevel,
                    actor);
        } catch (DuplicateKeyException e) {
            throw new IllegalStateException("A conflict set named '" + p.name + "' already exists");
        }
        audit.record(new AuditEvent(UUID.randomUUID(), null, IAuditForward.SystemType.INTERNAL, "", null,
                "sod_scan", actor, source, Outcome.OK, null,
                Map.of("op", "create_conflict_set", "id", id.toString(),
                        "name", p.name, "severity", p.severity, "kind", defaultKind(p.kind),
                        "roleCollections", p.roleCollections == null ? List.of() : p.roleCollections,
                        "thresholdCount", String.valueOf(p.thresholdCount))));
        return repo.findById(id).orElseThrow();
    }

    @Transactional
    public ConflictSet update(UUID id, Payload p, String actor, ActorSource source) {
        validate(p);
        ConflictSet existing = get(id);
        repo.update(id, p.name.trim(), nullSafe(p.description), p.severity, defaultKind(p.kind),
                p.roleCollections, p.thresholdCount,
                p.scopeLevel == null ? existing.scopeLevel() : p.scopeLevel);
        audit.record(new AuditEvent(UUID.randomUUID(), null, IAuditForward.SystemType.INTERNAL, "", null,
                "sod_scan", actor, source, Outcome.OK, null,
                Map.of("op", "update_conflict_set", "id", id.toString(),
                        "name", p.name)));
        return repo.findById(id).orElseThrow();
    }

    @Transactional
    public ConflictSet setEnabled(UUID id, boolean enabled, String actor, ActorSource source) {
        ConflictSet existing = get(id);
        if (existing.enabled() == enabled) return existing;
        repo.setEnabled(id, enabled);
        audit.record(new AuditEvent(UUID.randomUUID(), null, IAuditForward.SystemType.INTERNAL, "", null,
                "sod_scan", actor, source, Outcome.OK, null,
                Map.of("op", enabled ? "enable_conflict_set" : "disable_conflict_set",
                        "id", id.toString(), "name", existing.name())));
        return repo.findById(id).orElseThrow();
    }

    @Transactional
    public void delete(UUID id, String actor, ActorSource source) {
        ConflictSet existing = get(id);
        repo.delete(id);
        audit.record(new AuditEvent(UUID.randomUUID(), null, IAuditForward.SystemType.INTERNAL, "", null,
                "sod_scan", actor, source, Outcome.OK, null,
                Map.of("op", "delete_conflict_set", "id", id.toString(),
                        "name", existing.name())));
    }

    public ConflictSet get(UUID id) {
        return repo.findById(id)
                .orElseThrow(() -> new NoSuchElementException("conflict set not found: " + id));
    }

    public List<ConflictSet> list() { return repo.list(); }

    public List<ConflictSet> listEnabled() { return repo.listEnabled(); }

    private static void validate(Payload p) {
        if (p == null) throw new IllegalArgumentException("body is required");
        if (p.name == null || p.name.isBlank()) throw new IllegalArgumentException("name is required");
        if (p.severity == null || !SEVERITY.contains(p.severity))
            throw new IllegalArgumentException("severity must be one of " + SEVERITY);
        if (p.scopeLevel != null && !SCOPE.contains(p.scopeLevel))
            throw new IllegalArgumentException("scopeLevel must be one of " + SCOPE);
        String kind = defaultKind(p.kind);
        if (!KIND.contains(kind))
            throw new IllegalArgumentException("kind must be one of " + KIND);

        // Per-kind shape rules:
        switch (kind) {
            case "sod" -> {
                if (p.roleCollections == null || p.roleCollections.size() < 2)
                    throw new IllegalArgumentException("sod rules require at least two role collections");
            }
            case "critical" -> {
                if (p.roleCollections == null || p.roleCollections.isEmpty())
                    throw new IllegalArgumentException("critical rules require at least one role collection");
            }
            case "threshold" -> {
                if (p.thresholdCount == null || p.thresholdCount < 1)
                    throw new IllegalArgumentException("threshold rules require thresholdCount >= 1");
            }
            case "external_email" -> {
            }
        }
        if (p.roleCollections != null) {
            for (String rc : p.roleCollections) {
                if (rc == null || rc.isBlank())
                    throw new IllegalArgumentException("role collection names cannot be blank");
            }
        }
    }

    private static String defaultKind(String k) { return k == null || k.isBlank() ? "sod" : k; }

    private static String nullSafe(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    public static class Payload {
        public String name;
        public String description;
        public String severity;
        public String kind;                  // sod | critical | threshold (defaults to sod)
        public List<String> roleCollections;
        public Integer thresholdCount;
        public String scopeLevel;
    }
}
