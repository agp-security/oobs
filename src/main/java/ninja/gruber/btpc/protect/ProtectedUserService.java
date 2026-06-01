// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.protect;

import ninja.gruber.btpc.audit.IAuditForward;
import ninja.gruber.btpc.audit.IAuditForward.ActorSource;
import ninja.gruber.btpc.audit.IAuditForward.AuditEvent;
import ninja.gruber.btpc.audit.IAuditForward.Outcome;
import ninja.gruber.btpc.domain.ProtectedUser;
import ninja.gruber.btpc.domain.ProtectedUserOrigin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;

@Service
public class ProtectedUserService {

    private static final Logger log = LoggerFactory.getLogger(ProtectedUserService.class);

    private final ProtectedUserRepo repo;
    private final IAuditForward audit;

    public ProtectedUserService(ProtectedUserRepo repo, IAuditForward audit) {
        this.repo = repo;
        this.audit = audit;
    }

    @Transactional
    public ProtectedUser add(AddRequest req, String actor, ActorSource source) {
        if (req.userEmail == null || req.userEmail.isBlank()) {
            throw new IllegalArgumentException("userEmail is required");
        }
        if (req.reason == null || req.reason.isBlank()) {
            throw new IllegalArgumentException("reason is required");
        }
        if (req.subaccountId != null && req.iasTenantId != null) {
            throw new IllegalArgumentException(
                    "scope is exclusive - pick global, subaccount, OR IAS tenant (not both)");
        }
        ProtectedUserOrigin origin = req.origin == null ? ProtectedUserOrigin.MANUAL : req.origin;
        int expired = repo.deleteExpiredAtScope(req.subaccountId, req.iasTenantId, req.userEmail.trim());
        if (expired > 0) {
            log.info("protected_users: cleared {} expired row(s) for {} at scope (sa={}, ias={}) before re-add",
                    expired, req.userEmail, req.subaccountId, req.iasTenantId);
        }
        UUID id;
        try {
            id = repo.insert(req.subaccountId, req.iasTenantId,
                    req.userEmail.trim(),
                    req.reason.trim(),
                    origin, actor, req.expiresAt);
        } catch (DuplicateKeyException e) {
            String scopeDesc;
            if (req.subaccountId != null) scopeDesc = "subaccount " + req.subaccountId;
            else if (req.iasTenantId != null) scopeDesc = "IAS tenant " + req.iasTenantId;
            else scopeDesc = "(global)";
            throw new IllegalStateException(
                    "An active protection already exists for " + req.userEmail + " in " + scopeDesc);
        }
        audit.record(new AuditEvent(
                UUID.randomUUID(),
                auditSystemId(req.subaccountId, req.iasTenantId),
                auditSystemType(req.subaccountId, req.iasTenantId),
                req.userEmail,
                null,
                "protect_add",
                actor, source, Outcome.OK, null,
                Map.of("reason", req.reason, "origin", origin.dbValue(),
                        "iasTenantId", String.valueOf(req.iasTenantId),
                        "expiresAt", String.valueOf(req.expiresAt))));
        return repo.findById(id).orElseThrow();
    }

    public List<ProtectedUser> list() {
        return repo.list();
    }

    public ProtectedUser get(UUID id) {
        return repo.findById(id)
                .orElseThrow(() -> new NoSuchElementException("protected user not found: " + id));
    }

    @Transactional
    public void delete(UUID id, String actor, ActorSource source) {
        ProtectedUser p = get(id);
        audit.record(new AuditEvent(
                UUID.randomUUID(),
                auditSystemId(p.subaccountId(), p.iasTenantId()),
                auditSystemType(p.subaccountId(), p.iasTenantId()),
                p.userEmail(),
                null,
                "protect_disable",
                actor, source, Outcome.OK, null,
                Map.of("protectionId", id.toString(),
                        "reason", p.reason(),
                        "deleted", true,
                        "scopeIasTenantId", String.valueOf(p.iasTenantId()))));
        int rows = repo.delete(id);
        if (rows == 0) {
            throw new NoSuchElementException("protection " + id + " not found");
        }
    }

    public CheckResult check(String email, UUID subaccountId, UUID iasTenantId) {
        List<ProtectedUser> matches = repo.findActiveMatches(email, subaccountId, iasTenantId);
        return new CheckResult(!matches.isEmpty(), matches);
    }

    public CheckResult check(String email, UUID subaccountId) {
        return check(email, subaccountId, null);
    }


    private static String auditSystemId(UUID subaccountId, UUID iasTenantId) {
        if (subaccountId != null) return subaccountId.toString();
        if (iasTenantId != null) return iasTenantId.toString();
        return null;
    }

    private static IAuditForward.SystemType auditSystemType(UUID subaccountId, UUID iasTenantId) {
        if (subaccountId != null) return IAuditForward.SystemType.SUBACCOUNT;
        if (iasTenantId != null) return IAuditForward.SystemType.IAS;
        return IAuditForward.SystemType.INTERNAL;
    }

    public record CheckResult(boolean isProtected, List<ProtectedUser> matches) {}

    public static class AddRequest {
        public UUID subaccountId;
        public UUID iasTenantId;
        public String userEmail;
        public String reason;
        public ProtectedUserOrigin origin;   // null defaults to MANUAL
        public OffsetDateTime expiresAt;
    }
}
