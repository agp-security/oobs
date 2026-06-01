// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.containment;

import ninja.gruber.btpc.audit.IAuditForward;
import ninja.gruber.btpc.audit.IAuditForward.ActorSource;
import ninja.gruber.btpc.audit.IAuditForward.AuditEvent;
import ninja.gruber.btpc.audit.IAuditForward.Outcome;
import ninja.gruber.btpc.cf.CfApiClient;
import ninja.gruber.btpc.containment.domain.ContainmentDtos.ContainRequest;
import ninja.gruber.btpc.domain.CredentialKind;
import ninja.gruber.btpc.domain.Subaccount;
import ninja.gruber.btpc.enroll.SubaccountService;
import ninja.gruber.btpc.iastenant.IasTenantService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;

/**
 * Helper class for the locking / unlocking of users
 */
@Component
class ContainmentSupport {

    private static final Logger log = LoggerFactory.getLogger(ContainmentSupport.class);

    private final SubaccountService subaccounts;
    private final IasTenantService iasTenants;
    private final CfApiClient cf;
    private final IAuditForward audit;

    ContainmentSupport(SubaccountService subaccounts,
                       IasTenantService iasTenants,
                       CfApiClient cf,
                       IAuditForward audit) {
        this.subaccounts = subaccounts;
        this.iasTenants = iasTenants;
        this.cf = cf;
        this.audit = audit;
    }

    void emitLog(UUID corr, String systemId, String email, String userId, String action,
                String actor, ActorSource source, Outcome outcome, String err,
                Map<String, Object> details, IAuditForward.SystemType type) {
        audit.record(new AuditEvent(corr, systemId, type,
                email, userId, action, actor, source, outcome, err, details));
    }

    void emitComment(UUID corr, String email, String actor, ActorSource source,
                     String scope, String comment) {
        if (comment == null || comment.isBlank()) return;
        emitLog(corr, null, email, null, "comment", actor, source, Outcome.OK, null,
                Map.of("comment", comment.trim(), "scope", scope), IAuditForward.SystemType.INTERNAL);
    }

    List<Subaccount> resolveSubaccountList(List<UUID> ids) {
        List<UUID> resolved = (ids != null && !ids.isEmpty())
                ? ids
                : subaccounts.list().stream().map(Subaccount::id).toList();
        return resolved.stream().map(subaccounts::get).toList();
    }

    List<UUID> resolveTenantList(List<UUID> ids) {
        return (ids != null && !ids.isEmpty())
                ? ids
                : iasTenants.list().stream()
                        .map(ninja.gruber.btpc.iastenant.domain.IasTenant::id)
                        .toList();
    }

    String tryLoadCredential(UUID subaccountId, CredentialKind kind) {
        try {
            return new String(subaccounts.decryptCredential(subaccountId, kind), StandardCharsets.UTF_8);
        } catch (NoSuchElementException e) {
            return null;
        }
    }

    String requireCredential(UUID subaccountId, CredentialKind kind, String msg) {
        String json = tryLoadCredential(subaccountId, kind);
        if (json == null) throw new IllegalStateException(msg);
        return json;
    }

    List<CfApiClient.CfUser> resolveCfUsers(String cfJson, String email, ContainRequest req) {
        OriginFilter of = req == null ? OriginFilter.all() : OriginFilter.of(req);
        String originsFilter = of.allOrigins() ? null : String.join(",", of.origins());

        List<CfApiClient.CfUser> matches = cf.findUserByUsername(cfJson, email, originsFilter);
        int directCount = matches.size();
        if (matches.isEmpty()) {
            log.debug("CF: direct /v3/users lookup empty for {} (origins={}), falling back to org/space walk",
                    email, originsFilter);
            CfApiClient.OrgWalkDiagnostic walk = cf.walkOrgs(cfJson, email);
            List<CfApiClient.CfUser> walkMatches = walk.matches();
            if (!of.allOrigins()) {
                walkMatches = walkMatches.stream()
                        .filter(u -> of.origins().contains(u.origin()))
                        .toList();
            }
            if (walkMatches.isEmpty()) {
                String preview = walk.usernamesSample().isEmpty()
                        ? "none"
                        : String.join(", ", walk.usernamesSample())
                                + (walk.uniqueUsersSeen() > walk.usernamesSample().size()
                                        ? " (+" + (walk.uniqueUsersSeen() - walk.usernamesSample().size()) + " more)"
                                        : "");
                String hint = ContainmentMessages.cfUserNotFoundHint(
                        walk.orgsScanned(), walk.spacesScanned(), walk.uniqueUsersSeen());
                throw new CfUserNotFoundException(
                        "CF user not found for " + email
                                + " (direct /v3/users hits=" + directCount
                                + (of.allOrigins() ? "" : ", origins=" + of.origins())
                                + "; org walk: " + walk.orgsScanned() + " org(s), "
                                + walk.spacesScanned() + " space(s), "
                                + walk.uniqueUsersSeen() + " unique user(s) visible)"
                                + " - usernames sample: [" + preview + "]"
                                + hint);
            }
            matches = walkMatches;
        }
        Map<String, CfApiClient.CfUser> dedup = new LinkedHashMap<>();
        for (CfApiClient.CfUser u : matches) {
            if (u.guid() != null) dedup.putIfAbsent(u.guid(), u);
        }
        return new ArrayList<>(dedup.values());
    }

    List<CfApiClient.CfUser> resolveCfUsersInOrg(String cfJson, String email, ContainRequest req,
                                                 String orgGuid, List<CfApiClient.Space> spaces) {
        OriginFilter of = req == null ? OriginFilter.all() : OriginFilter.of(req);
        List<CfApiClient.CfUser> candidates = new ArrayList<>(cf.listUsersInOrg(cfJson, orgGuid));
        for (CfApiClient.Space sp : spaces) {
            candidates.addAll(cf.listUsersInSpace(cfJson, sp.guid()));
        }
        Map<String, CfApiClient.CfUser> dedup = new LinkedHashMap<>();
        for (CfApiClient.CfUser u : candidates) {
            if (u.guid() == null || u.username() == null) continue;
            if (!u.username().equalsIgnoreCase(email)) continue;
            if (!of.allOrigins() && !of.origins().contains(u.origin())) continue;
            dedup.putIfAbsent(u.guid(), u);
        }
        return new ArrayList<>(dedup.values());
    }
}
