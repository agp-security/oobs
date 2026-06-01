// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.sod;

import ninja.gruber.btpc.appconfig.AppConfigService;
import ninja.gruber.btpc.audit.IAuditForward;
import ninja.gruber.btpc.audit.IAuditForward.ActorSource;
import ninja.gruber.btpc.audit.IAuditForward.AuditEvent;
import ninja.gruber.btpc.audit.IAuditForward.Outcome;
import ninja.gruber.btpc.cf.CfApiClient;
import ninja.gruber.btpc.domain.ConflictSet;
import ninja.gruber.btpc.domain.CredentialKind;
import ninja.gruber.btpc.domain.Subaccount;
import ninja.gruber.btpc.enroll.SubaccountService;
import ninja.gruber.btpc.iam.IasClient;
import ninja.gruber.btpc.iam.XsuaaScimClient;
import ninja.gruber.btpc.iastenant.IasTenantService;
import ninja.gruber.btpc.iastenant.domain.IasTenant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Service
public class SodEngine {

    private static final Logger log = LoggerFactory.getLogger(SodEngine.class);

    private final ConflictSetService conflictSets;
    private final SubaccountService subaccounts;
    private final XsuaaScimClient xsuaa;
    private final CfApiClient cf;
    private final IAuditForward audit;
    private final AppConfigService appConfig;
    private final IasTenantService iasTenants;
    private final IasClient ias;

    public SodEngine(ConflictSetService conflictSets, SubaccountService subaccounts,
                     XsuaaScimClient xsuaa, CfApiClient cf, IAuditForward audit,
                     AppConfigService appConfig,
                     IasTenantService iasTenants, IasClient ias) {
        this.conflictSets = conflictSets;
        this.subaccounts = subaccounts;
        this.xsuaa = xsuaa;
        this.cf = cf;
        this.audit = audit;
        this.appConfig = appConfig;
        this.iasTenants = iasTenants;
        this.ias = ias;
    }

    static Set<String> parseDomainsCsv(String csv) {
        return AppConfigService.parseDomainsCsv(csv);
    }

    public ScanResult scan(UUID subaccountId, String actor, ActorSource source) {
        Subaccount sa = subaccounts.get(subaccountId);
        UUID correlationId = UUID.randomUUID();

        List<ConflictSet> allEnabled = conflictSets.listEnabled();
        if (allEnabled.isEmpty()) {
            audit.record(new AuditEvent(correlationId, subaccountId.toString(), IAuditForward.SystemType.SUBACCOUNT, "", null,
                    "sod_scan", actor, source, Outcome.SKIPPED, "no enabled conflict sets",
                    Map.of("conflictSetCount", 0)));
            return new ScanResult(correlationId, sa.cisDisplayName(), 0, 0, List.of(),
                    "No enabled conflict sets to evaluate.");
        }

        List<ConflictSet> saRules    = filterScope(allEnabled, "subaccount", "global");
        List<ConflictSet> orgRules   = filterScope(allEnabled, "org");
        List<ConflictSet> spaceRules = filterScope(allEnabled, "space");

        List<Finding> findings = new ArrayList<>();
        int totalUsersScanned = 0;
        Set<String> internalDomains = appConfig.getInternalDomains();

        if (!saRules.isEmpty()) {
            totalUsersScanned += scanSubaccount(sa, correlationId, saRules, findings,
                    internalDomains, actor, source);
        }


        if (!orgRules.isEmpty()) {
            totalUsersScanned += scanOrgs(sa, correlationId, orgRules, findings,
                    internalDomains, actor, source);
        }


        if (!spaceRules.isEmpty()) {
            totalUsersScanned += scanSpaces(sa, correlationId, spaceRules, findings,
                    internalDomains, actor, source);
        }

        audit.record(new AuditEvent(correlationId, subaccountId.toString(), IAuditForward.SystemType.SUBACCOUNT, "", null,
                "sod_scan", actor, source,
                findings.isEmpty() ? Outcome.OK : Outcome.PARTIAL, null,
                Map.of("conflictSetCount", allEnabled.size(),
                        "usersScanned", totalUsersScanned,
                        "findingCount", findings.size())));

        return new ScanResult(correlationId, sa.cisDisplayName(),
                totalUsersScanned, allEnabled.size(), findings, null);
    }

    private int scanSubaccount(Subaccount sa, UUID correlationId, List<ConflictSet> rules,
                               List<Finding> findings, Set<String> internalDomains,
                               String actor, ActorSource source) {
        String xsuaaJson;
        try {
            xsuaaJson = new String(subaccounts.decryptCredential(sa.id(),
                    CredentialKind.XSUAA_APIACCESS), StandardCharsets.UTF_8);
        } catch (NoSuchElementException e) {
            audit.record(new AuditEvent(correlationId, sa.id().toString(), IAuditForward.SystemType.SUBACCOUNT, "", null,
                    "sod_scan", actor, source, Outcome.FAILED,
                    "no XSUAA api-access credential", Map.of()));
            throw new IllegalStateException(
                    "Cannot run subaccount-scoped rules: subaccount has no XSUAA api-access credential. " +
                            "Attach one via the Edit dialog first.");
        }
        List<XsuaaScimClient.ShadowUser> users = xsuaa.listShadowUsers(xsuaaJson);
        Map<String, Set<String>> rcByUserId = new HashMap<>();
        try {
            for (XsuaaScimClient.Group g : xsuaa.listGroups(xsuaaJson)) {
                if (g.displayName() == null) continue;
                for (XsuaaScimClient.Member m : g.members()) {
                    if (m.userId() == null) continue;
                    rcByUserId.computeIfAbsent(m.userId(), k -> new HashSet<>())
                            .add(g.displayName());
                }
            }
        } catch (Exception e) {
            log.warn("SoD: failed to list groups for subaccount {}: {}",
                    sa.id(), e.getMessage());
        }

        Map<String, Set<String>> iasDerivedRcs = enrichWithIasGroupMappings(sa, xsuaaJson, users);
        for (Map.Entry<String, Set<String>> e : iasDerivedRcs.entrySet()) {
            rcByUserId.computeIfAbsent(e.getKey(), k -> new HashSet<>()).addAll(e.getValue());
        }

        Map<String, UserRoles> userRoles = new LinkedHashMap<>();
        for (XsuaaScimClient.ShadowUser u : users) {
            String origin = u.origin() != null ? u.origin() : "ias";
            String userName = u.userName();
            if (userName == null) continue;
            Set<String> rcs = rcByUserId.getOrDefault(u.id(), Set.of());
            userRoles.put(userName, new UserRoles(u.id(), origin, new HashSet<>(rcs)));
        }
        for (Map.Entry<String, UserRoles> e : userRoles.entrySet()) {
            String userName = e.getKey();
            UserRoles ur = e.getValue();
            for (ConflictSet cs : rules) {
                List<String> matched = evaluate(cs, userName, ur.roleCollections, internalDomains);
                if (matched == null) continue;
                recordFinding(findings, cs, userName, ur.id, ur.origin, matched,
                        "subaccount", correlationId, sa.id(), actor, source);
            }
        }
        return userRoles.size();
    }

    private Map<String, Set<String>> enrichWithIasGroupMappings(
            Subaccount sa, String xsuaaJson, List<XsuaaScimClient.ShadowUser> shadowUsers) {

        Set<String> originsSeen = new HashSet<>();
        for (XsuaaScimClient.ShadowUser u : shadowUsers) {
            if (u.origin() != null) originsSeen.add(u.origin());
        }
        if (originsSeen.isEmpty()) return Map.of();

        Map<String, Map<String, Set<String>>> mappingByOrigin = new HashMap<>();
        for (String origin : originsSeen) {
            try {
                List<XsuaaScimClient.IdpRcMapping> rules =
                        xsuaa.listIdpRoleCollectionMappings(xsuaaJson, origin);
                Map<String, Set<String>> groupToRcs = new HashMap<>();
                for (XsuaaScimClient.IdpRcMapping r : rules) {
                    if (!"Groups".equalsIgnoreCase(r.attributeName())) continue;
                    if (!"equals".equalsIgnoreCase(r.comparisonOperator())) continue;
                    if (r.attributeValue() == null || r.roleCollectionName() == null) continue;
                    groupToRcs.computeIfAbsent(r.attributeValue(), k -> new HashSet<>())
                            .add(r.roleCollectionName());
                }
                if (!groupToRcs.isEmpty()) mappingByOrigin.put(origin, groupToRcs);
            } catch (Exception e) {
                log.info("SoD enrich: XSUAA mapping lookup failed for origin {} on subaccount {}: {}",
                        origin, sa.id(), e.getMessage());
            }
        }
        if (mappingByOrigin.isEmpty()) return Map.of();

        Map<String, Set<String>> out = new HashMap<>();
        for (XsuaaScimClient.ShadowUser u : shadowUsers) {
            Map<String, Set<String>> groupMap = mappingByOrigin.get(u.origin());
            if (groupMap == null) continue;
            if (u.userName() == null || u.id() == null) continue;
            Set<String> derived = new HashSet<>();
            for (IasTenant tenant : iasTenants.list()) {
                String iasJson;
                try {
                    iasJson = new String(iasTenants.decryptCreds(tenant.id()), StandardCharsets.UTF_8);
                } catch (Exception e) {
                    continue;
                }
                try {
                    Optional<IasClient.IasUser> iasUser = ias.findUserByEmail(iasJson, u.userName());
                    if (iasUser.isEmpty()) continue;
                    List<IasClient.IasGroupRef> groups =
                            ias.listUserGroups(iasJson, iasUser.get().id());
                    for (IasClient.IasGroupRef g : groups) {
                        Set<String> rcs = groupMap.get(g.displayName());
                        if (rcs != null) derived.addAll(rcs);
                    }
                } catch (Exception e) {
                    log.debug("SoD enrich: IAS lookup for {} in tenant {} failed: {}",
                            u.userName(), tenant.id(), e.getMessage());
                }
            }
            if (!derived.isEmpty()) out.put(u.id(), derived);
        }
        return out;
    }

    private int scanOrgs(Subaccount sa, UUID correlationId, List<ConflictSet> rules,
                         List<Finding> findings, Set<String> internalDomains,
                         String actor, ActorSource source) {
        String cfJson = tryDecryptCfApi(sa.id());
        if (cfJson == null) {
            log.info("Skipping {} org-scope rule(s) for subaccount {}: no cf_technical_user credential",
                    rules.size(), sa.id());
            return 0;
        }
        int users = 0;
        for (CfApiClient.Organization org : cf.listOrganizations(cfJson)) {
            for (CfApiClient.CfUser u : cf.listUsersInOrg(cfJson, org.guid())) {
                users++;
                for (ConflictSet cs : rules) {
                    if (!"external_email".equals(cs.kind())) continue;
                    List<String> matched = evaluate(cs, u.username(), Set.of(), internalDomains);
                    if (matched == null) continue;
                    recordFinding(findings, cs, u.username(), u.guid(), u.origin(), matched,
                            "org:" + org.name(), correlationId, sa.id(), actor, source);
                }
            }
        }
        return users;
    }

    private int scanSpaces(Subaccount sa, UUID correlationId, List<ConflictSet> rules,
                           List<Finding> findings, Set<String> internalDomains,
                           String actor, ActorSource source) {
        String cfJson = tryDecryptCfApi(sa.id());
        if (cfJson == null) {
            log.info("Skipping {} space-scope rule(s) for subaccount {}: no cf_technical_user credential",
                    rules.size(), sa.id());
            return 0;
        }
        int users = 0;
        for (CfApiClient.Organization org : cf.listOrganizations(cfJson)) {
            for (CfApiClient.Space space : cf.listSpaces(cfJson, org.guid())) {
                for (CfApiClient.CfUser u : cf.listUsersInSpace(cfJson, space.guid())) {
                    users++;
                    for (ConflictSet cs : rules) {
                        if (!"external_email".equals(cs.kind())) continue;
                        List<String> matched = evaluate(cs, u.username(), Set.of(), internalDomains);
                        if (matched == null) continue;
                        recordFinding(findings, cs, u.username(), u.guid(), u.origin(), matched,
                                "space:" + org.name() + "/" + space.name(),
                                correlationId, sa.id(), actor, source);
                    }
                }
            }
        }
        return users;
    }

    private String tryDecryptCfApi(UUID subaccountId) {
        try {
            return new String(subaccounts.decryptCredential(subaccountId, CredentialKind.CF_TECHNICAL_USER),
                    StandardCharsets.UTF_8);
        } catch (NoSuchElementException e) {
            return null;
        }
    }

    private void recordFinding(List<Finding> findings, ConflictSet cs,
                               String userName, String userId, String origin,
                               List<String> matched, String scopeContext,
                               UUID correlationId, UUID subaccountId,
                               String actor, ActorSource source) {
        String kind = cs.kind() == null ? "sod" : cs.kind();
        findings.add(new Finding(cs.id(), cs.name(), cs.severity(), kind,
                userName, userId, origin, scopeContext, matched));
        audit.record(new AuditEvent(correlationId, subaccountId.toString(), IAuditForward.SystemType.SUBACCOUNT, userName, userId,
                "sod_finding", actor, source, Outcome.OK, null,
                Map.of("conflictSetId", cs.id().toString(),
                        "conflictSetName", cs.name(),
                        "severity", cs.severity(),
                        "kind", kind,
                        "scope", scopeContext,
                        "matched", matched)));
    }

    private static List<ConflictSet> filterScope(List<ConflictSet> all, String... scopes) {
        Set<String> wanted = new HashSet<>(Arrays.asList(scopes));
        List<ConflictSet> out = new ArrayList<>();
        for (ConflictSet cs : all) {
            String s = cs.scopeLevel() == null ? "subaccount" : cs.scopeLevel();
            if (wanted.contains(s)) out.add(cs);
        }
        return out;
    }

    static List<String> evaluate(ConflictSet cs, String userName, Set<String> userRcs,
                                 Set<String> globalInternalDomains) {
        String kind = cs.kind() == null ? "sod" : cs.kind();
        switch (kind) {
            case "sod" -> {
                Set<String> hit = new HashSet<>(cs.roleCollections());
                hit.retainAll(userRcs);
                return hit.size() >= 2 ? new ArrayList<>(hit) : null;
            }
            case "critical" -> {
                Set<String> hit = new HashSet<>(cs.roleCollections());
                hit.retainAll(userRcs);
                return hit.isEmpty() ? null : new ArrayList<>(hit);
            }
            case "threshold" -> {
                int threshold = cs.thresholdCount() == null ? Integer.MAX_VALUE : cs.thresholdCount();
                Set<String> filter = cs.roleCollections() == null ? Set.of() : new HashSet<>(cs.roleCollections());
                List<String> matched;
                if (filter.isEmpty()) {
                    matched = new ArrayList<>(userRcs);
                } else {
                    matched = new ArrayList<>();
                    for (String rc : userRcs) if (filter.contains(rc)) matched.add(rc);
                }
                return matched.size() >= threshold ? matched : null;
            }
            case "external_email" -> {
                Set<String> allowed = normaliseDomains(cs.roleCollections());
                if (allowed.isEmpty()) allowed = globalInternalDomains == null ? Set.of() : globalInternalDomains;
                if (allowed.isEmpty()) return null;
                String email = userName == null ? "" : userName.toLowerCase(Locale.ROOT).trim();
                int at = email.lastIndexOf('@');
                if (at <= 0 || at == email.length() - 1) {
                    // No '@' or malformed - treat as suspicious: flag with a clear marker.
                    return List.of("invalid-email: " + userName);
                }
                String domain = email.substring(at + 1);
                return allowed.contains(domain) ? null : List.of("external: @" + domain);
            }
            default -> {
                return null;
            }
        }
    }

    private static Set<String> normaliseDomains(List<String> raw) {
        if (raw == null || raw.isEmpty()) return Collections.emptySet();
        Set<String> out = new HashSet<>();
        for (String d : raw) {
            if (d == null) continue;
            String s = d.trim().toLowerCase(Locale.ROOT);
            if (s.startsWith("@")) s = s.substring(1);
            if (!s.isEmpty()) out.add(s);
        }
        return out;
    }

    private record UserRoles(String id, String origin, Set<String> roleCollections) {}

    public record Finding(
            UUID conflictSetId,
            String conflictSetName,
            String severity,
            String kind,
            String userEmail,
            String userIasId,
            String origin,
            String scopeContext,                  // "subaccount" / "org:NAME" / "space:ORG/SPACE"
            List<String> matchedRoleCollections
    ) {}

    public record ScanResult(
            UUID correlationId,
            String subaccountDisplayName,
            int usersScanned,
            int conflictSetCount,
            List<Finding> findings,
            String message
    ) {}
}
