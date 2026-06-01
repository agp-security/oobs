// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.containment;

import ninja.gruber.btpc.audit.IAuditForward;
import ninja.gruber.btpc.audit.IAuditForward.ActorSource;
import ninja.gruber.btpc.audit.IAuditForward.Outcome;
import ninja.gruber.btpc.cf.CfApiClient;
import ninja.gruber.btpc.containment.domain.ContainmentDtos.ActionResult;
import ninja.gruber.btpc.containment.domain.ContainmentDtos.ContainRequest;
import ninja.gruber.btpc.containment.domain.ContainmentDtos.ContainmentResult;
import ninja.gruber.btpc.containment.domain.ContainmentDtos.SubaccountResult;
import ninja.gruber.btpc.domain.CredentialKind;
import ninja.gruber.btpc.domain.ProtectedUser;
import ninja.gruber.btpc.domain.Subaccount;
import ninja.gruber.btpc.iam.IasClient;
import ninja.gruber.btpc.iam.XsuaaScimClient;
import ninja.gruber.btpc.iastenant.IasTenantService;
import ninja.gruber.btpc.protect.ProtectedUserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Service
public class ContainmentService {

    private static final Logger log = LoggerFactory.getLogger(ContainmentService.class);

    private final ProtectedUserService protections;
    private final IasClient ias;
    private final IasTenantService iasTenants;
    private final XsuaaScimClient xsuaa;
    private final CfApiClient cf;
    private final SnapshotRepo snapshots;
    private final ContainmentSupport support;

    public ContainmentService(ProtectedUserService protections,
                              IasClient ias,
                              IasTenantService iasTenants,
                              XsuaaScimClient xsuaa,
                              CfApiClient cf,
                              SnapshotRepo snapshots,
                              ContainmentSupport support) {
        this.protections = protections;
        this.ias = ias;
        this.iasTenants = iasTenants;
        this.xsuaa = xsuaa;
        this.cf = cf;
        this.snapshots = snapshots;
        this.support = support;
    }

    public ContainmentResult contain(ContainRequest req, String actor, ActorSource source) {
        validate(req);
        UUID correlationId = UUID.randomUUID(); //for internal tracking
        boolean isDryRun = req.dryRun != null ? req.dryRun : true;

        support.emitComment(correlationId, req.userEmail, actor, source, "containment", req.comment);

        List<String> perIASActions = orderedSubset(req.actions, IAS_ACTIONS);
        List<String> perSaActions  = orderedSubset(req.actions, SA_ACTIONS);
        boolean containsIAS = !perIASActions.isEmpty();
        boolean containsSubaccount = !perSaActions.isEmpty();

        List<Subaccount> sas = containsSubaccount ? support.resolveSubaccountList(req.subaccountIds) : List.of();
        List<UUID> tenantIds = containsIAS ? support.resolveTenantList(req.iasTenantIds) : List.of();

        if (sas.isEmpty() && tenantIds.isEmpty())
            throw new IllegalArgumentException(ContainmentMessages.NOTHING_TO_CONTAIN);

        ProtectedUserService.CheckResult globalCheck =
                protections.check(req.userEmail, null);
        if (globalCheck.isProtected()) {
            List<String> reasons = reasons(globalCheck);
            support.emitLog(correlationId, null, req.userEmail, null, "protect_block",
                    actor, source, Outcome.SKIPPED, null,
                    Map.of("matchedReasons", reasons,
                            "scope", "global",
                            "requestedActions", req.actions), IAuditForward.SystemType.INTERNAL);
            return new ContainmentResult(correlationId, isDryRun,
                    tenantIds, List.of(), List.of(), reasons);
        }

        List<ActionResult> perIAS = new ArrayList<>();
        for (UUID tenantId : tenantIds) {
            perIAS.addAll(containOneIAS(tenantId, req, perIASActions, correlationId,
                    isDryRun, actor, source)); // no wrapper for IAS -> direct results
        }

        List<SubaccountResult> perSubaccount = new ArrayList<>();
        for (Subaccount sa : sas) {
            perSubaccount.add(containOneSubaccount(sa, req, perSaActions, correlationId,
                    isDryRun, actor, source));
        }

        return new ContainmentResult(correlationId, isDryRun,
                tenantIds, perIAS, perSubaccount, null);
    }


    /**
     * doesn't work if shadow user gets deleted and then role revocation as no user entry..
     */
    private static int actionPriority(String action) {
        return switch (action) {
            case "xsuaa_strip_roles"   -> 1;
            case "cf_revoke_org_roles" -> 2;
            case "xsuaa_delete_shadow" -> 3;
            case "ias_strip_groups" -> 4;
            case "ias_deactivate" -> 5;
            default                    -> 99;
        };
    }

    private static List<String> orderedSubset(List<String> actions, Set<String> allowed) {
        return actions.stream()
                .filter(allowed::contains)
                .sorted(Comparator.comparingInt(ContainmentService::actionPriority))
                .toList();
    }

    private static List<String> reasons(ProtectedUserService.CheckResult check) {
        return check.matches().stream().map(ProtectedUser::reason).toList();
    }

    private List<XsuaaScimClient.ShadowUser> shadowsForRequest(String xsuaaJson, ContainRequest req, OriginFilter of) {
        List<XsuaaScimClient.ShadowUser> shadows = xsuaa.findShadowUsersByEmail(xsuaaJson, req.userEmail);
        if (of.allOrigins()) return shadows;
        return shadows.stream().filter(s -> of.origins().contains(s.origin())).toList();
    }

    private List<ActionResult> containOneIAS(UUID tenantId, ContainRequest req,
                                                  List<String> perIASActions, UUID correlationId,
                                                  boolean isDryRun,
                                                  String actor, ActorSource source) {
        ProtectedUserService.CheckResult tenantCheck =
                protections.check(req.userEmail, null, tenantId);
        if (tenantCheck.isProtected()) {
            List<String> reasons = reasons(tenantCheck);
            Map<String, Object> detail = new LinkedHashMap<>();
            detail.put("matchedReasons", reasons);
            detail.put("iasTenantId", tenantId.toString());
            support.emitLog(correlationId, tenantId.toString(), req.userEmail, null, "protect_block",
                    actor, source, Outcome.SKIPPED, null, detail, IAuditForward.SystemType.IAS);
            return List.of(new ActionResult(perIASActions.get(0), "skipped",
                    "user is protected in tenant: " + String.join("; ", reasons), null));
        }
        String iasJson;
        try {
            iasJson = new String(iasTenants.decryptCreds(tenantId), StandardCharsets.UTF_8);
        } catch (NoSuchElementException e) {
            return List.of(new ActionResult(
                    perIASActions.get(0), "failed",
                    "IAS tenant " + tenantId + " not found", null));
        }
        try {
            String iasUserId = null;
            Optional<IasClient.IasUser> u = ias.findUserByEmail(iasJson, req.userEmail);
            if (u.isPresent()) {
                iasUserId = u.get().id();
            }
            if (iasUserId == null) {
                support.emitLog(correlationId, tenantId.toString(), req.userEmail, null, perIASActions.get(0),
                        actor, source, Outcome.SKIPPED, "user not in tenant",
                        Map.of("iasTenantId", tenantId.toString()), IAuditForward.SystemType.IAS);
                return List.of(new ActionResult(perIASActions.get(0), "skipped",
                        "user " + req.userEmail + " not present in IAS tenant " + tenantId, null));
            }
            List<ActionResult> listAll = new ArrayList<>();
            if (perIASActions.contains("ias_deactivate")) {
                listAll.add(runIasSetActiveTenant(tenantId, iasJson, req, correlationId,
                        iasUserId, false, isDryRun, actor, source));
            }
            if (perIASActions.contains("ias_strip_groups")) {
                listAll.add(runIasStripGroupsTenant(tenantId, iasJson, req, correlationId,
                        iasUserId, isDryRun, actor, source));
            }
            return listAll;
        } catch (Exception e) {
            log.warn("{} failed for tenant {}", perIASActions.get(0), tenantId, e);
            support.emitLog(correlationId, tenantId.toString(), req.userEmail, "" /*get if possible*/, perIASActions.get(0),
                    actor, source, Outcome.FAILED, e.getMessage(),
                    Map.of("iasTenantId", tenantId.toString()), IAuditForward.SystemType.IAS);
            return List.of(new ActionResult(perIASActions.get(0), "failed", e.getMessage(), null));
        }
    }

    private SubaccountResult containOneSubaccount(Subaccount sa, ContainRequest req,
                                                  List<String> perSaActions, UUID correlationId,
                                                  boolean dryRun,
                                                  String actor, ActorSource source) {
        ProtectedUserService.CheckResult check = protections.check(req.userEmail, sa.id());
        if (check.isProtected()) {
            List<String> reasons = reasons(check);
            support.emitLog(correlationId, sa.id().toString(), req.userEmail, null, "protect_block",
                    actor, source, Outcome.SKIPPED, null,
                    Map.of("matchedReasons", reasons, "requestedActions", perSaActions), IAuditForward.SystemType.SUBACCOUNT);
            List<ActionResult> blocked = new ArrayList<>();
            for (String a : perSaActions) {
                blocked.add(new ActionResult(a, "skipped",
                        "user is protected: " + String.join("; ", reasons), null));
            }
            return new SubaccountResult(sa.id(), sa.cisDisplayName(), true, blocked, reasons);
        }
        List<ActionResult> results = new ArrayList<>();
        for (String action : perSaActions) {
            try {
                switch (action) {
                    case "xsuaa_strip_roles"   -> results.add(runStripRoles(sa, req, correlationId, dryRun, actor, source));
                    case "xsuaa_delete_shadow" -> results.add(runDeleteShadow(sa, req, correlationId, dryRun, actor, source));
                    case "cf_revoke_org_roles" -> results.add(runCfRevokeOrgRoles(sa, req, correlationId, dryRun, actor, source));
                    default -> {
                        results.add(new ActionResult(action, "failed",
                                "unknown action: " + action, null));
                        support.emitLog(correlationId, sa.id().toString(), req.userEmail, "",
                                action.matches("[a-z_]+") ? action : "sod_scan",
                                actor, source, Outcome.FAILED, "unknown action", null, IAuditForward.SystemType.SUBACCOUNT);
                    }
                }
            } catch (CfUserNotFoundException e) {
                log.info("containment action {} skipped for subaccount {}: {}",
                        action, sa.id(), e.getMessage());
                results.add(new ActionResult(action, "skipped", e.getMessage(), null));
                support.emitLog(correlationId, sa.id().toString(), req.userEmail, "", action,
                        actor, source, Outcome.SKIPPED, e.getMessage(),
                        Map.of("reason", "cf_user_not_found"), IAuditForward.SystemType.SUBACCOUNT);
            } catch (Exception e) {
                log.warn("containment action {} failed for subaccount {}", action, sa.id(), e);
                results.add(new ActionResult(action, "failed", e.getMessage(), null));
                support.emitLog(correlationId, sa.id().toString(), req.userEmail, "", action,
                        actor, source, Outcome.FAILED, e.getMessage(), null, IAuditForward.SystemType.SUBACCOUNT);
            }
        }
        return new SubaccountResult(sa.id(), sa.cisDisplayName(), false, results, List.of());
    }

    private ActionResult runIasStripGroupsTenant(UUID iasTenantId, String iasJson,
                                                 ContainRequest req, UUID corr,
                                                 String iasUserId, boolean dryRun,
                                                 String actor, ActorSource source) {
        List<IasClient.IasGroupRef> groups;
        try {
            groups = ias.listUserGroups(iasJson, iasUserId);
        } catch (Exception e) {
            support.emitLog(corr, iasTenantId.toString(), req.userEmail, iasUserId, "ias_strip_groups",
                    actor, source, Outcome.FAILED, e.getMessage(),
                    Map.of("iasTenantId", iasTenantId.toString()), IAuditForward.SystemType.IAS);
            return new ActionResult("ias_strip_groups", "failed", e.getMessage(), null);
        }
        if (groups.isEmpty()) {
            support.emitLog(corr, iasTenantId.toString(), req.userEmail, iasUserId, "ias_strip_groups",
                    actor, source, Outcome.SKIPPED, "user has no group memberships in this IAS tenant",
                    Map.of("iasTenantId", iasTenantId.toString()), IAuditForward.SystemType.IAS);
            return new ActionResult("ias_strip_groups", "skipped",
                    "user has no IAS group memberships in tenant " + iasTenantId, null);
        }
        UUID snapshotId = null;
        Outcome outcome;
        String msg;
        if (dryRun) {
            outcome = Outcome.DRY_RUN;
            msg = "would remove user from " + groups.size() + " IAS group(s)";
        } else {
            snapshotId = snapshots.record(corr, IAuditForward.SystemType.IAS, iasTenantId.toString(),
                    iasUserId, SnapshotRepo.SnapshotKind.IAS_USER_GROUPS,
                    Map.of("groups", iasGroupSnapshot(groups)));
            RemovalResult r = removeIasGroups(iasJson, iasUserId, groups);
            if (r.removed() == 0) {
                snapshots.delete(snapshotId);
                snapshotId = null;
                outcome = Outcome.FAILED;
            } else {
                outcome = r.removed() == groups.size() ? Outcome.OK : Outcome.PARTIAL;
            }
            msg = "removed user from " + r.removed() + "/" + groups.size() + " IAS group(s)"
                    + (r.failed().isEmpty() ? "" : "; failed: " + String.join("; ", r.failed()));
        }
        Map<String, Object> details = new LinkedHashMap<>();
        if (snapshotId != null) details.put("snapshotId", snapshotId.toString());
        details.put("dryRun", dryRun);
        details.put("iasTenantId", iasTenantId.toString());
        details.put("groupCount", groups.size());
        support.emitLog(corr, iasTenantId.toString(), req.userEmail, iasUserId, "ias_strip_groups",
                actor, source, outcome, null, details, IAuditForward.SystemType.IAS);
        return ActionResult.of("ias_strip_groups", outcome, msg, snapshotId);
    }

    private static List<Map<String, String>> iasGroupSnapshot(List<IasClient.IasGroupRef> groups) {
        List<Map<String, String>> out = new ArrayList<>();
        for (IasClient.IasGroupRef g : groups) {
            Map<String, String> m = new LinkedHashMap<>();
            m.put("id", g.id());
            if (g.displayName() != null) m.put("displayName", g.displayName());
            out.add(m);
        }
        return out;
    }

    private RemovalResult removeIasGroups(String iasJson, String iasUserId,
                                          List<IasClient.IasGroupRef> groups) {
        int removed = 0;
        List<String> failed = new ArrayList<>();
        for (IasClient.IasGroupRef g : groups) {
            try {
                ias.removeUserFromGroup(iasJson, g.id(), iasUserId);
                removed++;
            } catch (Exception e) {
                failed.add(g.id() + ": " + e.getMessage());
                log.warn("ias removeUserFromGroup failed for group {}: {}", g.id(), e.getMessage());
            }
        }
        return new RemovalResult(removed, failed);
    }

    private ActionResult runIasSetActiveTenant(UUID iasTenantId, String iasJson,
                                               ContainRequest req, UUID corr,
                                               String iasUserId, boolean active, boolean dryRun,
                                               String actor, ActorSource source) {
        UUID snapshotId = null;
        Outcome outcome;
        String msg;
        if (dryRun) {
            outcome = Outcome.DRY_RUN;
            msg = "would PATCH active=" + active + " on IAS user " + iasUserId;
        } else {
            snapshotId = snapshots.record(corr, IAuditForward.SystemType.IAS, iasTenantId.toString(),
                    iasUserId, SnapshotRepo.SnapshotKind.IAS_USER_STATE,
                    Map.of("active", true));
            IasClient.IasUser updated;
            try {
                updated = ias.setActive(iasJson, iasUserId, active);
            } catch (RuntimeException e) {
                snapshots.delete(snapshotId);
                throw e;
            }
            outcome = Outcome.OK;
            msg = "IAS user " + iasUserId + " active=" + updated.active();
            active = updated.active();
        }
        String action = active ? "ias_activate" : "ias_deactivate";
        Map<String, Object> details = new LinkedHashMap<>();
        if (snapshotId != null) details.put("snapshotId", snapshotId.toString());
        details.put("dryRun", dryRun);
        details.put("iasTenantId", iasTenantId.toString());
        support.emitLog(corr, iasTenantId.toString(), req.userEmail, iasUserId, action,
                actor, source, outcome, null, details, IAuditForward.SystemType.IAS);
        return ActionResult.of(action, outcome, msg, snapshotId);
    }

    private ActionResult runStripRoles(Subaccount sa, ContainRequest req, UUID corr,
                                       boolean dryRun, String actor, ActorSource source) {
        String xsuaaJson = support.requireCredential(sa.id(), CredentialKind.XSUAA_APIACCESS,
                "Cannot run xsuaa_strip_roles: no XSUAA api-access credential for this subaccount");
        OriginFilter of = OriginFilter.of(req);
        List<XsuaaScimClient.ShadowUser> shadows = shadowsForRequest(xsuaaJson, req, of);
        if (shadows.isEmpty()) {
            String skipMsg = of.allOrigins()
                    ? "no shadow users found for " + req.userEmail
                    : "no shadow user at any selected origin: " + of.origins();
            support.emitLog(corr, sa.id().toString(), req.userEmail, null, "xsuaa_strip_roles",
                    actor, source, Outcome.SKIPPED, "no shadow users for email/origin",
                    Map.of("dryRun", dryRun, "originMode", of.mode(), "origins", of.origins()), IAuditForward.SystemType.SUBACCOUNT);
            return new ActionResult("xsuaa_strip_roles", "skipped", skipMsg, null);
        }

        RoleHits hits = resolveRoleCollectionHits(xsuaaJson, shadows);

        UUID snapshotId = null;
        Outcome outcome;
        String msg;
        if (dryRun) {
            outcome = Outcome.DRY_RUN;
            msg = "would remove " + hits.totalRoles() + " role collection(s) across "
                    + hits.origins().size() + " origin(s): " + hits.origins();
        } else {
            snapshotId = snapshots.record(corr, IAuditForward.SystemType.SUBACCOUNT, sa.id().toString(),
                    req.userEmail, SnapshotRepo.SnapshotKind.ROLE_COLLECTIONS,
                    Map.of("perOrigin", hits.perOrigin(),
                            "originMode", of.mode(),
                            "origins", of.origins()));
            RemovalResult r = removeRoleMemberships(xsuaaJson, hits);
            if (r.removed() == 0) {
                snapshots.delete(snapshotId);
                snapshotId = null;
                outcome = Outcome.FAILED;
            } else {
                outcome = r.removed() == hits.totalRoles() ? Outcome.OK : Outcome.PARTIAL;
            }
            msg = "removed " + r.removed() + "/" + hits.totalRoles() + " role collection(s) across "
                    + hits.origins().size() + " origin(s)"
                    + (r.failed().isEmpty() ? "" : "; failed: " + String.join("; ", r.failed()));
        }
        Map<String, Object> details = new LinkedHashMap<>();
        if (snapshotId != null) details.put("snapshotId", snapshotId.toString());
        details.put("dryRun", dryRun);
        details.put("originMode", of.mode());
        details.put("origins", hits.origins());
        details.put("rolesBefore", hits.perOrigin());
        support.emitLog(corr, sa.id().toString(), req.userEmail, null, "xsuaa_strip_roles",
                actor, source, outcome, null, details, IAuditForward.SystemType.SUBACCOUNT);
        return ActionResult.of("xsuaa_strip_roles", outcome, msg, snapshotId);
    }

    private RoleHits resolveRoleCollectionHits(String xsuaaJson, List<XsuaaScimClient.ShadowUser> shadows) {
        Set<String> targetKeys = new HashSet<>();
        Map<String, String> userIdByOrigin = new LinkedHashMap<>();
        List<String> origins = new ArrayList<>();
        for (XsuaaScimClient.ShadowUser s : shadows) {
            if (s.id() == null || s.origin() == null) continue;
            targetKeys.add(s.origin() + "\0" + s.id());
            if (userIdByOrigin.putIfAbsent(s.origin(), s.id()) == null) {
                origins.add(s.origin());
            }
        }

        Map<String, List<String[]>> hitsByOrigin = new LinkedHashMap<>();
        for (String o : origins) hitsByOrigin.put(o, new ArrayList<>());
        for (XsuaaScimClient.Group g : xsuaa.listGroups(xsuaaJson)) {
            for (XsuaaScimClient.Member m : g.members()) {
                if (m.userId() == null || m.origin() == null) continue;
                if (!targetKeys.contains(m.origin() + "\0" + m.userId())) continue;
                hitsByOrigin.computeIfAbsent(m.origin(), k -> new ArrayList<>())
                        .add(new String[]{g.id(), g.displayName()});
            }
        }

        List<Map<String, Object>> perOrigin = new ArrayList<>();
        int totalRoles = 0;
        for (String o : origins) {
            List<String> rcNames = new ArrayList<>();
            for (String[] hit : hitsByOrigin.getOrDefault(o, List.of())) rcNames.add(hit[1]);
            perOrigin.add(Map.of("origin", o, "roleCollections", rcNames));
            totalRoles += rcNames.size();
        }
        return new RoleHits(origins, userIdByOrigin, hitsByOrigin, perOrigin, totalRoles);
    }

    private RemovalResult removeRoleMemberships(String xsuaaJson, RoleHits hits) {
        int removed = 0;
        List<String> failed = new ArrayList<>();
        for (Map.Entry<String, List<String[]>> entry : hits.hitsByOrigin().entrySet()) {
            String userId = hits.userIdByOrigin().get(entry.getKey());
            if (userId == null) continue;
            for (String[] hit : entry.getValue()) {
                try {
                    xsuaa.removeMember(xsuaaJson, hit[0], userId);
                    removed++;
                } catch (Exception e) {
                    failed.add(hit[1] + "@" + entry.getKey() + ": " + e.getMessage());
                    log.warn("xsuaa removeMember failed for rc '{}' ({}): {}",
                            hit[1], hit[0], e.getMessage());
                }
            }
        }
        return new RemovalResult(removed, failed);
    }

    private record RoleHits(
            List<String> origins,
            Map<String, String> userIdByOrigin,
            Map<String, List<String[]>> hitsByOrigin,
            List<Map<String, Object>> perOrigin,
            int totalRoles) {}

    private record RemovalResult(int removed, List<String> failed) {}

    private ActionResult runDeleteShadow(Subaccount sa, ContainRequest req, UUID corr,
                                         boolean dryRun, String actor, ActorSource source) {
        String xsuaaJson = support.requireCredential(sa.id(), CredentialKind.XSUAA_APIACCESS,
                "Cannot run xsuaa_delete_shadow: no XSUAA api-access credential for this subaccount");
        OriginFilter of = OriginFilter.of(req);
        List<XsuaaScimClient.ShadowUser> shadows = shadowsForRequest(xsuaaJson, req, of);
        if (shadows.isEmpty()) {
            support.emitLog(corr, sa.id().toString(), req.userEmail, null, "xsuaa_delete_shadow",
                    actor, source, Outcome.SKIPPED, "no shadow user",
                    Map.of("dryRun", dryRun, "originMode", of.mode(), "origins", of.origins()), IAuditForward.SystemType.SUBACCOUNT);
            return new ActionResult("xsuaa_delete_shadow", "skipped",
                    "no shadow user with email " + req.userEmail, null);
        }
        Outcome outcome;
        String msg;
        if (dryRun) {
            outcome = Outcome.DRY_RUN;
            msg = "would DELETE " + shadows.size() + " shadow user(s): "
                    + shadows.stream().map(s -> s.id() + " (origin=" + s.origin() + ")").toList();
        } else {
            int deleted = 0;
            for (XsuaaScimClient.ShadowUser s : shadows) {
                xsuaa.deleteShadowUser(xsuaaJson, s.id());
                deleted++;
            }
            outcome = deleted == shadows.size() ? Outcome.OK : Outcome.PARTIAL;
            msg = "deleted " + deleted + "/" + shadows.size() + " shadow user(s)";
        }
        support.emitLog(corr, sa.id().toString(), req.userEmail,
                shadows.size() == 1 ? shadows.get(0).id() : null,
                "xsuaa_delete_shadow", actor, source, outcome, null,
                Map.of("dryRun", dryRun,
                        "originMode", of.mode(),
                        "shadowUserIds", shadows.stream().map(XsuaaScimClient.ShadowUser::id).toList(),
                        "origins", shadows.stream().map(XsuaaScimClient.ShadowUser::origin).distinct().toList()), IAuditForward.SystemType.SUBACCOUNT);
        return ActionResult.of("xsuaa_delete_shadow", outcome, msg, null);
    }

    private ActionResult runCfRevokeOrgRoles(Subaccount sa, ContainRequest req, UUID corr,
                                             boolean dryRun, String actor, ActorSource source) {
        String cfJson = support.requireCredential(sa.id(), CredentialKind.CF_TECHNICAL_USER,
                "Cannot run cf_revoke_org_roles: no cf_technical_user credential for this subaccount");
        UUID orgIdUuid = sa.cfOrgId();
        if (orgIdUuid == null) {
            String msg = ContainmentMessages.noCfOrgIdConfigured(sa.cisDisplayName());
            support.emitLog(corr, sa.id().toString(), req.userEmail, null, "cf_revoke_org_roles",
                    actor, source, Outcome.SKIPPED, msg, Map.of("dryRun", dryRun), IAuditForward.SystemType.SUBACCOUNT);
            return new ActionResult("cf_revoke_org_roles", "skipped", msg, null);
        }
        String orgGuid = orgIdUuid.toString();

        List<CfApiClient.Space> spaces = cf.listSpaces(cfJson, orgGuid);
        List<CfApiClient.CfUser> cfUsers = support.resolveCfUsersInOrg(cfJson, req.userEmail, req, orgGuid, spaces);
        if (cfUsers.isEmpty()) {
            String skipMsg = "no CF user with email " + req.userEmail
                    + " holds a role in org " + orgGuid + " - nothing to revoke";
            support.emitLog(corr, sa.id().toString(), req.userEmail, null, "cf_revoke_org_roles",
                    actor, source, Outcome.SKIPPED, null,
                    Map.of("dryRun", dryRun, "orgGuid", orgGuid), IAuditForward.SystemType.SUBACCOUNT);
            return new ActionResult("cf_revoke_org_roles", "skipped", skipMsg, null);
        }

        List<CfUserRevokeResult> perUser = new ArrayList<>();
        for (CfApiClient.CfUser cfUser : cfUsers) {
            perUser.add(revokeOrgRolesForUser(cfJson, cfUser, spaces, orgGuid, sa, corr, dryRun));
        }

        int usersWithRoles    = (int) perUser.stream().filter(CfUserRevokeResult::hadRoles).count();
        int totalAttempts     = perUser.stream().mapToInt(CfUserRevokeResult::rolesAttempted).sum();
        int totalRevoked      = perUser.stream().mapToInt(CfUserRevokeResult::rolesDeleted).sum();
        List<UUID> snapshotIds = perUser.stream()
                .map(CfUserRevokeResult::snapshotId).filter(java.util.Objects::nonNull).toList();
        List<String> failureNotes = perUser.stream()
                .flatMap(r -> r.failureNotes().stream()).toList();
        List<Map<String, Object>> perUserSummaries = perUser.stream()
                .map(CfUserRevokeResult::summary).toList();

        if (usersWithRoles == 0) {
            String users = cfUsers.stream()
                    .map(u -> u.guid() + "@" + u.origin())
                    .collect(java.util.stream.Collectors.joining(", "));
            String skipMsg = "no CF user (of " + cfUsers.size() + " match"
                    + (cfUsers.size() == 1 ? "" : "es") + ") had org roles in org "
                    + orgGuid + " - nothing to revoke (no snapshot written). "
                    + "Checked: " + users;
            support.emitLog(corr, sa.id().toString(), req.userEmail, null, "cf_revoke_org_roles",
                    actor, source, Outcome.SKIPPED, null,
                    Map.of("dryRun", dryRun,
                            "orgGuid", orgGuid,
                            "matchCount", cfUsers.size(),
                            "perUser", perUserSummaries,
                            "reason", "no org roles on any match"), IAuditForward.SystemType.SUBACCOUNT);
            return new ActionResult("cf_revoke_org_roles", "skipped", skipMsg, null);
        }

        Outcome outcome;
        String msg;
        if (dryRun) {
            outcome = Outcome.DRY_RUN;
            msg = "would delete " + totalAttempts + " org role(s) in org " + orgGuid
                    + " across " + usersWithRoles + " CF user(s) for " + req.userEmail;
        } else {
            outcome = (totalRevoked == totalAttempts && failureNotes.isEmpty())
                    ? Outcome.OK : Outcome.PARTIAL;
            msg = "deleted " + totalRevoked + "/" + totalAttempts + " org role(s) in org "
                    + orgGuid + " across " + usersWithRoles + " CF user(s)"
                    + (failureNotes.isEmpty() ? ""
                            : "; failed: " + String.join("; ", failureNotes));
        }
        support.emitLog(corr, sa.id().toString(), req.userEmail, null, "cf_revoke_org_roles",
                actor, source, outcome, null,
                Map.of("snapshotIds", snapshotIds.stream().map(UUID::toString).toList(),
                        "dryRun", dryRun,
                        "orgGuid", orgGuid,
                        "matchCount", cfUsers.size(),
                        "usersWithRoles", usersWithRoles,
                        "perUser", perUserSummaries), IAuditForward.SystemType.SUBACCOUNT);
        return ActionResult.of("cf_revoke_org_roles", outcome, msg,
                snapshotIds.isEmpty() ? null : snapshotIds.get(0));
    }

    private CfUserRevokeResult revokeOrgRolesForUser(String cfJson, CfApiClient.CfUser cfUser,
                                                    List<CfApiClient.Space> spaces, String orgGuid,
                                                    Subaccount sa, UUID corr, boolean dryRun) {
        List<CfApiClient.RoleEntry> orgRoles = cf.listRolesForUser(cfJson, cfUser.guid(), orgGuid, null);
        List<CfApiClient.RoleEntry> spaceRoles = new ArrayList<>();
        for (CfApiClient.Space sp : spaces) {
            spaceRoles.addAll(cf.listRolesForUser(cfJson, cfUser.guid(), null, sp.guid()));
        }
        if (orgRoles.isEmpty() && spaceRoles.isEmpty()) {
            return new CfUserRevokeResult(0, 0, null, false,
                    Map.of("userGuid", cfUser.guid(),
                            "userName", String.valueOf(cfUser.username()),
                            "origin", String.valueOf(cfUser.origin()),
                            "rolesBefore", List.of(),
                            "outcome", "skipped",
                            "reason", "no org or space roles"),
                    List.of());
        }

        List<Map<String, Object>> snapshotRoles = new ArrayList<>();
        for (CfApiClient.RoleEntry r : orgRoles) {
            snapshotRoles.add(Map.of("orgGuid", orgGuid, "type", r.type()));
        }
        UUID snapshotId = null;
        if (!dryRun && !orgRoles.isEmpty()) {
            snapshotId = snapshots.record(corr, IAuditForward.SystemType.SUBACCOUNT, sa.id().toString(),
                    cfUser.guid(), SnapshotRepo.SnapshotKind.CF_ORG_ROLES,
                    Map.of("userGuid", cfUser.guid(),
                            "userName", String.valueOf(cfUser.username()),
                            "origin", String.valueOf(cfUser.origin()),
                            "orgGuid", orgGuid,
                            "roles", snapshotRoles));
        }

        List<CfApiClient.RoleEntry> deleteOrder = new ArrayList<>(spaceRoles);
        for (CfApiClient.RoleEntry r : orgRoles) {
            if (!"organization_user".equals(r.type())) deleteOrder.add(r);
        }
        for (CfApiClient.RoleEntry r : orgRoles) {
            if ("organization_user".equals(r.type())) deleteOrder.add(r);
        }

        int userTotal = deleteOrder.size();
        int userDeleted = 0;
        List<String> failures = new ArrayList<>();
        if (!dryRun) {
            for (CfApiClient.RoleEntry r : deleteOrder) {
                try {
                    cf.deleteRole(cfJson, r.guid());
                    userDeleted++;
                } catch (Exception e) {
                    failures.add(cfUser.guid() + "@" + cfUser.origin()
                            + " " + r.type() + " " + r.guid() + ": " + e.getMessage());
                    log.warn("cf deleteRole failed for {}/{}: {}", r.type(), r.guid(), e.getMessage());
                }
            }
        }

        if (!dryRun && userDeleted == 0 && snapshotId != null) {
            snapshots.delete(snapshotId);
            snapshotId = null;
        }

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("userGuid", cfUser.guid());
        summary.put("userName", String.valueOf(cfUser.username()));
        summary.put("origin", String.valueOf(cfUser.origin()));
        summary.put("rolesBefore", snapshotRoles);
        summary.put("spaceRolesRevoked", spaceRoles.size());
        if (snapshotId != null) summary.put("snapshotId", snapshotId.toString());
        summary.put("rolesDeleted", dryRun ? 0 : userDeleted);
        summary.put("outcome", dryRun ? "dry-run"
                : (userDeleted == userTotal ? "ok" : "partial"));

        return new CfUserRevokeResult(userTotal, userDeleted, snapshotId, true, summary, failures);
    }

    private record CfUserRevokeResult(
            int rolesAttempted,
            int rolesDeleted,
            UUID snapshotId,
            boolean hadRoles,
            Map<String, Object> summary,
            List<String> failureNotes
    ) {}

    static final Set<String> SA_ACTIONS = Set.of(
            "xsuaa_strip_roles", "xsuaa_delete_shadow", "cf_revoke_org_roles");
    static final Set<String> IAS_ACTIONS = Set.of(
            "ias_deactivate", "ias_strip_groups");
    private static final Set<String> ALLOWED_ACTIONS;
    static {
        Set<String> all = new java.util.HashSet<>(SA_ACTIONS);
        all.addAll(IAS_ACTIONS);
        ALLOWED_ACTIONS = Set.copyOf(all);
    }

    private void validate(ContainRequest req) {
        if (req == null) throw new IllegalArgumentException("body is required");
        if (req.userEmail == null || req.userEmail.isBlank())
            throw new IllegalArgumentException("userEmail is required");
        if (req.actions == null || req.actions.isEmpty()) {
            throw new IllegalArgumentException(
                    "actions is required and must be non-empty; allowed: " + ALLOWED_ACTIONS);
        }
        for (String a : req.actions) {
            if (!ALLOWED_ACTIONS.contains(a)) {
                throw new IllegalArgumentException(
                        "unknown action '" + a + "'; allowed: " + ALLOWED_ACTIONS);
            }
        }
        if (req.originMode != null && !req.originMode.isBlank()) {
            String m = req.originMode.toLowerCase();
            if (!m.equals("all") && !m.equals("list") && !m.equals("discovered")) {
                throw new IllegalArgumentException(
                        "originMode must be 'all', 'list', or 'discovered'; got: " + req.originMode);
            }
            if (!m.equals("all") && (req.origins == null || req.origins.isEmpty())) {
                throw new IllegalArgumentException(
                        "originMode='" + req.originMode + "' requires a non-empty origins list");
            }
        }
    }
}
