// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.containment;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ninja.gruber.btpc.audit.IAuditForward;
import ninja.gruber.btpc.audit.IAuditForward.ActorSource;
import ninja.gruber.btpc.audit.IAuditForward.Outcome;
import ninja.gruber.btpc.cf.CfApiClient;
import ninja.gruber.btpc.containment.domain.ContainmentDtos.ActionResult;
import ninja.gruber.btpc.containment.domain.ContainmentDtos.SubaccountResult;
import ninja.gruber.btpc.containment.domain.ContainmentDtos.UnlockPreviewEntry;
import ninja.gruber.btpc.containment.domain.ContainmentDtos.UnlockPreviewOrigin;
import ninja.gruber.btpc.containment.domain.ContainmentDtos.UnlockRequest;
import ninja.gruber.btpc.containment.domain.ContainmentDtos.UnlockResult;
import ninja.gruber.btpc.domain.CredentialKind;
import ninja.gruber.btpc.domain.Subaccount;
import ninja.gruber.btpc.enroll.SubaccountService;
import ninja.gruber.btpc.iam.IasClient;
import ninja.gruber.btpc.iam.XsuaaScimClient;
import ninja.gruber.btpc.iastenant.IasTenantService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Service
public class UnlockService {

    private static final Logger log = LoggerFactory.getLogger(UnlockService.class);

    private final SubaccountService subaccounts;
    private final IasClient ias;
    private final IasTenantService iasTenants;
    private final XsuaaScimClient xsuaa;
    private final CfApiClient cf;
    private final SnapshotRepo snapshots;
    private final ObjectMapper mapper;
    private final ContainmentSupport support;

    public UnlockService(SubaccountService subaccounts,
                         IasClient ias,
                         IasTenantService iasTenants,
                         XsuaaScimClient xsuaa,
                         CfApiClient cf,
                         SnapshotRepo snapshots,
                         ObjectMapper mapper,
                         ContainmentSupport support) {
        this.subaccounts = subaccounts;
        this.ias = ias;
        this.iasTenants = iasTenants;
        this.xsuaa = xsuaa;
        this.cf = cf;
        this.snapshots = snapshots;
        this.mapper = mapper;
        this.support = support;
    }

    static final Set<String> SA_ACTIONS = Set.of(
            "xsuaa_restore_roles", "cf_restore_org_roles");
    static final Set<String> IAS_ACTIONS = Set.of(
            "ias_activate", "ias_restore_groups");
    private static final Set<String> ALLOWED_ACTIONS;
    static {
        Set<String> all = new java.util.HashSet<>(SA_ACTIONS);
        all.addAll(IAS_ACTIONS);
        ALLOWED_ACTIONS = Set.copyOf(all);
    }

    public UnlockResult unlock(UnlockRequest req, String actor, ActorSource source) {
        validate(req);
        boolean doIasActivate     = req.actions.contains("ias_activate");
        boolean doIasRestoreGroups = req.actions.contains("ias_restore_groups");
        boolean doXsuaaRestore    = req.actions.contains("xsuaa_restore_roles");
        boolean doCfRestore       = req.actions.contains("cf_restore_org_roles");
        boolean wantsIas = doIasActivate || doIasRestoreGroups;
        boolean wantsSa = doXsuaaRestore || doCfRestore;

        UUID correlationId = req.correlationId != null ? req.correlationId : UUID.randomUUID(); //usr input -> but is fine
        support.emitComment(correlationId, req.userEmail, actor, source, "unlock", req.comment);
        List<Subaccount> sas = wantsSa ? support.resolveSubaccountList(req.subaccountIds) : List.of();
        boolean dryRun = req.dryRun != null ? req.dryRun : true;
        List<UUID> tenantIds = wantsIas ? support.resolveTenantList(req.iasTenantIds) : List.of();

        if (sas.isEmpty() && tenantIds.isEmpty()) {
            throw new IllegalArgumentException(ContainmentMessages.NOTHING_TO_UNLOCK);
        }

        List<ActionResult> iasResults = new ArrayList<>();
        for (UUID tenantId : tenantIds) {
            String iasJson;
            try {
                iasJson = new String(iasTenants.decryptCreds(tenantId), StandardCharsets.UTF_8);
            } catch (NoSuchElementException e) {
                String action = doIasActivate ? "ias_activate" : "ias_restore_groups";
                iasResults.add(new ActionResult(action, "failed",
                        "IAS tenant " + tenantId + " not found", null));
                continue;
            }
            String iasUserId = null;
            try {
                Optional<IasClient.IasUser> u = ias.findUserByEmail(iasJson, req.userEmail);
                if (u.isEmpty()) { //user needs to exist as only activate / deactivate is possible -> don't want to store surname/lastname and stuff
                    String action = doIasActivate ? "ias_activate" : "ias_restore_groups";
                    iasResults.add(new ActionResult(action, "skipped",
                            "IAS user not found for " + req.userEmail + " in tenant " + tenantId, null));
                    continue;
                }
                iasUserId = u.get().id();
                if (doIasActivate) {
                    Optional<SnapshotRepo.Latest> snap = snapshots.findLatestUnconsumed(
                            IAuditForward.SystemType.IAS, tenantId.toString(), iasUserId,
                            SnapshotRepo.SnapshotKind.IAS_USER_STATE);
                    if (snap.isEmpty()) {
                        iasResults.add(new ActionResult("ias_activate", "skipped",
                                "no unconsumed IAS snapshot for user in tenant " + tenantId, null));
                    } else {
                        iasResults.add(replayIasActivateTenant(tenantId, iasJson, req,
                                correlationId, iasUserId, snap.get(), dryRun, actor, source));
                    }
                }
                if (doIasRestoreGroups) {
                    iasResults.add(replayIasRestoreGroupsTenant(tenantId, iasJson, req,
                            correlationId, iasUserId, dryRun, actor, source));
                }
            } catch (Exception e) {
                String action = doIasActivate ? "ias_activate" : "ias_restore_groups";
                log.warn("{} failed for tenant {}", action, tenantId, e);
                iasResults.add(new ActionResult(action, "failed", e.getMessage(), null));
                support.emitLog(correlationId, tenantId.toString(), req.userEmail, iasUserId, action,
                        actor, source, Outcome.FAILED, e.getMessage(),
                        Map.of("iasTenantId", tenantId.toString()), IAuditForward.SystemType.IAS);
            }
        }

        List<SubaccountResult> perSubaccount = new ArrayList<>();
        for (Subaccount sa : sas) {
            perSubaccount.add(unlockOneSubaccount(sa, req, correlationId, dryRun,
                    doXsuaaRestore, doCfRestore, actor, source));
        }

        return new UnlockResult(correlationId, dryRun, tenantIds, iasResults, perSubaccount);
    }

    private void validate(UnlockRequest ureq) {
        if (ureq == null) throw new IllegalArgumentException("body is required");
        if (ureq.userEmail == null || ureq.userEmail.isBlank()) {
            throw new IllegalArgumentException("userEmail is required");
        }
        if (ureq.actions == null || ureq.actions.isEmpty()) {
            throw new IllegalArgumentException(
                    "actions is required and must be non-empty; allowed: " + ALLOWED_ACTIONS);
        }
        for (String a : ureq.actions) {
            if (!ALLOWED_ACTIONS.contains(a)) {
                throw new IllegalArgumentException(
                        "unknown action '" + a + "'; allowed: " + ALLOWED_ACTIONS);
            }
        }
    }

    private SubaccountResult unlockOneSubaccount(Subaccount sa, UnlockRequest req, UUID corr,
                                                 boolean dryRun, boolean doXsuaaRestore,
                                                 boolean doCfRestore, String actor, ActorSource source) {
        List<ActionResult> results = new ArrayList<>();

        if (doXsuaaRestore) {
            String xsuaaJson = support.tryLoadCredential(sa.id(), CredentialKind.XSUAA_APIACCESS);
            if (xsuaaJson != null) {
                try {
                    Optional<SnapshotRepo.Latest> snap = snapshots.findLatestUnconsumed(
                            IAuditForward.SystemType.SUBACCOUNT, sa.id().toString(), req.userEmail,
                            SnapshotRepo.SnapshotKind.ROLE_COLLECTIONS);
                    if (snap.isPresent()) {
                        results.add(replayRestoreRoles(sa, req, corr, xsuaaJson,
                                snap.get(), dryRun, actor, source));
                    } else {
                        results.add(new ActionResult("xsuaa_restore_roles", "skipped",
                                "no unconsumed role-collection snapshot for this user", null));
                    }
                } catch (Exception e) {
                    log.warn("xsuaa unlock failed for subaccount {}", sa.id(), e);
                    results.add(new ActionResult("xsuaa_restore_roles", "failed", e.getMessage(), null));
                    support.emitLog(corr, sa.id().toString(), req.userEmail, null, "xsuaa_restore_roles",
                            actor, source, Outcome.FAILED, e.getMessage(), null, IAuditForward.SystemType.SUBACCOUNT);
                }
            }
        }

        if (doCfRestore) {
            String cfJson = support.tryLoadCredential(sa.id(), CredentialKind.CF_TECHNICAL_USER);
            if (cfJson != null) {
                results.add(replayCfRolesIfAny(sa, req, corr, cfJson,
                        SnapshotRepo.SnapshotKind.CF_ORG_ROLES,
                        "cf_restore_org_roles", dryRun, actor, source));
            }
        }

        return new SubaccountResult(sa.id(), sa.cisDisplayName(), false, results, List.of());
    }

    private ActionResult replayIasActivateTenant(UUID iasTenantId, String iasJson,
                                                 UnlockRequest req, UUID corr, String iasUserId,
                                                 SnapshotRepo.Latest snap, boolean dryRun,
                                                 String actor, ActorSource source) {
        Outcome outcome;
        String msg;
        if (dryRun) {
            outcome = Outcome.DRY_RUN;
            msg = "would PATCH active=true on IAS user " + iasUserId;
        } else {
            ias.setActive(iasJson, iasUserId, true);
            snapshots.markConsumed(snap.id());
            outcome = Outcome.OK;
            msg = "IAS user " + iasUserId + " reactivated; snapshot " + snap.id() + " consumed";
        }
        support.emitLog(corr, iasTenantId.toString(), req.userEmail, iasUserId, "ias_activate",
                actor, source, outcome, null,
                Map.of("snapshotId", snap.id().toString(),
                        "dryRun", dryRun,
                        "iasTenantId", iasTenantId.toString()), IAuditForward.SystemType.IAS);
        return ActionResult.of("ias_activate", outcome, msg, snap.id());
    }

    private ActionResult replayIasRestoreGroupsTenant(UUID iasTenantId, String iasJson,
                                                      UnlockRequest req, UUID corr,
                                                      String iasUserId, boolean dryRun,
                                                      String actor, ActorSource source) {
        Optional<SnapshotRepo.Latest> snap = snapshots.findLatestUnconsumed(
                IAuditForward.SystemType.IAS, iasTenantId.toString(), iasUserId,
                SnapshotRepo.SnapshotKind.IAS_USER_GROUPS);
        if (snap.isEmpty()) {
            return new ActionResult("ias_restore_groups", "skipped",
                    "no unconsumed IAS group snapshot for this user in tenant " + iasTenantId, null);
        }
        JsonNode payload;
        try { payload = mapper.readTree(snap.get().payloadJson()); }
        catch (Exception e) {
            return new ActionResult("ias_restore_groups", "failed",
                    "snapshot payload not parseable: " + e.getMessage(), snap.get().id());
        }
        JsonNode arr = payload.path("groups");
        if (!arr.isArray() || arr.isEmpty()) {
            snapshots.markConsumed(snap.get().id());
            return new ActionResult("ias_restore_groups", "skipped",
                    "snapshot " + snap.get().id() + " has no groups to replay", snap.get().id());
        }
        Outcome outcome;
        String msg;
        int total = arr.size();
        if (dryRun) {
            outcome = Outcome.DRY_RUN;
            msg = "would re-add user to " + total + " IAS group(s)";
        } else {
            int restored = 0;
            List<String> failed = new ArrayList<>();
            for (JsonNode g : arr) {
                String groupId = g.path("id").asText(null);
                if (groupId == null) continue;
                try {
                    ias.addUserToGroup(iasJson, groupId, iasUserId);
                    restored++;
                } catch (Exception e) {
                    failed.add(groupId + ": " + e.getMessage());
                    log.warn("ias addUserToGroup failed for group {}: {}",
                            groupId, e.getMessage());
                }
            }
            snapshots.markConsumed(snap.get().id());
            outcome = failed.isEmpty() ? Outcome.OK : Outcome.PARTIAL;
            msg = "re-added user to " + restored + "/" + total + " IAS group(s)"
                    + (failed.isEmpty() ? "" : "; failed: " + String.join("; ", failed));
        }
        support.emitLog(corr, iasTenantId.toString(), req.userEmail, iasUserId, "ias_restore_groups",
                actor, source, outcome, null,
                Map.of("snapshotId", snap.get().id().toString(),
                        "dryRun", dryRun,
                        "iasTenantId", iasTenantId.toString(),
                        "groupCount", total), IAuditForward.SystemType.IAS);
        return ActionResult.of("ias_restore_groups", outcome, msg, snap.get().id());
    }

    private ActionResult replayCfRolesIfAny(Subaccount sa, UnlockRequest req, UUID corr,
                                            String cfJson, SnapshotRepo.SnapshotKind kind,
                                            String actionName, boolean dryRun,
                                            String actor, ActorSource source) {
        if (!snapshots.hasAnyUnconsumed(IAuditForward.SystemType.SUBACCOUNT, sa.id().toString(), kind)) {
            return new ActionResult(actionName, "skipped",
                    "no unconsumed " + kind.dbValue() + " snapshot for this subaccount", null);
        }
        List<CfApiClient.CfUser> cfUsers;
        try {
            cfUsers = support.resolveCfUsers(cfJson, req.userEmail, null);
        } catch (CfUserNotFoundException e) {
            log.info("cf unlock {} skipped for subaccount {}: {}",
                    actionName, sa.id(), e.getMessage());
            return new ActionResult(actionName, "skipped", e.getMessage(), null);
        }

        List<String> perUserMessages = new ArrayList<>();
        int replayedUsers = 0;
        int failedUsers = 0;
        for (CfApiClient.CfUser cfUser : cfUsers) {
            Optional<SnapshotRepo.Latest> snap = snapshots.findLatestUnconsumed(
                    IAuditForward.SystemType.SUBACCOUNT, sa.id().toString(), cfUser.guid(), kind);
            if (snap.isEmpty()) continue;
            try {
                ActionResult r = replayCfRoles(sa, req, corr, cfJson, cfUser, snap.get(),
                        kind, actionName, dryRun, actor, source);
                perUserMessages.add(cfUser.guid() + "@" + cfUser.origin() + ": " + r.message());
                if ("failed".equals(r.outcome())) failedUsers++; else replayedUsers++;
            } catch (Exception e) {
                log.warn("cf unlock {} failed for user {}", actionName, cfUser.guid(), e);
                perUserMessages.add(cfUser.guid() + "@" + cfUser.origin() + ": " + e.getMessage());
                support.emitLog(corr, sa.id().toString(), req.userEmail, cfUser.guid(), actionName,
                        actor, source, Outcome.FAILED, e.getMessage(), null, IAuditForward.SystemType.SUBACCOUNT);
                failedUsers++;
            }
        }
        if (replayedUsers == 0 && failedUsers == 0) {
            return new ActionResult(actionName, "skipped",
                    "no unconsumed " + kind.dbValue() + " snapshot matched any CF user for "
                            + req.userEmail + " (" + cfUsers.size() + " match"
                            + (cfUsers.size() == 1 ? "" : "es") + " checked)", null);
        }
        String outcome;
        if (dryRun)                  outcome = "dry-run";
        else if (failedUsers == 0)   outcome = "ok";
        else if (replayedUsers == 0) outcome = "failed";
        else                         outcome = "partial";
        String prefix = dryRun
                ? "would replay " + replayedUsers + "/" + (replayedUsers + failedUsers)
                  + " CF user snapshot(s); "
                : "replayed " + replayedUsers + "/" + (replayedUsers + failedUsers)
                  + " CF user snapshot(s); ";
        return new ActionResult(actionName, outcome, prefix + String.join(" | ", perUserMessages), null);
    }

    private ActionResult replayCfRoles(Subaccount sa, UnlockRequest req, UUID corr,
                                       String cfJson, CfApiClient.CfUser cfUser,
                                       SnapshotRepo.Latest snap, SnapshotRepo.SnapshotKind kind,
                                       String actionName, boolean dryRun,
                                       String actor, ActorSource source) {
        JsonNode payload;
        try { payload = mapper.readTree(snap.payloadJson()); }
        catch (Exception e) {
            throw new IllegalStateException("snapshot " + snap.id() + " payload is not valid JSON", e);
        }
        JsonNode roles = payload.path("roles");
        if (!roles.isArray() || roles.isEmpty()) {
            snapshots.markConsumed(snap.id());
            return new ActionResult(actionName, "skipped",
                    "snapshot " + snap.id() + " has no roles to replay", snap.id());
        }
        List<JsonNode> ordered = new ArrayList<>();
        for (JsonNode r : roles) {
            boolean isSpace = !r.path("spaceGuid").isMissingNode() && !r.path("spaceGuid").isNull();
            if (isSpace) continue;
            if ("organization_user".equals(r.path("type").asText())) ordered.add(r);
        }
        for (JsonNode r : roles) {
            boolean isSpace = !r.path("spaceGuid").isMissingNode() && !r.path("spaceGuid").isNull();
            if (isSpace) continue;
            if (!"organization_user".equals(r.path("type").asText())) ordered.add(r);
        }
        boolean hasOrgUser = ordered.stream()
                .anyMatch(r -> "organization_user".equals(r.path("type").asText()));
        if (!hasOrgUser && !ordered.isEmpty()) {
            String orgGuid = ordered.get(0).path("orgGuid").asText(null);
            if (orgGuid != null) {
                com.fasterxml.jackson.databind.node.ObjectNode synthetic = mapper.createObjectNode();
                synthetic.put("orgGuid", orgGuid);
                synthetic.put("type", "organization_user");
                ordered.add(0, synthetic);
            }
        }

        Outcome outcome;
        String msg;
        if (dryRun) {
            outcome = Outcome.DRY_RUN;
            msg = "would re-grant " + ordered.size() + " org role(s)";
        } else {
            int restored = 0;
            int failed = 0;
            for (JsonNode r : ordered) {
                String type = r.path("type").asText();
                String orgGuid = r.path("orgGuid").asText(null);
                try {
                    cf.grantRole(cfJson, type, cfUser.guid(), orgGuid, null);
                    restored++;
                } catch (Exception e) {
                    String emsg = e.getMessage() == null ? "" : e.getMessage().toLowerCase();
                    if (emsg.contains("already") || emsg.contains("422")) {
                        log.info("cf createRole {} skipped: {}", type, e.getMessage());
                        restored++;
                    } else {
                        log.warn("cf createRole {} failed: {}", type, e.getMessage());
                        failed++;
                    }
                }
            }
            snapshots.markConsumed(snap.id());
            outcome = failed == 0 ? Outcome.OK : Outcome.PARTIAL;
            msg = "re-granted " + restored + " org role(s)"
                    + (failed == 0 ? "" : " (" + failed + " failed)");
        }
        support.emitLog(corr, sa.id().toString(), req.userEmail, cfUser.guid(), actionName,
                actor, source, outcome, null,
                Map.of("snapshotId", snap.id().toString(), "dryRun", dryRun,
                        "rolesRestored", roles.size()), IAuditForward.SystemType.SUBACCOUNT);
        return ActionResult.of(actionName, outcome, msg, snap.id());
    }

    private ActionResult replayRestoreRoles(Subaccount sa, UnlockRequest req, UUID corr,
                                            String xsuaaJson, SnapshotRepo.Latest snap,
                                            boolean dryRun, String actor, ActorSource source) {
        JsonNode payload;
        try { payload = mapper.readTree(snap.payloadJson()); }
        catch (Exception e) {
            throw new IllegalStateException("snapshot " + snap.id() + " payload is not valid JSON", e);
        }

        List<Map.Entry<String, List<String>>> perOrigin = new ArrayList<>();
        if (payload.has("perOrigin") && payload.get("perOrigin").isArray()) {
            for (JsonNode entry : payload.get("perOrigin")) {
                extract(perOrigin, entry);
            }
        } else {
            extract(perOrigin, payload);
        }

        int totalRoles = perOrigin.stream().mapToInt(e -> e.getValue().size()).sum();
        Outcome outcome;
        String msg;
        if (dryRun) {
            outcome = Outcome.DRY_RUN;
            msg = "would re-assign " + totalRoles + " role collection(s) across "
                    + perOrigin.size() + " origin(s)";
        } else {
            Map<String, String> groupIdByName = new HashMap<>();
            for (XsuaaScimClient.Group g : xsuaa.listGroups(xsuaaJson)) {
                if (g.id() != null && g.displayName() != null) {
                    groupIdByName.put(g.displayName(), g.id());
                }
            }
            Map<String, String> userIdByOrigin = new HashMap<>();
            for (XsuaaScimClient.ShadowUser s : xsuaa.findShadowUsersByEmail(xsuaaJson, req.userEmail)) {
                if (s.origin() != null && s.id() != null) userIdByOrigin.put(s.origin(), s.id());
            }

            int restored = 0;
            List<String> skipReasons = new ArrayList<>();
            List<String> recreatedOrigins = new ArrayList<>();
            for (Map.Entry<String, List<String>> e : perOrigin) {
                String userId = userIdByOrigin.get(e.getKey());
                if (userId == null) {
                    if (e.getValue().isEmpty()) {
                        skipReasons.add("no shadow user at origin " + e.getKey()
                                + " and snapshot has no roles to re-grant");
                        continue;
                    }
                    try {
                        XsuaaScimClient.ShadowUser created =
                                xsuaa.createShadowUser(xsuaaJson, req.userEmail, e.getKey());
                        userId = created.id();
                        userIdByOrigin.put(e.getKey(), userId);
                        recreatedOrigins.add(e.getKey());
                        log.info("xsuaa_restore_roles: recreated shadow user {} at origin {} for {}",
                                userId, e.getKey(), req.userEmail);
                    } catch (Exception createEx) {
                        skipReasons.add("could not recreate shadow at origin "
                                + e.getKey() + ": " + createEx.getMessage());
                        continue;
                    }
                }
                for (String rc : e.getValue()) {
                    String groupId = groupIdByName.get(rc);
                    if (groupId == null) {
                        skipReasons.add("role collection '" + rc + "' no longer exists");
                        continue;
                    }
                    xsuaa.addMember(xsuaaJson, groupId, userId, e.getKey());
                    restored++;
                }
            }
            snapshots.markConsumed(snap.id());
            outcome = restored == totalRoles ? Outcome.OK : Outcome.PARTIAL;
            msg = "restored " + restored + "/" + totalRoles + " role collection(s) across "
                    + perOrigin.size() + " origin(s); snapshot " + snap.id() + " consumed"
                    + (recreatedOrigins.isEmpty() ? ""
                            : "; recreated shadow at: " + String.join(", ", recreatedOrigins))
                    + (skipReasons.isEmpty() ? "" : "; skipped: " + String.join("; ", skipReasons));
        }
        support.emitLog(corr, sa.id().toString(), req.userEmail, null, "xsuaa_restore_roles",
                actor, source, outcome, null,
                Map.of("snapshotId", snap.id().toString(),
                        "dryRun", dryRun,
                        "origins", perOrigin.stream().map(Map.Entry::getKey).toList(),
                        "totalRolesRestored", totalRoles), IAuditForward.SystemType.SUBACCOUNT);
        return ActionResult.of("xsuaa_restore_roles", outcome, msg, snap.id());
    }

    private void extract(List<Map.Entry<String, List<String>>> perOrigin, JsonNode entry) {
        String origin = entry.path("origin").asText("ias");
        List<String> rcs = new ArrayList<>();
        JsonNode arr = entry.path("roleCollections");
        if (arr.isArray()) for (JsonNode n : arr) rcs.add(n.asText());
        perOrigin.add(Map.entry(origin, rcs));
    }

    public List<UnlockPreviewEntry> previewUnlock(String userEmail, List<UUID> subaccountIds) {
        if (userEmail == null || userEmail.isBlank()) {
            throw new IllegalArgumentException("userEmail is required");
        }
        List<UUID> ids = (subaccountIds != null && !subaccountIds.isEmpty())
                ? subaccountIds
                : subaccounts.list().stream().map(Subaccount::id).toList();
        List<UnlockPreviewEntry> out = new ArrayList<>();
        for (UUID sid : ids) {
            Subaccount sa;
            try { sa = subaccounts.get(sid); }
            catch (NoSuchElementException e) { continue; }
            Optional<SnapshotRepo.Latest> snap = snapshots.findLatestUnconsumed(
                    IAuditForward.SystemType.SUBACCOUNT, sa.id().toString(), userEmail,
                    SnapshotRepo.SnapshotKind.ROLE_COLLECTIONS);
            if (snap.isEmpty()) {
                out.add(new UnlockPreviewEntry(sa.id(), sa.cisDisplayName(), null,
                        List.of(), 0, "no unconsumed role-collection snapshot for this user"));
                continue;
            }
            try {
                JsonNode payload = mapper.readTree(snap.get().payloadJson());
                List<UnlockPreviewOrigin> perOrigin = new ArrayList<>();
                int total = 0;
                JsonNode arr = payload.path("perOrigin");
                if (arr.isArray() && !arr.isEmpty()) {
                    for (JsonNode e : arr) {
                        List<String> rcs = new ArrayList<>();
                        for (JsonNode n : e.path("roleCollections")) rcs.add(n.asText());
                        perOrigin.add(new UnlockPreviewOrigin(e.path("origin").asText("ias"), rcs));
                        total += rcs.size();
                    }
                } else {
                    List<String> rcs = new ArrayList<>();
                    for (JsonNode n : payload.path("roleCollections")) rcs.add(n.asText());
                    perOrigin.add(new UnlockPreviewOrigin(
                            payload.path("origin").asText("ias"), rcs));
                    total += rcs.size();
                }
                out.add(new UnlockPreviewEntry(sa.id(), sa.cisDisplayName(),
                        snap.get().id(), perOrigin, total, null));
            } catch (Exception e) {
                out.add(new UnlockPreviewEntry(sa.id(), sa.cisDisplayName(), snap.get().id(),
                        List.of(), 0, "snapshot payload not parseable: " + e.getMessage()));
            }
        }
        return out;
    }
}
