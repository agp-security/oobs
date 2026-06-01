// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.containment.domain;

import ninja.gruber.btpc.audit.IAuditForward.Outcome;

import java.util.List;
import java.util.UUID;

public final class ContainmentDtos {

    private ContainmentDtos() {}

    public static class ContainRequest {
        // Per-SA actions (run once per resolved subaccount):
        //   xsuaa_strip_roles, xsuaa_delete_shadow, cf_revoke_org_roles
        // Per-IAS-tenant actions (run once per resolved IAS tenant):
        //   ias_deactivate, ias_strip_groups
        // Required, must be non-empty.
        public List<String> actions;
        // Null/empty -> all enrolled subaccounts (only used if a per-SA action is requested).
        public List<UUID> subaccountIds;
        // Null/empty -> all enrolled IAS tenants (only used if an IAS action is requested).
        public List<UUID> iasTenantIds;
        public String userEmail;
        public String originMode;       // "all" | "list" | "discovered"
        public List<String> origins;
        public Boolean dryRun;          // default true
        public String comment;
    }

    public static class UnlockRequest {
        // Per-SA actions: xsuaa_restore_roles, cf_restore_org_roles
        // Per-IAS-tenant actions: ias_activate, ias_restore_groups
        // Required, must be non-empty.
        public List<String> actions;
        public List<UUID> subaccountIds;
        public List<UUID> iasTenantIds;
        public String userEmail;
        public UUID correlationId;
        public Boolean dryRun;
        public String comment;
    }

    public record ActionResult(String action, String outcome, String message, UUID snapshotId) {
        public static ActionResult of(String action, Outcome outcome, String message, UUID snapshotId) {
            return new ActionResult(action, outcome.name().toLowerCase().replace('_', '-'), message, snapshotId);
        }
    }

    public record SubaccountResult(
            UUID subaccountId,
            String displayName,
            boolean blockedByProtection,
            List<ActionResult> results,
            List<String> protectionReasons
    ) {}

    public record ContainmentResult(
            UUID correlationId,
            boolean dryRun,
            List<UUID> resolvedIasTenantIds,
            List<ActionResult> iasResults,          // one entry per selected tenant
            List<SubaccountResult> perSubaccount,
            // Non-empty -> request was hard-blocked by a global protection;
            // iasResults and perSubaccount will be empty. Null/empty otherwise.
            List<String> globalProtectionReasons
    ) {}

    public record UnlockResult(
            UUID correlationId,
            boolean dryRun,
            List<UUID> resolvedIasTenantIds,
            List<ActionResult> iasResults,          // one per tenant
            List<SubaccountResult> perSubaccount
    ) {}

    public record UnlockPreviewEntry(
            UUID subaccountId, String displayName, UUID snapshotId,
            List<UnlockPreviewOrigin> perOrigin, int totalRoles, String note) {}

    public record UnlockPreviewOrigin(String origin, List<String> roleCollections) {}
}
