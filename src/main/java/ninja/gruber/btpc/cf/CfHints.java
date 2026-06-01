// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.cf;

final class CfHints {

    private CfHints() {}

    static final String EXTENDED_LANDSCAPE =
            "BTP landscape split: the technical user exists on "
                    + "the main landscape (<region><id> - e.g. us10) but not yet on the extended "
                    + "landscape where this service is provisioned (<region><extended id> - e.g. us10-001).";

    static final String QUOTA_EXHAUSTED =
            "CF / BTP quota exhausted in the target org or space. Add "
                    + "the entitlement in the BTP cockpit (Entitlements -> "
                    + "Cloud Foundry / XSUAA) or delete a stale instance.";

    static final String INSTANCE_NAME_COLLISION =
            "Instance name collision: an existing instance is using "
                    + "the same name. Auto-provision normally reuses it... "
                    + "Delete it manually then re-run.";

    static final String MISSING_SPACE_DEVELOPER =
            " Most likely cause: the technical user lacks the "
                    + "SpaceDeveloper role in the target CF space or misses a Org role. "
                    + "Grant it via 'cf set-space-role <user> <org> <space> SpaceDeveloper' "
                    + "or in the BTP cockpit -> Cloud Foundry -> Spaces -> Members (+same for org).";

    static String forUpstreamDetail(String upstreamDetail) {
        if (upstreamDetail == null) return "";
        String lower = upstreamDetail.toLowerCase();
        if (lower.contains("extended landscape")) return EXTENDED_LANDSCAPE;
        if (lower.contains("quota") || lower.contains("limit exceeded")) return QUOTA_EXHAUSTED;
        if (lower.contains("service instance with name") && lower.contains("already exists")) {
            return INSTANCE_NAME_COLLISION;
        }
        return "";
    }
}
