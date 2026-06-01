// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.containment;

final class ContainmentMessages {

    private ContainmentMessages() {}

    static final String NOTHING_TO_CONTAIN =
            "nothing to contain as no subaccounts selected and the IAS step is disabled "
                    + "(or no IAS tenants enrolled).";

    static final String NOTHING_TO_UNLOCK =
            "nothing to unlock: no subaccounts selected and the IAS step disabled (or no snapshot).";

    static String noCfOrgIdConfigured(String displayName) {
        return "no cf_org_id configured on subaccount " + displayName
                + " -> set it in the Edit tab of the UI or call the api endpoint.";
    }

    static String cfUserNotFoundHint(int orgsScanned, int spacesScanned, int uniqueUsersSeen) {
        if (orgsScanned == 0) {
            return " -> WARNING: LIKELY the CF technical user is not a member of any org.";
        }
        if (spacesScanned == 0) {
            return " -> WARNING: technical user can see " + orgsScanned
                    + " org(s) but no spaces in them (-> grant SpaceAuditor / "
                    + "SpaceDeveloper in the relevant space).";
        }
        if (uniqueUsersSeen == 0) {
            return " -> WARNING: technical user can see the org/space(s) but no users are "
                    + "assigned to roles there (the space exists but is empty). "
                    + "Confirm the user has at least one role binding in this CF org.";
        }
        return " -> WARNING: visibility for the technical user is fine; the email genuinely doesn't likely exist in this CF "
                + "landscape under any visible role binding. Check the address "
                + "or whether the user is in a different subaccount/IAS.";
    }
}
