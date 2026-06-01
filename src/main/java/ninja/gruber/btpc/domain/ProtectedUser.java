// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.domain;

import java.time.OffsetDateTime;
import java.util.UUID;

public record ProtectedUser(
        UUID id,
        UUID subaccountId,
        UUID iasTenantId,
        String userEmail,
        String reason,
        ProtectedUserOrigin origin,
        String addedBy,
        OffsetDateTime addedAt,
        OffsetDateTime expiresAt,    // nullable
        boolean enabled,
        OffsetDateTime disabledAt,   // nullable
        String disabledBy            // nullable
) {
    public boolean isGlobal()       { return subaccountId == null && iasTenantId == null; }
    public boolean isSubaccount()   { return subaccountId != null; }
    public boolean isIasTenant()    { return iasTenantId != null; }
}
