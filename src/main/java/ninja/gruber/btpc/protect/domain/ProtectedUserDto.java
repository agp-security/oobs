// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.protect.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import ninja.gruber.btpc.domain.ProtectedUser;

import java.time.OffsetDateTime;
import java.util.UUID;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ProtectedUserDto(
        UUID id,
        UUID subaccountId,
        UUID iasTenantId,
        String userEmail,
        String reason,
        String origin,
        String addedBy,
        OffsetDateTime addedAt,
        OffsetDateTime expiresAt,
        boolean enabled,
        OffsetDateTime disabledAt,
        String disabledBy,
        boolean isGlobal,
        boolean isSubaccount,
        boolean isIasTenant
) {
    public static ProtectedUserDto from(ProtectedUser p) {
        return new ProtectedUserDto(
                p.id(),
                p.subaccountId(),
                p.iasTenantId(),
                p.userEmail(),
                p.reason(),
                p.origin().dbValue(),
                p.addedBy(),
                p.addedAt(),
                p.expiresAt(),
                p.enabled(),
                p.disabledAt(),
                p.disabledBy(),
                p.isGlobal(),
                p.isSubaccount(),
                p.isIasTenant());
    }
}
