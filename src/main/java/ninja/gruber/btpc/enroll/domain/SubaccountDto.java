// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.enroll.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import ninja.gruber.btpc.domain.CredentialKind;
import ninja.gruber.btpc.domain.Subaccount;

import java.time.OffsetDateTime;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record SubaccountDto(
        UUID id,
        UUID subaccountGuid,
        String cisDisplayName,
        OffsetDateTime cisDisplayNameRefreshedAt,
        String label,
        String region,
        UUID globalAccountId,
        String globalAccountName,
        String stage,
        String enrolledBy,
        OffsetDateTime enrolledAt,
        OffsetDateTime lastHealthAt,
        String lastHealthError,
        String status,
        UUID cfOrgId,
        Capabilities capabilities,
        Integer contactCount
) {
    public static SubaccountDto from(Subaccount s, Set<CredentialKind> kinds, int contactCount) {
        return new SubaccountDto(
                s.id(), s.subaccountGuid(),
                s.cisDisplayName(), s.cisDisplayNameRefreshedAt(),
                s.label(), s.region(),
                s.globalAccountId(), s.globalAccountName(), s.stage(),
                s.enrolledBy(), s.enrolledAt(),
                s.lastHealthAt(), s.lastHealthError(), s.status(),
                s.cfOrgId(),
                Capabilities.from(kinds == null ? EnumSet.noneOf(CredentialKind.class) : kinds),
                contactCount);
    }

    public static SubaccountDto from(Subaccount s) {
        return from(s, EnumSet.noneOf(CredentialKind.class), 0);
    }

    public static List<SubaccountDto> fromAll(List<Subaccount> all,
                                              Map<UUID, Set<CredentialKind>> capabilities,
                                              Map<UUID, Integer> contactCounts) {
        return all.stream()
                .map(s -> from(s,
                        capabilities.getOrDefault(s.id(), EnumSet.noneOf(CredentialKind.class)),
                        contactCounts.getOrDefault(s.id(), 0)))
                .toList();
    }

    public record Capabilities(boolean cis, boolean xsuaaApiaccess, boolean cfTechnicalUser) {
        public static Capabilities from(Set<CredentialKind> kinds) {
            return new Capabilities(
                    kinds.contains(CredentialKind.CIS),
                    kinds.contains(CredentialKind.XSUAA_APIACCESS),
                    kinds.contains(CredentialKind.CF_TECHNICAL_USER));
        }
    }
}
