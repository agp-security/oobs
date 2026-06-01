// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.discovery.domain;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.OffsetDateTime;
import java.util.UUID;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record DiscoveredSubaccount(
        UUID id,
        UUID centralKeyId,
        UUID subaccountGuid,
        String displayName,
        String subdomain,
        String region,
        String parentType,
        UUID parentGuid,
        UUID globalAccountGuid,
        String state,
        String stateMessage,
        Boolean betaEnabled,
        String usedForProduction,
        String description,
        OffsetDateTime discoveredAt,
        OffsetDateTime lastSeenAt,
        UUID enrolledSubaccountId          // derived from JOIN; null = promotable
) {}
