// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.domain;

import java.time.OffsetDateTime;
import java.util.UUID;

public record Subaccount(
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
        UUID cfOrgId
) {}
