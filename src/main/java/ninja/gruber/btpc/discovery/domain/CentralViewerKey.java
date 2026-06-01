// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.discovery.domain;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.OffsetDateTime;
import java.util.UUID;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record CentralViewerKey(
        UUID id,
        UUID globalAccountId,
        String globalAccountName,
        String label,
        int keyVersion,
        boolean syncEnabled,
        int syncIntervalMinutes,
        OffsetDateTime lastSyncAt,
        String lastSyncError,
        Integer lastSyncCount,
        String addedBy,
        OffsetDateTime addedAt
) {}
