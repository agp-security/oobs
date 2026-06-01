// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.domain;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

public record ConflictSet(
        UUID id,
        String name,
        String description,
        String severity,// low / medium / high / critical
        String kind,  // sod | critical | threshold
        List<String> roleCollections,
        Integer thresholdCount,  // only meaningful when kind = 'threshold'
        boolean enabled,
        String scopeLevel,   // subaccount | space | org | global
        String createdBy,
        OffsetDateTime createdAt,
        OffsetDateTime updatedAt
) {}
