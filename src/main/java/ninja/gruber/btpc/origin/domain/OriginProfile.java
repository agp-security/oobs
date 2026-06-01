// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.origin.domain;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

public record OriginProfile(
        UUID id,
        String name,
        String description,
        List<String> originKeys,
        OffsetDateTime createdAt,
        String createdBy,
        OffsetDateTime updatedAt,
        String updatedBy
) {}
