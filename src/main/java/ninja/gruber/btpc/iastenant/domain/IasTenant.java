// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.iastenant.domain;

import java.time.OffsetDateTime;
import java.util.UUID;

public record IasTenant(
        UUID id,
        String displayName,
        String iasHost,
        OffsetDateTime createdAt,
        String createdBy,
        OffsetDateTime updatedAt,
        String updatedBy
) {}
