// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.domain;

import java.time.OffsetDateTime;
import java.util.UUID;

public record SubaccountContact(
        UUID id,
        UUID subaccountId,
        String name,
        String email,
        String role, // security|ops|business|technical|other
        String notes,
        String createdBy,
        OffsetDateTime createdAt,
        OffsetDateTime updatedAt
) {}
