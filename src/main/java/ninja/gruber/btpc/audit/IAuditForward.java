// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.audit;

import java.util.Map;
import java.util.UUID;

public interface IAuditForward {

    void record(AuditEvent event);

    enum Outcome { OK, PARTIAL, FAILED, DRY_RUN, SKIPPED }

    enum ActorSource { UI, SOAR_API, SYSTEM }

    enum SystemType { IAS, SUBACCOUNT, ONPREM, INTERNAL }

    record AuditEvent(
            UUID correlationId,
            String systemId,
            SystemType systemType,
            String targetUserEmail,
            String targetUserId,
            String action,
            String actor,
            ActorSource actorSource,
            Outcome outcome,
            String errorMessage,
            Map<String, Object> details
    ) {}
}
