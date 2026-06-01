// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.audit.postgres;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import ninja.gruber.btpc.audit.IAuditForward;
import org.jooq.DSLContext;
import org.jooq.JSONB;
import org.springframework.stereotype.Component;

import java.util.UUID;

import static ninja.gruber.btpc.jooq.Tables.CONTAINMENT_EVENTS;
import static org.jooq.impl.DSL.currentOffsetDateTime;

@Component
public class PostgresAuditSecondarySink implements IAuditForward {

    private final DSLContext dsl;
    private final ObjectMapper mapper;

    public PostgresAuditSecondarySink(DSLContext dsl, ObjectMapper mapper) {
        this.dsl = dsl;
        this.mapper = mapper;
    }

    @Override
    public void record(AuditEvent e) {
        dsl.insertInto(CONTAINMENT_EVENTS)
                .set(CONTAINMENT_EVENTS.ID,                UUID.randomUUID())
                .set(CONTAINMENT_EVENTS.CORRELATION_ID,    e.correlationId())
                .set(CONTAINMENT_EVENTS.SYSTEM_ID,         e.systemId())
                .set(CONTAINMENT_EVENTS.SYSTEM_TYPE,       e.systemType().toString())
                .set(CONTAINMENT_EVENTS.TARGET_USER_EMAIL,
                        e.targetUserEmail() == null ? "" : e.targetUserEmail())
                .set(CONTAINMENT_EVENTS.TARGET_USER_ID,    e.targetUserId())
                .set(CONTAINMENT_EVENTS.ACTION,            e.action())
                .set(CONTAINMENT_EVENTS.ACTOR,             e.actor())
                .set(CONTAINMENT_EVENTS.ACTOR_SOURCE,
                        e.actorSource().name().toLowerCase().replace('_', '-'))
                .set(CONTAINMENT_EVENTS.OUTCOME,
                        e.outcome().name().toLowerCase().replace('_', '-'))
                .set(CONTAINMENT_EVENTS.ERROR_MESSAGE,     e.errorMessage())
                .set(CONTAINMENT_EVENTS.DETAILS,
                        e.details() == null ? null : JSONB.valueOf(toJson(e.details())))
                .set(CONTAINMENT_EVENTS.FINISHED_AT,       currentOffsetDateTime())
                .execute();
    }

    private String toJson(Object value) {
        try {
            return mapper.writeValueAsString(value);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("failed to serialise audit details", ex);
        }
    }
}
