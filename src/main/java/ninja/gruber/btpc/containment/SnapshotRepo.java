// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.containment;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import ninja.gruber.btpc.audit.IAuditForward.SystemType;
import org.jooq.DSLContext;
import org.jooq.JSONB;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

import static ninja.gruber.btpc.jooq.Tables.ACTION_SNAPSHOTS;
import static org.jooq.impl.DSL.currentOffsetDateTime;

@Repository
public class SnapshotRepo {

    private final DSLContext dsl;
    private final ObjectMapper mapper;

    public SnapshotRepo(DSLContext dsl, ObjectMapper mapper) {
        this.dsl = dsl;
        this.mapper = mapper;
    }

    public UUID record(UUID correlationId, SystemType systemType, String systemId,
                       String targetUserId, SnapshotKind kind, Object payload) {
        UUID id = UUID.randomUUID();
        dsl.insertInto(ACTION_SNAPSHOTS)
                .set(ACTION_SNAPSHOTS.ID,             id)
                .set(ACTION_SNAPSHOTS.CORRELATION_ID, correlationId)
                .set(ACTION_SNAPSHOTS.SYSTEM_TYPE,    systemType.name())
                .set(ACTION_SNAPSHOTS.SYSTEM_ID,      systemId)
                .set(ACTION_SNAPSHOTS.TARGET_USER_ID, targetUserId)
                .set(ACTION_SNAPSHOTS.SNAPSHOT_KIND,  kind.dbValue())
                .set(ACTION_SNAPSHOTS.PAYLOAD,        JSONB.valueOf(toJson(payload)))
                .execute();
        return id;
    }

    public Optional<Latest> findLatestUnconsumed(SystemType systemType, String systemId,
                                                 String targetUserId, SnapshotKind kind) {
        return dsl.select(ACTION_SNAPSHOTS.ID, ACTION_SNAPSHOTS.PAYLOAD)
                .from(ACTION_SNAPSHOTS)
                .where(ACTION_SNAPSHOTS.SYSTEM_TYPE.eq(systemType.name()))
                .and(ACTION_SNAPSHOTS.SYSTEM_ID.eq(systemId))
                .and(ACTION_SNAPSHOTS.TARGET_USER_ID.eq(targetUserId))
                .and(ACTION_SNAPSHOTS.SNAPSHOT_KIND.eq(kind.dbValue()))
                .and(ACTION_SNAPSHOTS.CONSUMED_AT.isNull())
                .orderBy(ACTION_SNAPSHOTS.CREATED_AT.desc())
                .limit(1)
                .fetchOptional()
                .map(r -> new Latest(r.value1(), r.value2().data()));
    }

    public int delete(UUID snapshotId) {
        return dsl.deleteFrom(ACTION_SNAPSHOTS)
                .where(ACTION_SNAPSHOTS.ID.eq(snapshotId))
                .and(ACTION_SNAPSHOTS.CONSUMED_AT.isNull())
                .execute();
    }

    public int markConsumed(UUID snapshotId) {
        return dsl.update(ACTION_SNAPSHOTS)
                .set(ACTION_SNAPSHOTS.CONSUMED_AT, currentOffsetDateTime())
                .where(ACTION_SNAPSHOTS.ID.eq(snapshotId))
                .and(ACTION_SNAPSHOTS.CONSUMED_AT.isNull())
                .execute();
    }

    public boolean hasAnyUnconsumed(SystemType systemType, String systemId, SnapshotKind kind) {
        return dsl.fetchExists(
                dsl.selectOne()
                        .from(ACTION_SNAPSHOTS)
                        .where(ACTION_SNAPSHOTS.SYSTEM_TYPE.eq(systemType.name()))
                        .and(ACTION_SNAPSHOTS.SYSTEM_ID.eq(systemId))
                        .and(ACTION_SNAPSHOTS.SNAPSHOT_KIND.eq(kind.dbValue()))
                        .and(ACTION_SNAPSHOTS.CONSUMED_AT.isNull()));
    }

    public record Latest(UUID id, String payloadJson) {}

    private String toJson(Object value) {
        try { return mapper.writeValueAsString(value); }
        catch (JsonProcessingException e) {
            throw new IllegalStateException("failed to serialise snapshot payload", e);
        }
    }

    public enum SnapshotKind {
        ROLE_COLLECTIONS("role_collections"),
        IAS_USER_STATE("ias_user_state"),
        CF_ORG_ROLES("cf_org_roles"),
        IAS_USER_GROUPS("ias_user_groups");

        private final String dbValue;

        SnapshotKind(String dbValue) { this.dbValue = dbValue; }

        public String dbValue() { return dbValue; }
    }
}
