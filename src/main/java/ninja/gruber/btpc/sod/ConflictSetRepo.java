// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.sod;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import ninja.gruber.btpc.domain.ConflictSet;
import org.jooq.DSLContext;
import org.jooq.JSONB;
import org.jooq.Record;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static ninja.gruber.btpc.jooq.Tables.CONFLICT_SETS;
import static org.jooq.impl.DSL.currentOffsetDateTime;

@Repository
public class ConflictSetRepo {

    private final DSLContext dsl;
    private final ObjectMapper mapper;

    public ConflictSetRepo(DSLContext dsl, ObjectMapper mapper) {
        this.dsl = dsl;
        this.mapper = mapper;
    }

    public UUID insert(String name, String description, String severity, String kind,
                       List<String> roleCollections, Integer thresholdCount,
                       String scopeLevel, String createdBy) {
        UUID id = UUID.randomUUID();
        dsl.insertInto(CONFLICT_SETS)
                .set(CONFLICT_SETS.ID,               id)
                .set(CONFLICT_SETS.NAME,             name)
                .set(CONFLICT_SETS.DESCRIPTION,      description)
                .set(CONFLICT_SETS.SEVERITY,         severity)
                .set(CONFLICT_SETS.KIND,             kind)
                .set(CONFLICT_SETS.ROLE_COLLECTIONS, JSONB.valueOf(toJson(roleCollections)))
                .set(CONFLICT_SETS.THRESHOLD_COUNT,  thresholdCount)
                .set(CONFLICT_SETS.SCOPE_LEVEL,      scopeLevel)
                .set(CONFLICT_SETS.CREATED_BY,       createdBy)
                .execute();
        return id;
    }

    public int update(UUID id, String name, String description, String severity, String kind,
                      List<String> roleCollections, Integer thresholdCount, String scopeLevel) {
        return dsl.update(CONFLICT_SETS)
                .set(CONFLICT_SETS.NAME,             name)
                .set(CONFLICT_SETS.DESCRIPTION,      description)
                .set(CONFLICT_SETS.SEVERITY,         severity)
                .set(CONFLICT_SETS.KIND,             kind)
                .set(CONFLICT_SETS.ROLE_COLLECTIONS, JSONB.valueOf(toJson(roleCollections)))
                .set(CONFLICT_SETS.THRESHOLD_COUNT,  thresholdCount)
                .set(CONFLICT_SETS.SCOPE_LEVEL,      scopeLevel)
                .set(CONFLICT_SETS.UPDATED_AT,       currentOffsetDateTime())
                .where(CONFLICT_SETS.ID.eq(id))
                .execute();
    }

    public int setEnabled(UUID id, boolean enabled) {
        return dsl.update(CONFLICT_SETS)
                .set(CONFLICT_SETS.ENABLED,    enabled)
                .set(CONFLICT_SETS.UPDATED_AT, currentOffsetDateTime())
                .where(CONFLICT_SETS.ID.eq(id))
                .execute();
    }

    public int delete(UUID id) {
        return dsl.deleteFrom(CONFLICT_SETS)
                .where(CONFLICT_SETS.ID.eq(id))
                .execute();
    }

    public Optional<ConflictSet> findById(UUID id) {
        return dsl.selectFrom(CONFLICT_SETS)
                .where(CONFLICT_SETS.ID.eq(id))
                .fetchOptional()
                .map(this::toConflictSet);
    }

    public List<ConflictSet> list() {
        return dsl.selectFrom(CONFLICT_SETS)
                .orderBy(CONFLICT_SETS.KIND, CONFLICT_SETS.SEVERITY.desc(), CONFLICT_SETS.NAME)
                .fetch()
                .map(this::toConflictSet);
    }

    public List<ConflictSet> listEnabled() {
        return dsl.selectFrom(CONFLICT_SETS)
                .where(CONFLICT_SETS.ENABLED.isTrue())
                .orderBy(CONFLICT_SETS.SEVERITY.desc(), CONFLICT_SETS.NAME)
                .fetch()
                .map(this::toConflictSet);
    }

    public int countAll() {
        return dsl.fetchCount(CONFLICT_SETS);
    }

    private ConflictSet toConflictSet(Record r) {
        JSONB rc = r.get(CONFLICT_SETS.ROLE_COLLECTIONS);
        return new ConflictSet(
                r.get(CONFLICT_SETS.ID),
                r.get(CONFLICT_SETS.NAME),
                r.get(CONFLICT_SETS.DESCRIPTION),
                r.get(CONFLICT_SETS.SEVERITY),
                r.get(CONFLICT_SETS.KIND),
                fromJson(rc == null ? null : rc.data()),
                r.get(CONFLICT_SETS.THRESHOLD_COUNT),
                r.get(CONFLICT_SETS.ENABLED),
                r.get(CONFLICT_SETS.SCOPE_LEVEL),
                r.get(CONFLICT_SETS.CREATED_BY),
                r.get(CONFLICT_SETS.CREATED_AT),
                r.get(CONFLICT_SETS.UPDATED_AT));
    }

    private String toJson(List<String> v) {
        try { return mapper.writeValueAsString(v == null ? List.of() : v); }
        catch (JsonProcessingException e) {
            throw new IllegalStateException("failed to serialise role_collections", e);
        }
    }

    private List<String> fromJson(String json) {
        if (json == null || json.isBlank()) return List.of();
        try {
            return mapper.readValue(json, new TypeReference<List<String>>() {});
        } catch (Exception e) {
            throw new IllegalStateException("malformed role_collections JSON: " + json, e);
        }
    }
}
