// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.origin;

import ninja.gruber.btpc.origin.domain.OriginProfile;

import org.jooq.DSLContext;
import org.jooq.Record;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;

import static ninja.gruber.btpc.jooq.Tables.ORIGIN_PROFILES;
import static org.jooq.impl.DSL.currentOffsetDateTime;
import static org.jooq.impl.DSL.lower;

@Repository
public class OriginProfileRepo {

    private final DSLContext dsl;

    public OriginProfileRepo(DSLContext dsl) { this.dsl = dsl; }

    public List<OriginProfile> list() {
        return dsl.selectFrom(ORIGIN_PROFILES)
                .orderBy(lower(ORIGIN_PROFILES.NAME))
                .fetch()
                .map(OriginProfileRepo::toProfile);
    }

    public Optional<OriginProfile> findById(UUID id) {
        return dsl.selectFrom(ORIGIN_PROFILES)
                .where(ORIGIN_PROFILES.ID.eq(id))
                .fetchOptional()
                .map(OriginProfileRepo::toProfile);
    }

    public OriginProfile insert(String name, String description, List<String> originKeys, String actor) {
        UUID id = UUID.randomUUID();
        dsl.insertInto(ORIGIN_PROFILES)
                .set(ORIGIN_PROFILES.ID,          id)
                .set(ORIGIN_PROFILES.NAME,        name)
                .set(ORIGIN_PROFILES.DESCRIPTION, description)
                .set(ORIGIN_PROFILES.ORIGIN_KEYS, originKeys.toArray(new String[0]))
                .set(ORIGIN_PROFILES.CREATED_BY,  actor)
                .set(ORIGIN_PROFILES.UPDATED_BY,  actor)
                .execute();
        return findById(id).orElseThrow();
    }

    public OriginProfile update(UUID id, String name, String description,
                                List<String> originKeys, String actor) {
        int n = dsl.update(ORIGIN_PROFILES)
                .set(ORIGIN_PROFILES.NAME,        name)
                .set(ORIGIN_PROFILES.DESCRIPTION, description)
                .set(ORIGIN_PROFILES.ORIGIN_KEYS, originKeys.toArray(new String[0]))
                .set(ORIGIN_PROFILES.UPDATED_AT,  currentOffsetDateTime())
                .set(ORIGIN_PROFILES.UPDATED_BY,  actor)
                .where(ORIGIN_PROFILES.ID.eq(id))
                .execute();
        if (n == 0) throw new NoSuchElementException("origin_profile " + id);
        return findById(id).orElseThrow();
    }

    public void delete(UUID id) {
        dsl.deleteFrom(ORIGIN_PROFILES)
                .where(ORIGIN_PROFILES.ID.eq(id))
                .execute();
    }

    private static OriginProfile toProfile(Record r) {
        String[] keys = r.get(ORIGIN_PROFILES.ORIGIN_KEYS);
        List<String> keyList = keys == null ? List.of() : List.of(keys);
        return new OriginProfile(
                r.get(ORIGIN_PROFILES.ID),
                r.get(ORIGIN_PROFILES.NAME),
                r.get(ORIGIN_PROFILES.DESCRIPTION),
                keyList,
                r.get(ORIGIN_PROFILES.CREATED_AT),
                r.get(ORIGIN_PROFILES.CREATED_BY),
                r.get(ORIGIN_PROFILES.UPDATED_AT),
                r.get(ORIGIN_PROFILES.UPDATED_BY));
    }
}
