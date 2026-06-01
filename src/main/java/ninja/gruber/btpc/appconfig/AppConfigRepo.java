// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.appconfig;

import org.jooq.DSLContext;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.Optional;

import static ninja.gruber.btpc.jooq.Tables.APP_CONFIG;
import static org.jooq.impl.DSL.currentOffsetDateTime;

// key:value store for admin settings.
@Repository
public class AppConfigRepo {

    private final DSLContext dsl;

    public AppConfigRepo(DSLContext dsl) { this.dsl = dsl; }

    public Optional<Entry> get(String key) {
        return dsl.select(APP_CONFIG.KEY, APP_CONFIG.VALUE, APP_CONFIG.UPDATED_AT, APP_CONFIG.UPDATED_BY)
                .from(APP_CONFIG)
                .where(APP_CONFIG.KEY.eq(key))
                .fetchOptional()
                .map(r -> new Entry(r.value1(), r.value2(), r.value3(), r.value4()));
    }

    public Optional<String> getValue(String key) {
        return get(key).map(Entry::value);
    }

    public void put(String key, String value, String updatedBy) {
        dsl.insertInto(APP_CONFIG)
                .set(APP_CONFIG.KEY,        key)
                .set(APP_CONFIG.VALUE,      value)
                .set(APP_CONFIG.UPDATED_BY, updatedBy)
                .onConflict(APP_CONFIG.KEY)
                .doUpdate()
                .set(APP_CONFIG.VALUE,      value)
                .set(APP_CONFIG.UPDATED_AT, currentOffsetDateTime())
                .set(APP_CONFIG.UPDATED_BY, updatedBy)
                .execute();
    }

    public record Entry(String key, String value, OffsetDateTime updatedAt, String updatedBy) {}
}
