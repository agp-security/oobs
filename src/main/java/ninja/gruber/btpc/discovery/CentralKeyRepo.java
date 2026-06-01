// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.discovery;

import ninja.gruber.btpc.discovery.domain.CentralViewerKey;

import org.jooq.DSLContext;
import org.jooq.Field;
import org.jooq.Record;
import org.springframework.stereotype.Repository;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static ninja.gruber.btpc.jooq.Tables.CENTRAL_VIEWER_KEYS;
import static org.jooq.impl.DSL.coalesce;
import static org.jooq.impl.DSL.condition;
import static org.jooq.impl.DSL.currentOffsetDateTime;
import static org.jooq.impl.DSL.val;

@Repository
public class CentralKeyRepo {

    private final DSLContext dsl;

    public CentralKeyRepo(DSLContext dsl) {
        this.dsl = dsl;
    }

    public UUID insert(UUID id, UUID globalAccountId, String globalAccountName,
                       String label, byte[] cipher, byte[] nonce,
                       int syncIntervalMinutes, boolean syncEnabled, String addedBy) {
        dsl.insertInto(CENTRAL_VIEWER_KEYS)
                .set(CENTRAL_VIEWER_KEYS.ID,                    id)
                .set(CENTRAL_VIEWER_KEYS.GLOBAL_ACCOUNT_ID,     globalAccountId)
                .set(CENTRAL_VIEWER_KEYS.GLOBAL_ACCOUNT_NAME,   globalAccountName)
                .set(CENTRAL_VIEWER_KEYS.LABEL,                 label)
                .set(CENTRAL_VIEWER_KEYS.CIPHER,                cipher)
                .set(CENTRAL_VIEWER_KEYS.NONCE,                 nonce)
                .set(CENTRAL_VIEWER_KEYS.SYNC_ENABLED,          syncEnabled)
                .set(CENTRAL_VIEWER_KEYS.SYNC_INTERVAL_MINUTES, syncIntervalMinutes)
                .set(CENTRAL_VIEWER_KEYS.ADDED_BY,              addedBy)
                .execute();
        return id;
    }

    public List<CentralViewerKey> list() {
        return dsl.selectFrom(CENTRAL_VIEWER_KEYS)
                .orderBy(CENTRAL_VIEWER_KEYS.ADDED_AT.desc())
                .fetch()
                .map(CentralKeyRepo::toKey);
    }

    public Optional<CentralViewerKey> findById(UUID id) {
        return dsl.selectFrom(CENTRAL_VIEWER_KEYS)
                .where(CENTRAL_VIEWER_KEYS.ID.eq(id))
                .fetchOptional()
                .map(CentralKeyRepo::toKey);
    }

    public Optional<EncryptedKey> loadCipher(UUID id) {
        return dsl.select(CENTRAL_VIEWER_KEYS.CIPHER, CENTRAL_VIEWER_KEYS.NONCE)
                .from(CENTRAL_VIEWER_KEYS)
                .where(CENTRAL_VIEWER_KEYS.ID.eq(id))
                .fetchOptional()
                .map(r -> new EncryptedKey(r.value1(), r.value2()));
    }

    public Optional<CentralViewerKey> findByGlobalAccountId(UUID globalAccountId) {
        return dsl.selectFrom(CENTRAL_VIEWER_KEYS)
                .where(CENTRAL_VIEWER_KEYS.GLOBAL_ACCOUNT_ID.eq(globalAccountId))
                .fetchOptional()
                .map(CentralKeyRepo::toKey);
    }

    public List<CentralViewerKey> findDueForSync() {
        return dsl.selectFrom(CENTRAL_VIEWER_KEYS)
                .where(CENTRAL_VIEWER_KEYS.SYNC_ENABLED.isTrue())
                .and(CENTRAL_VIEWER_KEYS.LAST_SYNC_AT.isNull()
                        .or(condition(
                                "{0} + ({1} * interval '1 minute') <= now()",
                                CENTRAL_VIEWER_KEYS.LAST_SYNC_AT,
                                CENTRAL_VIEWER_KEYS.SYNC_INTERVAL_MINUTES)))
                .orderBy(coalesce(CENTRAL_VIEWER_KEYS.LAST_SYNC_AT,
                        val("epoch").cast(CENTRAL_VIEWER_KEYS.LAST_SYNC_AT.getDataType())).asc())
                .fetch()
                .map(CentralKeyRepo::toKey);
    }

    public int updateSyncSettings(UUID id, Boolean syncEnabled, Integer syncIntervalMinutes,
                                  String label) {
        Map<Field<?>, Object> updates = new LinkedHashMap<>();
        if (syncEnabled != null)         updates.put(CENTRAL_VIEWER_KEYS.SYNC_ENABLED,          syncEnabled);
        if (syncIntervalMinutes != null) updates.put(CENTRAL_VIEWER_KEYS.SYNC_INTERVAL_MINUTES, syncIntervalMinutes);
        if (label != null)               updates.put(CENTRAL_VIEWER_KEYS.LABEL,                 label);
        if (updates.isEmpty()) return 0;
        return dsl.update(CENTRAL_VIEWER_KEYS)
                .set(updates)
                .where(CENTRAL_VIEWER_KEYS.ID.eq(id))
                .execute();
    }

    public int recordSyncSuccess(UUID id, int count, UUID inferredGlobalAccountId,
                                 String inferredGlobalAccountName) {
        return dsl.update(CENTRAL_VIEWER_KEYS)
                .set(CENTRAL_VIEWER_KEYS.LAST_SYNC_AT,    currentOffsetDateTime())
                .setNull(CENTRAL_VIEWER_KEYS.LAST_SYNC_ERROR)
                .set(CENTRAL_VIEWER_KEYS.LAST_SYNC_COUNT, count)
                .set(CENTRAL_VIEWER_KEYS.GLOBAL_ACCOUNT_ID,
                        coalesce(CENTRAL_VIEWER_KEYS.GLOBAL_ACCOUNT_ID, val(inferredGlobalAccountId)))
                .set(CENTRAL_VIEWER_KEYS.GLOBAL_ACCOUNT_NAME,
                        coalesce(CENTRAL_VIEWER_KEYS.GLOBAL_ACCOUNT_NAME, val(inferredGlobalAccountName)))
                .where(CENTRAL_VIEWER_KEYS.ID.eq(id))
                .execute();
    }

    public int recordSyncFailure(UUID id, String errorMessage) {
        String truncated = errorMessage == null ? "unknown error"
                : (errorMessage.length() > 1000 ? errorMessage.substring(0, 1000) : errorMessage);
        return dsl.update(CENTRAL_VIEWER_KEYS)
                .set(CENTRAL_VIEWER_KEYS.LAST_SYNC_AT,    currentOffsetDateTime())
                .set(CENTRAL_VIEWER_KEYS.LAST_SYNC_ERROR, truncated)
                .where(CENTRAL_VIEWER_KEYS.ID.eq(id))
                .execute();
    }

    public int delete(UUID id) {
        return dsl.deleteFrom(CENTRAL_VIEWER_KEYS)
                .where(CENTRAL_VIEWER_KEYS.ID.eq(id))
                .execute();
    }

    public record EncryptedKey(byte[] cipher, byte[] nonce) {}

    private static CentralViewerKey toKey(Record r) {
        return new CentralViewerKey(
                r.get(CENTRAL_VIEWER_KEYS.ID),
                r.get(CENTRAL_VIEWER_KEYS.GLOBAL_ACCOUNT_ID),
                r.get(CENTRAL_VIEWER_KEYS.GLOBAL_ACCOUNT_NAME),
                r.get(CENTRAL_VIEWER_KEYS.LABEL),
                r.get(CENTRAL_VIEWER_KEYS.KEY_VERSION),
                r.get(CENTRAL_VIEWER_KEYS.SYNC_ENABLED),
                r.get(CENTRAL_VIEWER_KEYS.SYNC_INTERVAL_MINUTES),
                r.get(CENTRAL_VIEWER_KEYS.LAST_SYNC_AT),
                r.get(CENTRAL_VIEWER_KEYS.LAST_SYNC_ERROR),
                r.get(CENTRAL_VIEWER_KEYS.LAST_SYNC_COUNT),
                r.get(CENTRAL_VIEWER_KEYS.ADDED_BY),
                r.get(CENTRAL_VIEWER_KEYS.ADDED_AT));
    }
}
