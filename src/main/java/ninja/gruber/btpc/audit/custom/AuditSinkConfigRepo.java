// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.audit.custom;

import ninja.gruber.btpc.audit.custom.domain.AuditSinkConfig;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ninja.gruber.btpc.crypto.AesGcmBox;
import org.jooq.DSLContext;
import org.jooq.JSONB;
import org.jooq.Record;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static ninja.gruber.btpc.jooq.Tables.AUDIT_SINKS;
import static org.jooq.impl.DSL.currentOffsetDateTime;

@Repository
public class AuditSinkConfigRepo {

    private final DSLContext dsl;
    private final ObjectMapper mapper;

    public AuditSinkConfigRepo(DSLContext dsl, ObjectMapper mapper) {
        this.dsl = dsl;
        this.mapper = mapper;
    }

    public List<AuditSinkConfig> list() {
        return dsl.selectFrom(AUDIT_SINKS)
                .orderBy(AUDIT_SINKS.KIND)
                .fetch()
                .map(this::toConfig);
    }

    public Optional<AuditSinkConfig> findByKind(AuditSinkConfig.Kind kind) {
        return dsl.selectFrom(AUDIT_SINKS)
                .where(AUDIT_SINKS.KIND.eq(kind.dbValue()))
                .fetchOptional()
                .map(this::toConfig);
    }

    public Optional<EncryptedSecret> loadSecret(AuditSinkConfig.Kind kind) {
        return dsl.select(AUDIT_SINKS.ENCRYPTED_SECRET, AUDIT_SINKS.ENCRYPTED_SECRET_NONCE)
                .from(AUDIT_SINKS)
                .where(AUDIT_SINKS.KIND.eq(kind.dbValue()))
                .and(AUDIT_SINKS.ENCRYPTED_SECRET.isNotNull())
                .fetchOptional()
                .map(r -> new EncryptedSecret(r.value1(), r.value2()));
    }

    public void upsert(AuditSinkConfig.Kind kind, boolean enabled, JsonNode config,
                       AesGcmBox.Wrapped wrapped, String actor) {
        String configJson;
        try { configJson = mapper.writeValueAsString(config); }
        catch (Exception e) { throw new IllegalStateException("failed to serialise config", e); }
        JSONB cfgJsonb = JSONB.valueOf(configJson);
        var insert = dsl.insertInto(AUDIT_SINKS)
                .set(AUDIT_SINKS.KIND,             kind.dbValue())
                .set(AUDIT_SINKS.ENABLED,          enabled)
                .set(AUDIT_SINKS.CONFIG_PLAINTEXT, cfgJsonb)
                .set(AUDIT_SINKS.UPDATED_BY,       actor);
        if (wrapped != null) {
            insert.set(AUDIT_SINKS.ENCRYPTED_SECRET,       wrapped.cipher())
                  .set(AUDIT_SINKS.ENCRYPTED_SECRET_NONCE, wrapped.nonce());
        }

        var update = insert.onConflict(AUDIT_SINKS.KIND).doUpdate()
                .set(AUDIT_SINKS.ENABLED,          enabled)
                .set(AUDIT_SINKS.CONFIG_PLAINTEXT, cfgJsonb)
                .set(AUDIT_SINKS.UPDATED_AT,       currentOffsetDateTime())
                .set(AUDIT_SINKS.UPDATED_BY,       actor);
        if (wrapped != null) {
            update.set(AUDIT_SINKS.ENCRYPTED_SECRET,       wrapped.cipher())
                  .set(AUDIT_SINKS.ENCRYPTED_SECRET_NONCE, wrapped.nonce());
        }
        update.execute();
    }

    public void recordTestResult(AuditSinkConfig.Kind kind, String status, String message) {
        dsl.update(AUDIT_SINKS)
                .set(AUDIT_SINKS.LAST_TEST_AT,      currentOffsetDateTime())
                .set(AUDIT_SINKS.LAST_TEST_STATUS,  status)
                .set(AUDIT_SINKS.LAST_TEST_MESSAGE, message)
                .where(AUDIT_SINKS.KIND.eq(kind.dbValue()))
                .execute();
    }

    public int delete(AuditSinkConfig.Kind kind) {
        return dsl.deleteFrom(AUDIT_SINKS)
                .where(AUDIT_SINKS.KIND.eq(kind.dbValue()))
                .execute();
    }

    public record EncryptedSecret(byte[] cipher, byte[] nonce) {}

    private AuditSinkConfig toConfig(Record r) {
        JsonNode cfg;
        try {
            JSONB raw = r.get(AUDIT_SINKS.CONFIG_PLAINTEXT);
            cfg = raw == null ? mapper.createObjectNode() : mapper.readTree(raw.data());
        } catch (Exception e) {
            cfg = mapper.createObjectNode();
        }
        return new AuditSinkConfig(
                r.get(AUDIT_SINKS.ID),
                AuditSinkConfig.Kind.fromDb(r.get(AUDIT_SINKS.KIND)),
                r.get(AUDIT_SINKS.ENABLED),
                cfg,
                r.get(AUDIT_SINKS.ENCRYPTED_SECRET) != null,
                r.get(AUDIT_SINKS.LAST_TEST_AT),
                r.get(AUDIT_SINKS.LAST_TEST_STATUS),
                r.get(AUDIT_SINKS.LAST_TEST_MESSAGE),
                r.get(AUDIT_SINKS.UPDATED_AT),
                r.get(AUDIT_SINKS.UPDATED_BY));
    }
}
