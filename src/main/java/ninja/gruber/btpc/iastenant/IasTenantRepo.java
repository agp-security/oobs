// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.iastenant;

import ninja.gruber.btpc.iastenant.domain.IasTenant;

import ninja.gruber.btpc.crypto.AesGcmBox;
import org.jooq.DSLContext;
import org.jooq.Record;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static ninja.gruber.btpc.jooq.Tables.IAS_TENANTS;
import static org.jooq.impl.DSL.currentOffsetDateTime;

@Repository
public class IasTenantRepo {

    private final DSLContext dsl;

    public IasTenantRepo(DSLContext dsl) { this.dsl = dsl; }

    public UUID insert(String displayName, String iasHost, AesGcmBox.Wrapped creds, String createdBy) {
        UUID id = UUID.randomUUID();
        dsl.insertInto(IAS_TENANTS)
                .set(IAS_TENANTS.ID,                    id)
                .set(IAS_TENANTS.DISPLAY_NAME,          displayName)
                .set(IAS_TENANTS.IAS_HOST,              iasHost)
                .set(IAS_TENANTS.ENCRYPTED_CREDS,       creds.cipher())
                .set(IAS_TENANTS.ENCRYPTED_CREDS_NONCE, creds.nonce())
                .set(IAS_TENANTS.CREATED_BY,            createdBy)
                .set(IAS_TENANTS.UPDATED_BY,            createdBy)
                .execute();
        return id;
    }

    public int updateMeta(UUID id, String displayName, String updatedBy) {
        return dsl.update(IAS_TENANTS)
                .set(IAS_TENANTS.DISPLAY_NAME, displayName)
                .set(IAS_TENANTS.UPDATED_AT,   currentOffsetDateTime())
                .set(IAS_TENANTS.UPDATED_BY,   updatedBy)
                .where(IAS_TENANTS.ID.eq(id))
                .execute();
    }

    public int updateCreds(UUID id, AesGcmBox.Wrapped creds, String updatedBy) {
        return dsl.update(IAS_TENANTS)
                .set(IAS_TENANTS.ENCRYPTED_CREDS,       creds.cipher())
                .set(IAS_TENANTS.ENCRYPTED_CREDS_NONCE, creds.nonce())
                .set(IAS_TENANTS.UPDATED_AT,            currentOffsetDateTime())
                .set(IAS_TENANTS.UPDATED_BY,            updatedBy)
                .where(IAS_TENANTS.ID.eq(id))
                .execute();
    }

    public Optional<IasTenant> findById(UUID id) {
        return dsl.selectFrom(IAS_TENANTS)
                .where(IAS_TENANTS.ID.eq(id))
                .fetchOptional()
                .map(IasTenantRepo::toIasTenant);
    }

    public Optional<IasTenant> findByHost(String iasHost) {
        return dsl.selectFrom(IAS_TENANTS)
                .where(IAS_TENANTS.IAS_HOST.eq(iasHost))
                .fetchOptional()
                .map(IasTenantRepo::toIasTenant);
    }

    public List<IasTenant> list() {
        return dsl.selectFrom(IAS_TENANTS)
                .orderBy(IAS_TENANTS.DISPLAY_NAME)
                .fetch()
                .map(IasTenantRepo::toIasTenant);
    }

    public Optional<EncryptedCreds> loadCreds(UUID id) {
        return dsl.select(IAS_TENANTS.ENCRYPTED_CREDS, IAS_TENANTS.ENCRYPTED_CREDS_NONCE)
                .from(IAS_TENANTS)
                .where(IAS_TENANTS.ID.eq(id))
                .fetchOptional()
                .map(r -> new EncryptedCreds(r.value1(), r.value2()));
    }

    public int delete(UUID id) {
        return dsl.deleteFrom(IAS_TENANTS)
                .where(IAS_TENANTS.ID.eq(id))
                .execute();
    }

    public record EncryptedCreds(byte[] cipher, byte[] nonce) {}

    private static IasTenant toIasTenant(Record r) {
        return new IasTenant(
                r.get(IAS_TENANTS.ID),
                r.get(IAS_TENANTS.DISPLAY_NAME),
                r.get(IAS_TENANTS.IAS_HOST),
                r.get(IAS_TENANTS.CREATED_AT),
                r.get(IAS_TENANTS.CREATED_BY),
                r.get(IAS_TENANTS.UPDATED_AT),
                r.get(IAS_TENANTS.UPDATED_BY));
    }
}
