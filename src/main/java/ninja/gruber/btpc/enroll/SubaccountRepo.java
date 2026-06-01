// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.enroll;

import ninja.gruber.btpc.crypto.AesGcmBox;
import ninja.gruber.btpc.domain.CredentialKind;
import ninja.gruber.btpc.domain.Subaccount;
import org.jooq.DSLContext;
import org.jooq.Field;
import org.jooq.Record;
import org.springframework.stereotype.Repository;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static ninja.gruber.btpc.jooq.Tables.SUBACCOUNTS;
import static ninja.gruber.btpc.jooq.Tables.SUBACCOUNT_CONTACTS;
import static ninja.gruber.btpc.jooq.Tables.SUBACCOUNT_CREDENTIALS;
import static org.jooq.impl.DSL.count;
import static org.jooq.impl.DSL.currentOffsetDateTime;

@Repository
public class SubaccountRepo {

    private final DSLContext dsl;

    public SubaccountRepo(DSLContext dsl) {
        this.dsl = dsl;
    }

    public UUID insertSubaccount(
            UUID subaccountGuid, String cisDisplayName, String label, String region,
            UUID globalAccountId, String globalAccountName, String stage,
            String enrolledBy) {
        UUID id = UUID.randomUUID();
        dsl.insertInto(SUBACCOUNTS)
                .set(SUBACCOUNTS.ID,                            id)
                .set(SUBACCOUNTS.SUBACCOUNT_GUID,               subaccountGuid)
                .set(SUBACCOUNTS.CIS_DISPLAY_NAME,              cisDisplayName)
                .set(SUBACCOUNTS.CIS_DISPLAY_NAME_REFRESHED_AT, currentOffsetDateTime())
                .set(SUBACCOUNTS.LABEL,                         label)
                .set(SUBACCOUNTS.REGION,                        region)
                .set(SUBACCOUNTS.GLOBAL_ACCOUNT_ID,             globalAccountId)
                .set(SUBACCOUNTS.GLOBAL_ACCOUNT_NAME,           globalAccountName)
                .set(SUBACCOUNTS.STAGE,                         stage)
                .set(SUBACCOUNTS.ENROLLED_BY,                   enrolledBy)
                .execute();
        return id;
    }

    public int updateLabel(UUID id, String label) {
        return dsl.update(SUBACCOUNTS)
                .set(SUBACCOUNTS.LABEL, label)
                .where(SUBACCOUNTS.ID.eq(id))
                .execute();
    }

    public int updateMetadata(UUID id, String label, UUID globalAccountId,
                              String globalAccountName, String stage) {
        return dsl.update(SUBACCOUNTS)
                .set(SUBACCOUNTS.LABEL,               label)
                .set(SUBACCOUNTS.GLOBAL_ACCOUNT_ID,   globalAccountId)
                .set(SUBACCOUNTS.GLOBAL_ACCOUNT_NAME, globalAccountName)
                .set(SUBACCOUNTS.STAGE,               stage)
                .where(SUBACCOUNTS.ID.eq(id))
                .execute();
    }

    public void upsertCredential(UUID subaccountId, CredentialKind kind, AesGcmBox.Wrapped wrapped) {
        dsl.insertInto(SUBACCOUNT_CREDENTIALS)
                .set(SUBACCOUNT_CREDENTIALS.SUBACCOUNT_ID, subaccountId)
                .set(SUBACCOUNT_CREDENTIALS.KIND,          kind.dbValue())
                .set(SUBACCOUNT_CREDENTIALS.CIPHER,        wrapped.cipher())
                .set(SUBACCOUNT_CREDENTIALS.NONCE,         wrapped.nonce())
                .onConflict(SUBACCOUNT_CREDENTIALS.SUBACCOUNT_ID, SUBACCOUNT_CREDENTIALS.KIND)
                .doUpdate()
                .set(SUBACCOUNT_CREDENTIALS.CIPHER,     wrapped.cipher())
                .set(SUBACCOUNT_CREDENTIALS.NONCE,      wrapped.nonce())
                .set(SUBACCOUNT_CREDENTIALS.ROTATED_AT, currentOffsetDateTime())
                .execute();
    }

    public Optional<Subaccount> findById(UUID id) {
        return dsl.selectFrom(SUBACCOUNTS)
                .where(SUBACCOUNTS.ID.eq(id))
                .fetchOptional()
                .map(SubaccountRepo::toSubaccount);
    }

    public Optional<Subaccount> findByGuid(UUID subaccountGuid) {
        return dsl.selectFrom(SUBACCOUNTS)
                .where(SUBACCOUNTS.SUBACCOUNT_GUID.eq(subaccountGuid))
                .fetchOptional()
                .map(SubaccountRepo::toSubaccount);
    }

    public List<Subaccount> list() {
        return dsl.selectFrom(SUBACCOUNTS)
                .orderBy(SUBACCOUNTS.ENROLLED_AT.desc())
                .fetch()
                .map(SubaccountRepo::toSubaccount);
    }

    public int delete(UUID id) {
        return dsl.deleteFrom(SUBACCOUNTS)
                .where(SUBACCOUNTS.ID.eq(id))
                .execute();
    }

    public int setCfOrgId(UUID subaccountId, UUID cfOrgId) {
        return dsl.update(SUBACCOUNTS)
                .set(SUBACCOUNTS.CF_ORG_ID, cfOrgId)
                .where(SUBACCOUNTS.ID.eq(subaccountId))
                .execute();
    }

    public Optional<EncryptedCredential> loadCredential(UUID subaccountId, CredentialKind kind) {
        return dsl.select(SUBACCOUNT_CREDENTIALS.CIPHER, SUBACCOUNT_CREDENTIALS.NONCE)
                .from(SUBACCOUNT_CREDENTIALS)
                .where(SUBACCOUNT_CREDENTIALS.SUBACCOUNT_ID.eq(subaccountId))
                .and(SUBACCOUNT_CREDENTIALS.KIND.eq(kind.dbValue()))
                .fetchOptional()
                .map(r -> new EncryptedCredential(r.value1(), r.value2()));
    }

    public Map<UUID, Set<CredentialKind>> capabilitiesByAccount() {
        Map<UUID, Set<CredentialKind>> out = new HashMap<>();
        dsl.select(SUBACCOUNT_CREDENTIALS.SUBACCOUNT_ID, SUBACCOUNT_CREDENTIALS.KIND)
                .from(SUBACCOUNT_CREDENTIALS)
                .forEach(r -> out
                        .computeIfAbsent(r.value1(), k -> EnumSet.noneOf(CredentialKind.class))
                        .add(CredentialKind.fromDb(r.value2())));
        return out;
    }

    public Map<UUID, Integer> contactCountByAccount() {
        Field<Integer> cnt = count();
        return dsl.select(SUBACCOUNT_CONTACTS.SUBACCOUNT_ID, cnt)
                .from(SUBACCOUNT_CONTACTS)
                .groupBy(SUBACCOUNT_CONTACTS.SUBACCOUNT_ID)
                .fetchMap(SUBACCOUNT_CONTACTS.SUBACCOUNT_ID, cnt);
    }

    public record EncryptedCredential(byte[] cipher, byte[] nonce) {}

    private static Subaccount toSubaccount(Record r) {
        return new Subaccount(
                r.get(SUBACCOUNTS.ID),
                r.get(SUBACCOUNTS.SUBACCOUNT_GUID),
                r.get(SUBACCOUNTS.CIS_DISPLAY_NAME),
                r.get(SUBACCOUNTS.CIS_DISPLAY_NAME_REFRESHED_AT),
                r.get(SUBACCOUNTS.LABEL),
                r.get(SUBACCOUNTS.REGION),
                r.get(SUBACCOUNTS.GLOBAL_ACCOUNT_ID),
                r.get(SUBACCOUNTS.GLOBAL_ACCOUNT_NAME),
                r.get(SUBACCOUNTS.STAGE),
                r.get(SUBACCOUNTS.ENROLLED_BY),
                r.get(SUBACCOUNTS.ENROLLED_AT),
                r.get(SUBACCOUNTS.LAST_HEALTH_AT),
                r.get(SUBACCOUNTS.LAST_HEALTH_ERROR),
                r.get(SUBACCOUNTS.STATUS),
                r.get(SUBACCOUNTS.CF_ORG_ID));
    }
}
