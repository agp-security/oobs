// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.protect;

import ninja.gruber.btpc.domain.ProtectedUser;
import ninja.gruber.btpc.domain.ProtectedUserOrigin;
import org.jooq.DSLContext;
import org.jooq.Record;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static ninja.gruber.btpc.jooq.Tables.PROTECTED_USERS;
import static org.jooq.impl.DSL.currentOffsetDateTime;
import static org.jooq.impl.DSL.lower;

@Repository
public class ProtectedUserRepo {

    private final DSLContext dsl;

    public ProtectedUserRepo(DSLContext dsl) {
        this.dsl = dsl;
    }

    public UUID insert(UUID subaccountId, UUID iasTenantId,
                       String email, String reason,
                       ProtectedUserOrigin origin, String addedBy, OffsetDateTime expiresAt) {
        UUID id = UUID.randomUUID();
        dsl.insertInto(PROTECTED_USERS)
                .set(PROTECTED_USERS.ID,            id)
                .set(PROTECTED_USERS.SUBACCOUNT_ID, subaccountId)
                .set(PROTECTED_USERS.IAS_TENANT_ID, iasTenantId)
                .set(PROTECTED_USERS.USER_EMAIL,    email)
                .set(PROTECTED_USERS.REASON,        reason)
                .set(PROTECTED_USERS.ORIGIN,        origin.dbValue())
                .set(PROTECTED_USERS.ADDED_BY,      addedBy)
                .set(PROTECTED_USERS.EXPIRES_AT,    expiresAt)
                .execute();
        return id;
    }

    public List<ProtectedUser> list() {
        return dsl.selectFrom(PROTECTED_USERS)
                .orderBy(PROTECTED_USERS.ADDED_AT.desc())
                .fetch()
                .map(ProtectedUserRepo::toProtectedUser);
    }

    public Optional<ProtectedUser> findById(UUID id) {
        return dsl.selectFrom(PROTECTED_USERS)
                .where(PROTECTED_USERS.ID.eq(id))
                .fetchOptional()
                .map(ProtectedUserRepo::toProtectedUser);
    }

    public List<ProtectedUser> findActiveMatches(String email, UUID subaccountId, UUID iasTenantId) {
        return dsl.selectFrom(PROTECTED_USERS)
                .where(lower(PROTECTED_USERS.USER_EMAIL).eq(email.toLowerCase()))
                .and(PROTECTED_USERS.SUBACCOUNT_ID.isNull().and(PROTECTED_USERS.IAS_TENANT_ID.isNull())
                        .or(PROTECTED_USERS.SUBACCOUNT_ID.eq(subaccountId))
                        .or(PROTECTED_USERS.IAS_TENANT_ID.eq(iasTenantId)))
                .and(PROTECTED_USERS.ENABLED.isTrue())
                .and(PROTECTED_USERS.EXPIRES_AT.isNull().or(PROTECTED_USERS.EXPIRES_AT.gt(currentOffsetDateTime())))
                .orderBy(
                        PROTECTED_USERS.SUBACCOUNT_ID.isNull()
                                .and(PROTECTED_USERS.IAS_TENANT_ID.isNull()).desc(),
                        PROTECTED_USERS.ADDED_AT.desc())
                .fetch()
                .map(ProtectedUserRepo::toProtectedUser);
    }

    public int delete(UUID id) {
        return dsl.deleteFrom(PROTECTED_USERS)
                .where(PROTECTED_USERS.ID.eq(id))
                .execute();
    }

    public int deleteExpiredAtScope(UUID subaccountId, UUID iasTenantId, String email) {
        return dsl.deleteFrom(PROTECTED_USERS)
                .where(PROTECTED_USERS.SUBACCOUNT_ID.isNotDistinctFrom(subaccountId))
                .and(PROTECTED_USERS.IAS_TENANT_ID.isNotDistinctFrom(iasTenantId))
                .and(lower(PROTECTED_USERS.USER_EMAIL).eq(email.toLowerCase()))
                .and(PROTECTED_USERS.ENABLED.isTrue())
                .and(PROTECTED_USERS.EXPIRES_AT.isNotNull())
                .and(PROTECTED_USERS.EXPIRES_AT.le(currentOffsetDateTime()))
                .execute();
    }

    private static ProtectedUser toProtectedUser(Record r) {
        return new ProtectedUser(
                r.get(PROTECTED_USERS.ID),
                r.get(PROTECTED_USERS.SUBACCOUNT_ID),
                r.get(PROTECTED_USERS.IAS_TENANT_ID),
                r.get(PROTECTED_USERS.USER_EMAIL),
                r.get(PROTECTED_USERS.REASON),
                ProtectedUserOrigin.fromDb(r.get(PROTECTED_USERS.ORIGIN)),
                r.get(PROTECTED_USERS.ADDED_BY),
                r.get(PROTECTED_USERS.ADDED_AT),
                r.get(PROTECTED_USERS.EXPIRES_AT),
                r.get(PROTECTED_USERS.ENABLED),
                r.get(PROTECTED_USERS.DISABLED_AT),
                r.get(PROTECTED_USERS.DISABLED_BY)
        );
    }
}
