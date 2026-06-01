// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.contacts;

import ninja.gruber.btpc.domain.SubaccountContact;
import org.jooq.DSLContext;
import org.jooq.Record;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static ninja.gruber.btpc.jooq.Tables.SUBACCOUNT_CONTACTS;
import static org.jooq.impl.DSL.currentOffsetDateTime;
import static org.jooq.impl.DSL.lower;

@Repository
public class ContactRepo {

    private final DSLContext dsl;

    public ContactRepo(DSLContext dsl) {
        this.dsl = dsl;
    }

    public UUID insert(UUID subaccountId, String name, String email, String role,
                       String notes, String createdBy) {
        UUID id = UUID.randomUUID();
        dsl.insertInto(SUBACCOUNT_CONTACTS)
                .set(SUBACCOUNT_CONTACTS.ID,            id)
                .set(SUBACCOUNT_CONTACTS.SUBACCOUNT_ID, subaccountId)
                .set(SUBACCOUNT_CONTACTS.NAME,          name)
                .set(SUBACCOUNT_CONTACTS.EMAIL,         email)
                .set(SUBACCOUNT_CONTACTS.ROLE,          role)
                .set(SUBACCOUNT_CONTACTS.NOTES,         notes)
                .set(SUBACCOUNT_CONTACTS.CREATED_BY,    createdBy)
                .execute();
        return id;
    }

    public int update(UUID id, String name, String email, String role, String notes) {
        return dsl.update(SUBACCOUNT_CONTACTS)
                .set(SUBACCOUNT_CONTACTS.NAME,       name)
                .set(SUBACCOUNT_CONTACTS.EMAIL,      email)
                .set(SUBACCOUNT_CONTACTS.ROLE,       role)
                .set(SUBACCOUNT_CONTACTS.NOTES,      notes)
                .set(SUBACCOUNT_CONTACTS.UPDATED_AT, currentOffsetDateTime())
                .where(SUBACCOUNT_CONTACTS.ID.eq(id))
                .execute();
    }

    public int delete(UUID id) {
        return dsl.deleteFrom(SUBACCOUNT_CONTACTS)
                .where(SUBACCOUNT_CONTACTS.ID.eq(id))
                .execute();
    }

    public Optional<SubaccountContact> findById(UUID id) {
        return dsl.selectFrom(SUBACCOUNT_CONTACTS)
                .where(SUBACCOUNT_CONTACTS.ID.eq(id))
                .fetchOptional()
                .map(ContactRepo::toContact);
    }

    public List<SubaccountContact> listForSubaccount(UUID subaccountId) {
        return dsl.selectFrom(SUBACCOUNT_CONTACTS)
                .where(SUBACCOUNT_CONTACTS.SUBACCOUNT_ID.eq(subaccountId))
                .orderBy(SUBACCOUNT_CONTACTS.ROLE, lower(SUBACCOUNT_CONTACTS.EMAIL))
                .fetch()
                .map(ContactRepo::toContact);
    }

    private static SubaccountContact toContact(Record r) {
        return new SubaccountContact(
                r.get(SUBACCOUNT_CONTACTS.ID),
                r.get(SUBACCOUNT_CONTACTS.SUBACCOUNT_ID),
                r.get(SUBACCOUNT_CONTACTS.NAME),
                r.get(SUBACCOUNT_CONTACTS.EMAIL),
                r.get(SUBACCOUNT_CONTACTS.ROLE),
                r.get(SUBACCOUNT_CONTACTS.NOTES),
                r.get(SUBACCOUNT_CONTACTS.CREATED_BY),
                r.get(SUBACCOUNT_CONTACTS.CREATED_AT),
                r.get(SUBACCOUNT_CONTACTS.UPDATED_AT));
    }
}
