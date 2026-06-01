// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.discovery;

import ninja.gruber.btpc.discovery.domain.DiscoveredSubaccount;

import org.jooq.Condition;
import org.jooq.DSLContext;
import org.jooq.Record;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static ninja.gruber.btpc.jooq.Tables.DISCOVERED_SUBACCOUNTS;
import static ninja.gruber.btpc.jooq.Tables.SUBACCOUNTS;
import static org.jooq.impl.DSL.currentOffsetDateTime;
import static org.jooq.impl.DSL.noCondition;

@Repository
public class DiscoveredSubaccountRepo {

    private static final org.jooq.Field<UUID> ENROLLED_SUBACCOUNT_ID =
            SUBACCOUNTS.ID.as("enrolled_subaccount_id");

    private final DSLContext dsl;

    public DiscoveredSubaccountRepo(DSLContext dsl) {
        this.dsl = dsl;
    }

    public int upsert(UUID centralKeyId, UUID subaccountGuid,
                      String displayName, String subdomain, String region,
                      String parentType, UUID parentGuid, UUID globalAccountGuid,
                      String state, String stateMessage,
                      Boolean betaEnabled, String usedForProduction, String description) {
        return dsl.insertInto(DISCOVERED_SUBACCOUNTS)
                .set(DISCOVERED_SUBACCOUNTS.CENTRAL_KEY_ID,      centralKeyId)
                .set(DISCOVERED_SUBACCOUNTS.SUBACCOUNT_GUID,     subaccountGuid)
                .set(DISCOVERED_SUBACCOUNTS.DISPLAY_NAME,        displayName)
                .set(DISCOVERED_SUBACCOUNTS.SUBDOMAIN,           subdomain)
                .set(DISCOVERED_SUBACCOUNTS.REGION,              region)
                .set(DISCOVERED_SUBACCOUNTS.PARENT_TYPE,         parentType)
                .set(DISCOVERED_SUBACCOUNTS.PARENT_GUID,         parentGuid)
                .set(DISCOVERED_SUBACCOUNTS.GLOBAL_ACCOUNT_GUID, globalAccountGuid)
                .set(DISCOVERED_SUBACCOUNTS.STATE,               state)
                .set(DISCOVERED_SUBACCOUNTS.STATE_MESSAGE,       stateMessage)
                .set(DISCOVERED_SUBACCOUNTS.BETA_ENABLED,        betaEnabled)
                .set(DISCOVERED_SUBACCOUNTS.USED_FOR_PRODUCTION, usedForProduction)
                .set(DISCOVERED_SUBACCOUNTS.DESCRIPTION,         description)
                .onConflict(DISCOVERED_SUBACCOUNTS.CENTRAL_KEY_ID, DISCOVERED_SUBACCOUNTS.SUBACCOUNT_GUID)
                .doUpdate()
                .set(DISCOVERED_SUBACCOUNTS.DISPLAY_NAME,        displayName)
                .set(DISCOVERED_SUBACCOUNTS.SUBDOMAIN,           subdomain)
                .set(DISCOVERED_SUBACCOUNTS.REGION,              region)
                .set(DISCOVERED_SUBACCOUNTS.PARENT_TYPE,         parentType)
                .set(DISCOVERED_SUBACCOUNTS.PARENT_GUID,         parentGuid)
                .set(DISCOVERED_SUBACCOUNTS.GLOBAL_ACCOUNT_GUID, globalAccountGuid)
                .set(DISCOVERED_SUBACCOUNTS.STATE,               state)
                .set(DISCOVERED_SUBACCOUNTS.STATE_MESSAGE,       stateMessage)
                .set(DISCOVERED_SUBACCOUNTS.BETA_ENABLED,        betaEnabled)
                .set(DISCOVERED_SUBACCOUNTS.USED_FOR_PRODUCTION, usedForProduction)
                .set(DISCOVERED_SUBACCOUNTS.DESCRIPTION,         description)
                .set(DISCOVERED_SUBACCOUNTS.LAST_SEEN_AT,        currentOffsetDateTime())
                .execute();
    }

    public List<DiscoveredSubaccount> list(boolean onlyPromotable, UUID centralKeyIdFilter) {
        Condition cond = noCondition();
        if (onlyPromotable)              cond = cond.and(SUBACCOUNTS.ID.isNull());
        if (centralKeyIdFilter != null)  cond = cond.and(DISCOVERED_SUBACCOUNTS.CENTRAL_KEY_ID.eq(centralKeyIdFilter));

        return dsl.select(DISCOVERED_SUBACCOUNTS.fields())
                .select(ENROLLED_SUBACCOUNT_ID)
                .from(DISCOVERED_SUBACCOUNTS)
                .leftJoin(SUBACCOUNTS)
                .on(SUBACCOUNTS.SUBACCOUNT_GUID.eq(DISCOVERED_SUBACCOUNTS.SUBACCOUNT_GUID))
                .where(cond)
                .orderBy(DISCOVERED_SUBACCOUNTS.DISCOVERED_AT.desc())
                .fetch()
                .map(DiscoveredSubaccountRepo::toDto);
    }

    public Optional<DiscoveredSubaccount> findById(UUID id) {
        return dsl.select(DISCOVERED_SUBACCOUNTS.fields())
                .select(ENROLLED_SUBACCOUNT_ID)
                .from(DISCOVERED_SUBACCOUNTS)
                .leftJoin(SUBACCOUNTS)
                .on(SUBACCOUNTS.SUBACCOUNT_GUID.eq(DISCOVERED_SUBACCOUNTS.SUBACCOUNT_GUID))
                .where(DISCOVERED_SUBACCOUNTS.ID.eq(id))
                .fetchOptional()
                .map(DiscoveredSubaccountRepo::toDto);
    }

    public int delete(UUID id) {
        return dsl.deleteFrom(DISCOVERED_SUBACCOUNTS)
                .where(DISCOVERED_SUBACCOUNTS.ID.eq(id))
                .execute();
    }

    private static DiscoveredSubaccount toDto(Record r) {
        return new DiscoveredSubaccount(
                r.get(DISCOVERED_SUBACCOUNTS.ID),
                r.get(DISCOVERED_SUBACCOUNTS.CENTRAL_KEY_ID),
                r.get(DISCOVERED_SUBACCOUNTS.SUBACCOUNT_GUID),
                r.get(DISCOVERED_SUBACCOUNTS.DISPLAY_NAME),
                r.get(DISCOVERED_SUBACCOUNTS.SUBDOMAIN),
                r.get(DISCOVERED_SUBACCOUNTS.REGION),
                r.get(DISCOVERED_SUBACCOUNTS.PARENT_TYPE),
                r.get(DISCOVERED_SUBACCOUNTS.PARENT_GUID),
                r.get(DISCOVERED_SUBACCOUNTS.GLOBAL_ACCOUNT_GUID),
                r.get(DISCOVERED_SUBACCOUNTS.STATE),
                r.get(DISCOVERED_SUBACCOUNTS.STATE_MESSAGE),
                r.get(DISCOVERED_SUBACCOUNTS.BETA_ENABLED),
                r.get(DISCOVERED_SUBACCOUNTS.USED_FOR_PRODUCTION),
                r.get(DISCOVERED_SUBACCOUNTS.DESCRIPTION),
                r.get(DISCOVERED_SUBACCOUNTS.DISCOVERED_AT),
                r.get(DISCOVERED_SUBACCOUNTS.LAST_SEEN_AT),
                r.get(ENROLLED_SUBACCOUNT_ID));
    }
}
