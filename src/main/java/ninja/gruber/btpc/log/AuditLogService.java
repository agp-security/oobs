// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.log;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jooq.Condition;
import org.jooq.Cursor;
import org.jooq.DSLContext;
import org.jooq.JSONB;
import org.jooq.Record;
import org.jooq.ResultQuery;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static ninja.gruber.btpc.jooq.Tables.CONTAINMENT_EVENTS;
import static ninja.gruber.btpc.jooq.Tables.IAS_TENANTS;
import static ninja.gruber.btpc.jooq.Tables.SUBACCOUNTS;
import static org.jooq.impl.DSL.noCondition;
import static org.jooq.impl.SQLDataType.CLOB;

@Service
public class AuditLogService {

    private final DSLContext dsl;
    private final ObjectMapper mapper;

    public AuditLogService(DSLContext dsl, ObjectMapper mapper) {
        this.dsl = dsl;
        this.mapper = mapper;
    }

    // Filter inputs for both list() and the export streams. All optional.
    public record FilterCriteria(
            String action,
            String outcome,
            String actor,
            String targetEmail,
            String fromDate,
            String toDate,
            UUID   subaccountId,
            String systemType,        // 'SUBACCOUNT' | 'IAS' | 'ONPREM' | 'INTERNAL'
            UUID   iasTenantId
    ) {}

    public List<Map<String, Object>> list(FilterCriteria c, int limit) {
        List<Map<String, Object>> rows = new ArrayList<>();
        try (Cursor<? extends Record> cursor = query(c, limit).fetchLazy()) {
            cursor.forEach(r -> rows.add(recordToMap(r)));
        }
        return rows;
    }

    public void streamCsv(FilterCriteria c, int limit, OutputStream out) {
        PrintWriter w = new PrintWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8));
        w.println("startedAt,correlationId,systemType,subaccountDisplayName,iasTenantName,"
                + "action,outcome,actor,actorSource,targetUserEmail,targetUserId,errorMessage,details");
        try (Cursor<? extends Record> cursor = query(c, limit).fetchLazy()) {
            cursor.forEach(r -> {
                w.print(csvEscape(r.get(CONTAINMENT_EVENTS.STARTED_AT)));      w.print(',');
                w.print(csvEscape(r.get(CONTAINMENT_EVENTS.CORRELATION_ID)));  w.print(',');
                w.print(csvEscape(r.get(CONTAINMENT_EVENTS.SYSTEM_TYPE)));     w.print(',');
                w.print(csvEscape(r.get(SUBACCOUNTS.CIS_DISPLAY_NAME)));       w.print(',');
                w.print(csvEscape(r.get(IAS_TENANTS.DISPLAY_NAME)));           w.print(',');
                w.print(csvEscape(r.get(CONTAINMENT_EVENTS.ACTION)));          w.print(',');
                w.print(csvEscape(r.get(CONTAINMENT_EVENTS.OUTCOME)));         w.print(',');
                w.print(csvEscape(r.get(CONTAINMENT_EVENTS.ACTOR)));           w.print(',');
                w.print(csvEscape(r.get(CONTAINMENT_EVENTS.ACTOR_SOURCE)));    w.print(',');
                w.print(csvEscape(r.get(CONTAINMENT_EVENTS.TARGET_USER_EMAIL))); w.print(',');
                w.print(csvEscape(r.get(CONTAINMENT_EVENTS.TARGET_USER_ID)));  w.print(',');
                w.print(csvEscape(r.get(CONTAINMENT_EVENTS.ERROR_MESSAGE)));   w.print(',');
                JSONB det = r.get(CONTAINMENT_EVENTS.DETAILS);
                w.print(csvEscape(det == null ? null : det.data()));           w.println();
            });
        }
        w.flush();
    }

    public void streamJson(FilterCriteria c, int limit, OutputStream out) throws IOException {
        try (JsonGenerator g = mapper.getFactory().createGenerator(out)) {
            g.writeStartArray();
            try (Cursor<? extends Record> cursor = query(c, limit).fetchLazy()) {
                cursor.forEach(r -> {
                    try {
                        writeRowJson(g, r);
                    } catch (IOException ioe) {
                        throw new RuntimeException(ioe);
                    }
                });
            }
            g.writeEndArray();
            g.flush();
        }
    }

    private ResultQuery<? extends Record> query(FilterCriteria c, int limit) {
        return dsl
                .select(
                        CONTAINMENT_EVENTS.STARTED_AT,
                        CONTAINMENT_EVENTS.CORRELATION_ID,
                        CONTAINMENT_EVENTS.SYSTEM_ID,
                        CONTAINMENT_EVENTS.SYSTEM_TYPE,
                        CONTAINMENT_EVENTS.ACTION,
                        CONTAINMENT_EVENTS.OUTCOME,
                        CONTAINMENT_EVENTS.ACTOR,
                        CONTAINMENT_EVENTS.ACTOR_SOURCE,
                        CONTAINMENT_EVENTS.TARGET_USER_EMAIL,
                        CONTAINMENT_EVENTS.TARGET_USER_ID,
                        CONTAINMENT_EVENTS.ERROR_MESSAGE,
                        CONTAINMENT_EVENTS.DETAILS,
                        SUBACCOUNTS.CIS_DISPLAY_NAME,
                        IAS_TENANTS.DISPLAY_NAME)
                .from(CONTAINMENT_EVENTS)
                .leftJoin(SUBACCOUNTS)
                .on(SUBACCOUNTS.ID.cast(CLOB).eq(CONTAINMENT_EVENTS.SYSTEM_ID)
                        .and(CONTAINMENT_EVENTS.SYSTEM_TYPE.eq("SUBACCOUNT")))
                .leftJoin(IAS_TENANTS)
                .on(IAS_TENANTS.ID.cast(CLOB).eq(CONTAINMENT_EVENTS.SYSTEM_ID)
                        .and(CONTAINMENT_EVENTS.SYSTEM_TYPE.eq("IAS")))
                .where(conditions(c))
                .orderBy(CONTAINMENT_EVENTS.STARTED_AT.desc())
                .limit(limit);
    }

    private static Condition conditions(FilterCriteria c) {
        Condition cond = noCondition();
        cond = andEq(cond, CONTAINMENT_EVENTS.ACTION,           c.action());
        cond = andEq(cond, CONTAINMENT_EVENTS.OUTCOME,          c.outcome());
        cond = andEq(cond, CONTAINMENT_EVENTS.ACTOR,            c.actor());
        if (isPresent(c.targetEmail())) {
            cond = cond.and(CONTAINMENT_EVENTS.TARGET_USER_EMAIL.likeIgnoreCase(c.targetEmail().trim()));
        }
        OffsetDateTime fromDate = parseIsoOrNull(c.fromDate());
        if (fromDate != null) {
            cond = cond.and(CONTAINMENT_EVENTS.STARTED_AT.greaterOrEqual(fromDate));
        }
        OffsetDateTime toDate = parseIsoOrNull(c.toDate());
        if (toDate != null) {
            cond = cond.and(CONTAINMENT_EVENTS.STARTED_AT.lessThan(toDate));
        }
        if (c.subaccountId() != null) {
            cond = cond.and(CONTAINMENT_EVENTS.SYSTEM_TYPE.eq("SUBACCOUNT"))
                       .and(CONTAINMENT_EVENTS.SYSTEM_ID.eq(c.subaccountId().toString()));
        }
        if (c.iasTenantId() != null) {
            cond = cond.and(CONTAINMENT_EVENTS.SYSTEM_TYPE.eq("IAS"))
                       .and(CONTAINMENT_EVENTS.SYSTEM_ID.eq(c.iasTenantId().toString()));
        }
        if (isPresent(c.systemType())) {
            cond = cond.and(CONTAINMENT_EVENTS.SYSTEM_TYPE.eq(c.systemType().trim().toUpperCase()));
        }
        return cond;
    }

    private static Condition andEq(Condition cond, org.jooq.TableField<?, String> field, String value) {
        return isPresent(value) ? cond.and(field.eq(value.trim())) : cond;
    }

    private static Map<String, Object> recordToMap(Record r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("startedAt",             r.get(CONTAINMENT_EVENTS.STARTED_AT));
        m.put("correlationId",         r.get(CONTAINMENT_EVENTS.CORRELATION_ID));
        m.put("systemId",              r.get(CONTAINMENT_EVENTS.SYSTEM_ID));
        m.put("systemType",            r.get(CONTAINMENT_EVENTS.SYSTEM_TYPE));
        m.put("subaccountDisplayName", r.get(SUBACCOUNTS.CIS_DISPLAY_NAME));
        m.put("iasTenantName",         r.get(IAS_TENANTS.DISPLAY_NAME));
        m.put("action",                r.get(CONTAINMENT_EVENTS.ACTION));
        m.put("outcome",               r.get(CONTAINMENT_EVENTS.OUTCOME));
        m.put("actor",                 r.get(CONTAINMENT_EVENTS.ACTOR));
        m.put("actorSource",           r.get(CONTAINMENT_EVENTS.ACTOR_SOURCE));
        m.put("targetUserEmail",       r.get(CONTAINMENT_EVENTS.TARGET_USER_EMAIL));
        m.put("targetUserId",          r.get(CONTAINMENT_EVENTS.TARGET_USER_ID));
        m.put("errorMessage",          r.get(CONTAINMENT_EVENTS.ERROR_MESSAGE));
        JSONB det = r.get(CONTAINMENT_EVENTS.DETAILS);
        m.put("details",               det == null ? null : det.data());
        return m;
    }

    private static void writeRowJson(JsonGenerator g, Record r) throws IOException {
        g.writeStartObject();
        g.writeStringField("startedAt",             String.valueOf(r.get(CONTAINMENT_EVENTS.STARTED_AT)));
        g.writeStringField("correlationId",         String.valueOf(r.get(CONTAINMENT_EVENTS.CORRELATION_ID)));
        g.writeStringField("systemId",              r.get(CONTAINMENT_EVENTS.SYSTEM_ID));
        g.writeStringField("systemType",            r.get(CONTAINMENT_EVENTS.SYSTEM_TYPE));
        g.writeStringField("subaccountDisplayName", r.get(SUBACCOUNTS.CIS_DISPLAY_NAME));
        g.writeStringField("iasTenantName",         r.get(IAS_TENANTS.DISPLAY_NAME));
        g.writeStringField("action",                r.get(CONTAINMENT_EVENTS.ACTION));
        g.writeStringField("outcome",               r.get(CONTAINMENT_EVENTS.OUTCOME));
        g.writeStringField("actor",                 r.get(CONTAINMENT_EVENTS.ACTOR));
        g.writeStringField("actorSource",           r.get(CONTAINMENT_EVENTS.ACTOR_SOURCE));
        g.writeStringField("targetUserEmail",       r.get(CONTAINMENT_EVENTS.TARGET_USER_EMAIL));
        g.writeStringField("targetUserId",          r.get(CONTAINMENT_EVENTS.TARGET_USER_ID));
        g.writeStringField("errorMessage",          r.get(CONTAINMENT_EVENTS.ERROR_MESSAGE));
        JSONB det = r.get(CONTAINMENT_EVENTS.DETAILS);
        if (det != null) {
            g.writeFieldName("details");
            g.writeRawValue(det.data());
        }
        g.writeEndObject();
    }

    private static boolean isPresent(String s) {
        return s != null && !s.isBlank();
    }

    private static OffsetDateTime parseIsoOrNull(String s) {
        if (!isPresent(s)) return null;
        try {
            return OffsetDateTime.parse(s.trim());
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private static String csvEscape(Object o) {
        if (o == null) return "";
        String s = o.toString();
        boolean needsQuote = s.indexOf(',') >= 0 || s.indexOf('"') >= 0
                || s.indexOf('\n') >= 0 || s.indexOf('\r') >= 0;
        if (!needsQuote) return s;
        return "\"" + s.replace("\"", "\"\"") + "\"";
    }
}
