// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.audit.custom.domain;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.OffsetDateTime;
import java.util.UUID;

public record AuditSinkConfig(
        UUID id, //later..?!
        Kind kind,
        boolean enabled,
        JsonNode configPlaintext,
        boolean hasSecret,
        OffsetDateTime lastTestAt,
        String lastTestStatus,
        String lastTestMessage,
        OffsetDateTime updatedAt,
        String updatedBy
) {
    public enum Kind {
        //key for db field (check)
        SPLUNK_HEC("splunk_hec"),
        BTP_AUDIT_LOG("btp_audit_log");

        private final String dbValue;
        Kind(String dbValue) { this.dbValue = dbValue; }
        public String dbValue() { return dbValue; }
        public static Kind fromDb(String v) {
            for (Kind k : values()) if (k.dbValue.equals(v)) return k;
            throw new IllegalArgumentException("unknown audit sink kind: " + v);
        }
    }
}
