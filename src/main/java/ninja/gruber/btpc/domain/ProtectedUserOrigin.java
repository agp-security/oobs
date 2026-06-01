// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.domain;

public enum ProtectedUserOrigin {
    MANUAL("manual"),
    SELF("self"),
    SYSTEM("system"),
    RULE("rule");

    private final String dbValue;

    ProtectedUserOrigin(String dbValue) { this.dbValue = dbValue; }

    public String dbValue() { return dbValue; }

    public static ProtectedUserOrigin fromDb(String v) {
        for (ProtectedUserOrigin o : values()) if (o.dbValue.equals(v)) return o;
        throw new IllegalArgumentException("unknown origin: " + v);
    }
}
