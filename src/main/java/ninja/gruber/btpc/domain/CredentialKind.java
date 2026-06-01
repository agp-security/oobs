// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.domain;

public enum CredentialKind {
    CIS("cis"),
    IAS("ias"),
    XSUAA_APIACCESS("xsuaa_apiaccess"),
    CF_TECHNICAL_USER("cf_technical_user");

    private final String dbValue;

    CredentialKind(String dbValue) {
        this.dbValue = dbValue;
    }

    public String dbValue() {
        return dbValue;
    }

    public static CredentialKind fromDb(String v) {
        for (CredentialKind k : values()) {
            if (k.dbValue.equals(v)) return k;
        }
        throw new IllegalArgumentException("unknown credential kind: " + v);
    }
}
