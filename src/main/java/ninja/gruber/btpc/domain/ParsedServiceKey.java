// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.domain;

import java.util.UUID;

public record ParsedServiceKey(
        CredentialKind kind,
        UUID subaccountGuid,
        String region,
        String identityZone,
        String rawJson
) {
    public boolean isCis() { return kind == CredentialKind.CIS; }
    public boolean isIas() { return kind == CredentialKind.IAS; }
}
