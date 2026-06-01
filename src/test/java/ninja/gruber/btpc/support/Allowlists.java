// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.support;

import ninja.gruber.btpc.config.UrlAllowlist;

// Test-only UrlAllowlist factory. Mirrors the production default suffixes plus
// the loopback hosts FakeBtpServer binds to
public final class Allowlists {

    private Allowlists() {}

    public static UrlAllowlist permissive() {
        return new UrlAllowlist(
                "127.0.0.1,localhost,.hana.ondemand.com,.cloud.sap,"
                        + ".accounts.ondemand.com,.trial-accounts.ondemand.com");
    }
}
