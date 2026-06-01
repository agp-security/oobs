// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

// SSRF mitigation: every URL, also for Splunk HEC and! Audit log service needs to be in a whitelist defined at the app start to prevent credentials leakage from xsuaa admin users.
@Component
public class UrlAllowlist {

    private final List<String> suffixes;

    public UrlAllowlist(
            @Value("${btpc.security.allowed-host-suffixes:.hana.ondemand.com,.cloud.sap,.accounts.ondemand.com,.trial-accounts.ondemand.com}")
            String csv) {
        this.suffixes = Arrays.stream(csv.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(s -> s.toLowerCase(Locale.ROOT))
                .toList();
    }

    public boolean isAllowed(String url) {
        if (url == null || url.isBlank()) return false;
        try {
            URI u = URI.create(url);
            String host = u.getHost();
            if (host == null) return false;
            String h = host.toLowerCase(Locale.ROOT);
            for (String s : suffixes) {
                if (s.startsWith(".")) {
                    if (h.endsWith(s) || ("." + h).endsWith(s)) return true;
                } else if (h.equals(s)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    public void requireAllowed(String url, String fieldName) {
        if (!isAllowed(url)) {
            throw new IllegalArgumentException(
                    "URL in field '" + fieldName + "' is not in the allowed-host suffix list: " + url +
                            " (allowed: " + suffixes + ")");
        }
    }
}
