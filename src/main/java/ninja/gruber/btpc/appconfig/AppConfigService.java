// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.appconfig;

import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

@Service
public class AppConfigService {

    public static final String KEY_EXTERNAL_EMAIL_DOMAINS = "external_email.internal_domains";
    public static final String KEY_HEALTH_AUTO_INTERVAL_SECONDS = "health.auto.interval_seconds";

    private static final Set<String> KNOWN_KEYS = Set.of(
            KEY_EXTERNAL_EMAIL_DOMAINS, KEY_HEALTH_AUTO_INTERVAL_SECONDS);

    private final AppConfigRepo repo;

    public AppConfigService(AppConfigRepo repo) {
        this.repo = repo;
    }

    public String getExternalEmailDomainsCsv() {
        return repo.getValue(KEY_EXTERNAL_EMAIL_DOMAINS)
                .orElse("");
    }

    public Set<String> getInternalDomains() {
        return parseDomainsCsv(getExternalEmailDomainsCsv());
    }

    public Long getHealthAutoIntervalSeconds() {
        return repo.getValue(KEY_HEALTH_AUTO_INTERVAL_SECONDS)
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(s -> {
                    try { return Long.parseLong(s); }
                    catch (NumberFormatException e) { return 0L; }
                })
                .orElse(0L);
    }

    public void putWhitelisted(String key, String value, String actor) {
        if (key == null || key.isBlank()) throw new IllegalArgumentException("key required");
        if (!KNOWN_KEYS.contains(key)) {
            throw new IllegalArgumentException("unknown config key: " + key
                    + " | known keys: " + KNOWN_KEYS);
        }
        repo.put(key, value == null ? "" : value, actor == null ? "unknown" : actor);
    }

    public static Set<String> parseDomainsCsv(String csv) {
        if (csv == null || csv.isBlank()) return Collections.emptySet();
        Set<String> out = new HashSet<>();
        for (String raw : csv.split(",")) {
            String d = raw.trim().toLowerCase(Locale.ROOT);
            if (d.startsWith("@")) d = d.substring(1); // also allow @ as first symbol
            if (!d.isEmpty()) out.add(d);
        }
        return out;
    }
}
