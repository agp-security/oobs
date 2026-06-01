// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.cis;

import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Component
public class CisTokenCache {

    private static final Duration SAFETY_MARGIN = Duration.ofSeconds(60);

    private final ConcurrentMap<String, Entry> entries = new ConcurrentHashMap<>();

    public String key(String uaaUrl, String clientId) {
        return uaaUrl + "|" + clientId;
    }

    public String getOrNull(String key) {
        Entry e = entries.get(key);
        if (e == null) return null;
        if (Instant.now().isAfter(e.expiresAt.minus(SAFETY_MARGIN))) {
            entries.remove(key, e);
            return null;
        }
        return e.token;
    }

    public void put(String key, String token, Duration ttl) {
        entries.put(key, new Entry(token, Instant.now().plus(ttl)));
    }

    public void invalidate(String key) {
        entries.remove(key);
    }

    public int size() {
        return entries.size();
    }

    private record Entry(String token, Instant expiresAt) {}
}
