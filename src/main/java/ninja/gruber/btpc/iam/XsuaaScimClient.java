// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.iam;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ninja.gruber.btpc.cis.CisException;
import ninja.gruber.btpc.cis.CisTokenCache;
import ninja.gruber.btpc.config.UrlAllowlist;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;

@Component
public class XsuaaScimClient {

    private static final Logger log = LoggerFactory.getLogger(XsuaaScimClient.class);
    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(20);

    private static final int MAX_RETRY_ATTEMPTS = 4;
    private static final Duration MAX_RETRY_AFTER = Duration.ofSeconds(10);
    private static final Duration BASE_BACKOFF = Duration.ofSeconds(1);

    private final HttpClient http;
    private final ObjectMapper mapper;
    private final CisTokenCache tokenCache;
    private final UrlAllowlist allowlist;

    public XsuaaScimClient(ObjectMapper mapper, CisTokenCache tokenCache, UrlAllowlist allowlist) {
        this.mapper = mapper;
        this.tokenCache = tokenCache;
        this.allowlist = allowlist;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    // Cheap auth probe for the health-check job: client-credentials token
    // round-trip only. Any non-2xx surfaces as an exception for the caller.
    public void ping(String serviceKeyJson) {
        obtainToken(credsNode(parse(serviceKeyJson)));
    }

    public List<ShadowUser> listShadowUsers(String serviceKeyJson) {
        JsonNode creds = credsNode(parse(serviceKeyJson));
        String apiUrl = requiredText(creds, "apiurl", "apiurl missing from XSUAA key");
        String token = obtainToken(creds);
        List<ShadowUser> all = new ArrayList<>();
        int start = 1;
        int pageSize = 100;
        for (int safety = 0; safety < 100; safety++) {
            JsonNode body = sendJson("GET", apiUrl + "/Users?startIndex=" + start + "&count=" + pageSize,
                    token, null);
            JsonNode arr = body.path("resources");
            if (!arr.isArray() || arr.isEmpty()) arr = body.path("Resources");
            if (!arr.isArray() || arr.isEmpty()) break;
            int count = 0;
            for (Iterator<JsonNode> it = arr.elements(); it.hasNext(); ) {
                all.add(toShadowUser(it.next()));
                count++;
            }
            int total = body.path("totalResults").asInt(all.size());
            if (all.size() >= total || count < pageSize) break;
            start += count;
        }
        return all;
    }

    public Optional<ShadowUser> findUserByEmail(String serviceKeyJson, String email) {
        List<ShadowUser> all = findShadowUsersByEmail(serviceKeyJson, email);
        return all.isEmpty() ? Optional.empty() : Optional.of(all.get(0));
    }

    public List<ShadowUser> findShadowUsersByEmail(String serviceKeyJson, String email) {
        JsonNode creds = credsNode(parse(serviceKeyJson));
        String apiUrl = requiredText(creds, "apiurl", "apiurl missing from XSUAA key");
        String token = obtainToken(creds);
        String filter = "userName eq \"" + jsonEscape(email) + "\"";
        String url = apiUrl + "/Users?filter=" + URLEncoder.encode(filter, StandardCharsets.UTF_8);
        JsonNode body = sendJson("GET", url, token, null);
        JsonNode resources = body.path("resources");
        if (!resources.isArray() || resources.isEmpty()) resources = body.path("Resources");
        List<ShadowUser> out = new ArrayList<>();
        if (resources.isArray()) {
            for (Iterator<JsonNode> it = resources.elements(); it.hasNext(); ) {
                out.add(toShadowUser(it.next()));
            }
        }
        return out;
    }

    public List<Group> listGroups(String serviceKeyJson) {
        JsonNode creds = credsNode(parse(serviceKeyJson));
        String apiUrl = requiredText(creds, "apiurl", "apiurl missing from XSUAA key");
        String token = obtainToken(creds);
        List<Group> all = new ArrayList<>();
        int start = 1;
        int pageSize = 100;
        for (int safety = 0; safety < 1000; safety++) {
            JsonNode body = sendJson("GET", apiUrl + "/Groups?startIndex=" + start + "&count=" + pageSize,
                    token, null);
            JsonNode arr = body.path("resources");
            if (!arr.isArray() || arr.isEmpty()) arr = body.path("Resources");
            if (!arr.isArray() || arr.isEmpty()) break;
            int count = 0;
            for (Iterator<JsonNode> it = arr.elements(); it.hasNext(); ) {
                all.add(toGroup(it.next()));
                count++;
            }
            int total = body.path("totalResults").asInt(all.size());
            if (all.size() >= total || count < pageSize) break;
            start += count;
        }
        return all;
    }

    public void removeMember(String serviceKeyJson, String groupId, String userId) {
        JsonNode creds = credsNode(parse(serviceKeyJson));
        String apiUrl = requiredText(creds, "apiurl", "apiurl missing from XSUAA key");
        String token = obtainToken(creds);
        String body = "{\"schemas\":[\"urn:scim:schemas:core:1.0\"],"
                + "\"members\":[{\"value\":\"" + jsonEscape(userId) + "\",\"operation\":\"delete\"}]}";
        String url = apiUrl + "/Groups/" + pathEncode(groupId);
        try {
            sendPatch(url, token, body);
        } catch (CisException e) {
            if (e.upstreamStatus() == 404) {
                log.debug("removeMember: group {} no longer exists, treating as idempotent success", groupId);
                return;
            }
            throw e;
        }
    }

    public void addMember(String serviceKeyJson, String groupId, String userId, String origin) {
        JsonNode creds = credsNode(parse(serviceKeyJson));
        String apiUrl = requiredText(creds, "apiurl", "apiurl missing from XSUAA key");
        String token = obtainToken(creds);
        StringBuilder mem = new StringBuilder()
                .append("{\"value\":\"").append(jsonEscape(userId)).append("\",\"type\":\"USER\"");
        if (origin != null && !origin.isBlank()) {
            mem.append(",\"origin\":\"").append(jsonEscape(origin)).append("\"");
        }
        mem.append("}");
        String body = "{\"schemas\":[\"urn:scim:schemas:core:1.0\"],"
                + "\"members\":[" + mem + "]}";
        sendPatch(apiUrl + "/Groups/" + pathEncode(groupId), token, body);
    }

    public void deleteShadowUser(String serviceKeyJson, String userId) {
        JsonNode creds = credsNode(parse(serviceKeyJson));
        String apiUrl = requiredText(creds, "apiurl", "apiurl missing from XSUAA key");
        String token = obtainToken(creds);
        sendJson("DELETE", apiUrl + "/Users/" + pathEncode(userId), token, null);
    }

    public ShadowUser createShadowUser(String serviceKeyJson, String email, String origin) {
        JsonNode creds = credsNode(parse(serviceKeyJson));
        String apiUrl = requiredText(creds, "apiurl", "apiurl missing from XSUAA key");
        String token = obtainToken(creds);
        String body = "{\"schemas\":[\"urn:scim:schemas:core:1.0\"],"
                + "\"userName\":\"" + jsonEscape(email) + "\","
                + "\"origin\":\"" + jsonEscape(origin) + "\","
                + "\"emails\":[{\"value\":\"" + jsonEscape(email) + "\",\"primary\":true}],"
                + "\"active\":true}";
        JsonNode res = sendJson("POST", apiUrl + "/Users", token, body);
        return toShadowUser(res);
    }

    public List<IdentityProvider> listIdentityProviders(String serviceKeyJson) {
        JsonNode creds = credsNode(parse(serviceKeyJson));
        String apiUrl = requiredText(creds, "apiurl", "apiurl missing from XSUAA key");
        String token = obtainToken(creds);
        JsonNode body = sendJson("GET", apiUrl + "/sap/rest/identity-providers", token, null);
        List<IdentityProvider> out = new ArrayList<>();
        // The endpoint returns a bare JSON array, not a SCIM-style envelope.
        JsonNode arr = body.isArray() ? body : body.path("identityProviders");
        if (arr.isArray()) {
            for (Iterator<JsonNode> it = arr.elements(); it.hasNext(); ) {
                JsonNode n = it.next();
                out.add(new IdentityProvider(
                        textOrNull(n, "originKey"),
                        textOrNull(n, "name"),
                        textOrNull(n, "type"),
                        n.path("active").isBoolean() ? n.get("active").asBoolean() : null));
            }
        }
        return out;
    }

    public record IdentityProvider(String originKey, String name, String type, Boolean active) {}

    public List<IdpRcMapping> listIdpRoleCollectionMappings(String serviceKeyJson, String originKey) {
        JsonNode creds = credsNode(parse(serviceKeyJson));
        String apiUrl = requiredText(creds, "apiurl", "apiurl missing from XSUAA key");
        String token = obtainToken(creds);
        String url = apiUrl + "/sap/rest/authorization/v2/identity-providers/"
                + pathEncode(originKey) + "/attributes/rolecollections";
        JsonNode body = sendJson("GET", url, token, null);
        List<IdpRcMapping> out = new ArrayList<>();
        JsonNode arr = body.isArray() ? body : body.path("value");
        if (arr.isArray()) {
            for (Iterator<JsonNode> it = arr.elements(); it.hasNext(); ) {
                JsonNode n = it.next();
                out.add(new IdpRcMapping(
                        textOrNull(n, "roleCollectionName"),
                        textOrNull(n, "attributeName"),
                        textOrNull(n, "attributeValue"),
                        textOrNull(n, "comparisonOperator")));
            }
        }
        return out;
    }

    public record IdpRcMapping(String roleCollectionName,
                               String attributeName,
                               String attributeValue,
                               String comparisonOperator) {}

    private static String pathEncode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static String jsonEscape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static ShadowUser toShadowUser(JsonNode n) {
        return new ShadowUser(
                textOrNull(n, "id"),
                textOrNull(n, "userName"),
                textOrNull(n, "origin"),
                textOrNull(n, "externalId")
        );
    }

    private static Group toGroup(JsonNode n) {
        String id = textOrNull(n, "id");
        String displayName = textOrNull(n, "displayName");
        List<Member> members = new ArrayList<>();
        JsonNode arr = n.path("members");
        if (arr.isArray()) {
            for (Iterator<JsonNode> it = arr.elements(); it.hasNext(); ) {
                JsonNode m = it.next();
                members.add(new Member(
                        textOrNull(m, "origin"),
                        textOrNull(m, "value"),
                        textOrNull(m, "type")));
            }
        }
        return new Group(id, displayName, members);
    }

    static JsonNode credsNode(JsonNode root) {
        return ninja.gruber.btpc.enroll.ServiceKeyClassifier.xsuaaCredsNode(root);
    }

    private String obtainToken(JsonNode creds) {
        String url = requiredText(creds, "url", "url missing from XSUAA key");
        allowlist.requireAllowed(url, "xsuaa.url");
        String clientId = requiredText(creds, "clientid", "clientid missing from XSUAA key");
        String clientSecret = requiredText(creds, "clientsecret", "clientsecret missing from XSUAA key");
        String cacheKey = tokenCache.key(url, clientId);
        String cached = tokenCache.getOrNull(cacheKey);
        if (cached != null) return cached;

        String basic = Base64.getEncoder().encodeToString(
                (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url + "/oauth/token"))
                .timeout(HTTP_TIMEOUT)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .header("Authorization", "Basic " + basic)
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials",
                        StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> res;
        try {
            res = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new CisException("XSUAA token call failed: " + e.getMessage(), e);
        }
        if (res.statusCode() / 100 != 2) {
            throw new CisException("XSUAA token endpoint returned HTTP " + res.statusCode(),
                    res.statusCode(), truncate(res.body()));
        }
        JsonNode tokenJson = parse(res.body());
        String access = textOrNull(tokenJson, "access_token");
        if (access == null) {
            throw new CisException("XSUAA response missing access_token",
                    res.statusCode(), truncate(res.body()));
        }
        long ttl = tokenJson.path("expires_in").asLong(3600);
        tokenCache.put(cacheKey, access, Duration.ofSeconds(ttl));
        log.debug("obtained XSUAA token for {} (ttl={}s)", clientId, ttl);
        return access;
    }

    private JsonNode sendJson(String method, String url, String bearer, String body) {
        allowlist.requireAllowed(url, "xsuaa.apiurl");
        HttpRequest.Builder b = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(HTTP_TIMEOUT)
                .header("Authorization", "Bearer " + bearer)
                .header("Accept", "application/json");
        if (body != null) {
            b.header("Content-Type", "application/json");
            b.method(method, HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        } else {
            b.method(method, HttpRequest.BodyPublishers.noBody());
        }
        HttpResponse<String> res = sendWithRetry(b.build(), method + " " + url);
        if (res.statusCode() / 100 != 2) {
            throw new CisException("XSUAA " + method + " " + url + " returned HTTP " + res.statusCode(),
                    res.statusCode(), truncate(res.body()));
        }
        if (res.body() == null || res.body().isEmpty()) return mapper.createObjectNode();
        return parse(res.body());
    }

    private JsonNode sendPatch(String url, String bearer, String body) {
        allowlist.requireAllowed(url, "xsuaa.apiurl");
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(HTTP_TIMEOUT)
                .header("Authorization", "Bearer " + bearer)
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .header("If-Match", "*")
                .method("PATCH", HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> res = sendWithRetry(req, "PATCH " + url);
        if (res.statusCode() / 100 != 2) {
            throw new CisException("XSUAA PATCH " + url + " returned HTTP " + res.statusCode(),
                    res.statusCode(), truncate(res.body()));
        }
        if (res.body() == null || res.body().isEmpty()) return mapper.createObjectNode();
        return parse(res.body());
    }

    //had only one issue here
    private HttpResponse<String> sendWithRetry(HttpRequest req, String label) {
        HttpResponse<String> res;
        for (int attempt = 1; ; attempt++) {
            try {
                res = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            } catch (Exception e) {
                throw new CisException("XSUAA " + label + " failed: " + e.getMessage(), e);
            }
            if (res.statusCode() != 429 || attempt >= MAX_RETRY_ATTEMPTS) return res;
            Duration sleep = parseRetryAfter(res, attempt);
            log.warn("XSUAA {} returned HTTP 429 (attempt {}/{}), backing off {} ms before retry",
                    label, attempt, MAX_RETRY_ATTEMPTS, sleep.toMillis());
            try {
                Thread.sleep(sleep.toMillis());
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                throw new CisException("XSUAA " + label + " retry interrupted", ie);
            }
        }
    }

    private static Duration parseRetryAfter(HttpResponse<?> res, int attempt) {
        Optional<String> hdr = res.headers().firstValue("Retry-After");
        if (hdr.isPresent()) {
            String raw = hdr.get().trim();
            try {
                long secs = Long.parseLong(raw);
                if (secs > 0) {
                    Duration d = Duration.ofSeconds(secs);
                    return d.compareTo(MAX_RETRY_AFTER) > 0 ? MAX_RETRY_AFTER : d;
                }
            } catch (NumberFormatException ignored) {
            }
        }
        long ms = BASE_BACKOFF.toMillis() * (1L << (attempt - 1));
        return Duration.ofMillis(Math.min(ms, MAX_RETRY_AFTER.toMillis()));
    }

    private JsonNode parse(String json) {
        try { return mapper.readTree(json); }
        catch (Exception e) { throw new CisException("Failed to parse JSON: " + e.getMessage(), e); }
    }

    private static String requiredText(JsonNode node, String field, String msg) {
        JsonNode v = node.path(field);
        if (!v.isTextual() || v.asText().isBlank()) throw new CisException(msg, 0, null);
        return v.asText();
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode v = node.path(field);
        return v.isTextual() ? v.asText() : null;
    }

    private static String truncate(String s) {
        if (s == null) return null;
        return s.length() <= 50 ? s : s.substring(0, 50) + "...";
    }

    public record ShadowUser(String id, String userName, String origin, String externalId) {}

    public record Group(String id, String displayName, List<Member> members) {}

    public record Member(String origin, String userId, String type) {}
}
