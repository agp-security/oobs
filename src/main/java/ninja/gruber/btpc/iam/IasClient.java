// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.iam;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ninja.gruber.btpc.cis.CisException;
import ninja.gruber.btpc.config.UrlAllowlist;
import org.springframework.stereotype.Component;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

@Component
public class IasClient {

    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(20);
    private static final String SCIM_PATCH_SCHEMA =
            "urn:ietf:params:scim:api:messages:2.0:PatchOp";

    private final ObjectMapper mapper;
    private final UrlAllowlist allowlist;

    public IasClient(ObjectMapper mapper, UrlAllowlist allowlist) {
        this.mapper = mapper;
        this.allowlist = allowlist;
    }

    private Ctx ctx(String serviceKeyJson) {
        JsonNode key = parse(serviceKeyJson);
        String base = requiredText(key, "url", "url missing from IAS key");
        allowlist.requireAllowed(base, "ias.url");
        return new Ctx(base, buildHttpClient(key, base));
    }

    private record Ctx(String base, HttpClient http) {}

    // Cheap auth probe for the health-check job: an mTLS SCIM GET with a
    // sentinel filter that returns an empty Resources array on success. Any
    // non-2xx (e.g. a rejected client cert) surfaces as CisException.
    public void ping(String serviceKeyJson) {
        Ctx c = ctx(serviceKeyJson);
        String filter = "userName eq \"__btpc-health-probe__\"";
        String url = c.base() + "/scim/Users?filter="
                + URLEncoder.encode(filter, StandardCharsets.UTF_8) + "&count=1";
        sendJson(c.http(), "GET", url, null);
    }

    public Optional<IasUser> findUserByEmail(String serviceKeyJson, String email) {
        Ctx c = ctx(serviceKeyJson);
        String filter = "userName eq \"" + scimQuote(email) + "\"";
        String url = c.base() + "/scim/Users?filter=" + URLEncoder.encode(filter, StandardCharsets.UTF_8);
        JsonNode body = sendJson(c.http(), "GET", url, null);
        JsonNode resources = body.path("Resources"); //case
        if (!resources.isArray() || resources.isEmpty()) return Optional.empty();
        return Optional.of(toIasUser(resources.get(0)));
    }

    public IasUser setActive(String serviceKeyJson, String userId, boolean active) {
        Ctx c = ctx(serviceKeyJson);
        String patch = "{\"schemas\":[\"" + SCIM_PATCH_SCHEMA + "\"]," +
                "\"Operations\":[{\"op\":\"replace\",\"path\":\"active\",\"value\":" + active + "}]}";
        JsonNode body = sendJson(c.http(), "PATCH",
                c.base() + "/scim/Users/" + URLEncoder.encode(userId, StandardCharsets.UTF_8),
                patch);
        return toIasUser(body);
    }

    public List<IasGroupRef> listUserGroups(String serviceKeyJson, String userId) {
        Ctx c = ctx(serviceKeyJson);
        JsonNode body = sendJson(c.http(), "GET",
                c.base() + "/scim/Users/" + URLEncoder.encode(userId, StandardCharsets.UTF_8),
                null);
        List<IasGroupRef> out = new java.util.ArrayList<>();
        JsonNode groups = body.path("groups");
        if (groups.isArray()) {
            for (JsonNode g : groups) {
                String id = textOrNull(g, "value");
                if (id == null) continue;
                out.add(new IasGroupRef(id, textOrNull(g, "display")));
            }
        }
        return out;
    }

    public void removeUserFromGroup(String serviceKeyJson, String groupId, String userId) {
        Ctx c = ctx(serviceKeyJson);
        HttpClient http = c.http();
        String groupUrl = c.base() + "/scim/Groups/" + URLEncoder.encode(groupId, StandardCharsets.UTF_8);

        JsonNode group = sendJson(http, "GET", groupUrl, null);
        JsonNode members = group.path("members");
        if (!members.isArray() || members.isEmpty()) return;
        boolean found = false;
        StringBuilder kept = new StringBuilder("[");
        boolean first = true;
        for (JsonNode m : members) {
            String v = textOrNull(m, "value");
            if (v != null && v.equals(userId)) { found = true; continue; }
            if (!first) kept.append(",");
            try { kept.append(mapper.writeValueAsString(m)); }
            catch (Exception e) {
                throw new CisException("could not re-serialise IAS group member: " + e.getMessage(), e);
            }
            first = false;
        }
        kept.append("]");
        if (!found) return;

        String patch = "{\"schemas\":[\"" + SCIM_PATCH_SCHEMA + "\"],\"Operations\":["
                + "{\"op\":\"replace\",\"path\":\"members\",\"value\":" + kept + "}]}";
        sendJson(http, "PATCH", groupUrl, patch);
    }

    public void addUserToGroup(String serviceKeyJson, String groupId, String userId) {
        Ctx c = ctx(serviceKeyJson);
        String patch = "{\"schemas\":[\"" + SCIM_PATCH_SCHEMA + "\"],\"Operations\":["
                + "{\"op\":\"add\",\"path\":\"members\","
                + "\"value\":[{\"value\":\"" + scimQuote(userId) + "\"}]}]}";
        sendJson(c.http(), "PATCH",
                c.base() + "/scim/Groups/" + URLEncoder.encode(groupId, StandardCharsets.UTF_8),
                patch);
    }

    public record IasGroupRef(String id, String displayName) {}

    private static IasUser toIasUser(JsonNode n) {
        return new IasUser(
                textOrNull(n, "id"),
                textOrNull(n, "userName"),
                n.has("active") && n.get("active").isBoolean() ? n.get("active").asBoolean() : null,
                textOrNull(n.path("name"), "givenName"),
                textOrNull(n.path("name"), "familyName")
        );
    }

    private HttpClient buildHttpClient(JsonNode key, String url) {
        if (url.startsWith("https://")) {
            String p12Base64 = requiredText(key, "p12Base64",
                    "p12Base64 missing from IAS key (X509_GENERATED Application binding required)");
            JsonNode pwNode = key.path("p12Password");
            String p12Password = pwNode.isTextual() ? pwNode.asText() : "";
            return buildMtlsClient(p12Base64, p12Password);
        }
        return HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    private static HttpClient buildMtlsClient(String p12Base64, String p12Password) {
        try {
            byte[] p12Bytes = Base64.getDecoder().decode(p12Base64);
            char[] pw = p12Password == null ? new char[0] : p12Password.toCharArray();
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new ByteArrayInputStream(p12Bytes), pw);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, pw);
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), null, null);
            return HttpClient.newBuilder()
                    .sslContext(sslContext)
                    .connectTimeout(Duration.ofSeconds(10))
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();
        } catch (Exception e) {
            throw new CisException("failed to build mTLS client from IAS P12: " + e.getMessage(), e);
        }
    }

    private JsonNode sendJson(HttpClient http, String method, String url, String body) {
        HttpRequest.Builder b = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(HTTP_TIMEOUT)
                .header("Accept", "application/scim+json, application/json");
        if (body != null) {
            b.header("Content-Type", "application/scim+json");
            b.method(method, HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        } else {
            b.method(method, HttpRequest.BodyPublishers.noBody());
        }
        HttpResponse<String> res;
        try {
            res = http.send(b.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (Exception ex) {
            throw new CisException("IAS " + method + " " + url + " failed: " + ex.getMessage(), ex);
        }
        if (res.statusCode() / 100 != 2) {
            String upstreamBody = truncate(res.body());
            String suffix = (upstreamBody == null || upstreamBody.isBlank())
                    ? "" : " body=" + upstreamBody;
            throw new CisException("IAS " + method + " " + url + " returned HTTP "
                    + res.statusCode() + suffix,
                    res.statusCode(), upstreamBody);
        }
        if (res.body() == null || res.body().isEmpty()) {
            return mapper.createObjectNode();
        }
        return parse(res.body());
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

    private static String scimQuote(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String truncate(String s) {
        if (s == null) return null;
        return s.length() <= 500 ? s : s.substring(0, 500) + "...";
    }

    public record IasUser(String id, String userName, Boolean active,
                          String givenName, String familyName) {}
}
