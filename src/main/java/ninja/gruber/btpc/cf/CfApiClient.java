// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.cf;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ninja.gruber.btpc.cis.CisException;
import ninja.gruber.btpc.cis.CisTokenCache;
import ninja.gruber.btpc.config.UrlAllowlist;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

//v3 Cloud Controller API Client
@Component
public class CfApiClient {

    private static final Logger log = LoggerFactory.getLogger(CfApiClient.class);
    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(20);

    private final HttpClient http;
    private final ObjectMapper mapper;
    private final CisTokenCache tokenCache;
    private final UrlAllowlist allowlist;

    public CfApiClient(ObjectMapper mapper, CisTokenCache tokenCache, UrlAllowlist allowlist) {
        this.mapper = mapper;
        this.tokenCache = tokenCache;
        this.allowlist = allowlist;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    private record CfCtx(String base, String token) {}

    private CfCtx cfCtx(String credJson) {
        JsonNode creds = parse(credJson);
        return new CfCtx(enforceField(creds, "cfApiUrl"), obtainToken(creds));
    }

    public List<Organization> listOrganizations(String credJson) {
        CfCtx ctx = cfCtx(credJson);
        return paginate(ctx.base() + "/v3/organizations?per_page=20", ctx.token(),
                b -> b.path("resources"),
                r -> new Organization(optString(r, "guid"), optString(r, "name")));
    }

    public List<Space> listSpaces(String credJson, String orgGuid) {
        CfCtx ctx = cfCtx(credJson);
        return paginate(
                ctx.base() + "/v3/spaces?per_page=20&organization_guids=" + orgGuid,
                ctx.token(),
                b -> b.path("resources"),
                r -> new Space(optString(r, "guid"), optString(r, "name"), orgGuid));
    }


    public List<CfUser> findUserByUsername(String credJson, String username, String origins) {
        CfCtx ctx = cfCtx(credJson);
        return paginate(
                ctx.base() + "/v3/users?per_page=200&usernames=" + encode(username) + ((origins != null && !origins.isBlank())?"&origins="+encode(origins):""),
                ctx.token(),
                b -> b.path("resources"),
                r -> new CfUser(optString(r, "guid"), optString(r, "username"), optString(r, "origin")));
    }

    public List<CfUser> findUsersAcrossOrgs(String credJson, String username) {
        return walkOrgs(credJson, username).matches();
    }

    public OrgWalkDiagnostic walkOrgs(String credJson, String username) {
        Map<String, CfUser> matches = new LinkedHashMap<>();
        Map<String, String> allSeenUsernames = new LinkedHashMap<>();
        int orgCount = 0;
        int spaceCount = 0;
        for (Organization org : listOrganizations(credJson)) {
            orgCount++;
            for (CfUser u : listUsersInOrg(credJson, org.guid())) {
                if (u.guid() != null) allSeenUsernames.putIfAbsent(u.guid(), u.username());
                if (matchesUsername(u, username) && u.guid() != null) {
                    matches.putIfAbsent(u.guid(), u);
                }
            }
            for (Space space : listSpaces(credJson, org.guid())) {
                spaceCount++;
                for (CfUser u : listUsersInSpace(credJson, space.guid())) {
                    if (u.guid() != null) allSeenUsernames.putIfAbsent(u.guid(), u.username());
                    if (matchesUsername(u, username) && u.guid() != null) {
                        matches.putIfAbsent(u.guid(), u);
                    }
                }
            }
        }
        return new OrgWalkDiagnostic(
                new ArrayList<>(matches.values()),
                orgCount, spaceCount, allSeenUsernames.size(),
                allSeenUsernames.values().stream()
                        .filter(Objects::nonNull)
                        .limit(20).toList());
    }

    private static boolean matchesUsername(CfUser u, String username) {
        return u.username() != null && u.username().equalsIgnoreCase(username);
    }

    public List<RoleEntry> listRolesForUser(String credJson,
                                            String userGuid, String orgGuid, String spaceGuid) {
        if ((orgGuid == null) == (spaceGuid == null)) {
            throw new IllegalArgumentException("listRolesForUser: pass exactly one of orgGuid / spaceGuid");
        }
        CfCtx ctx = cfCtx(credJson);
        StringBuilder url = new StringBuilder(ctx.base())
                .append("/v3/roles?per_page=20&user_guids=").append(userGuid);
        if (orgGuid != null) url.append("&organization_guids=").append(orgGuid);
        else url.append("&space_guids=").append(spaceGuid);
        return paginate(url.toString(), ctx.token(),
                b -> b.path("resources"),
                r -> new RoleEntry(
                        optString(r, "guid"),
                        optString(r, "type"),
                        userGuid, orgGuid, spaceGuid));
    }

    public List<CfUser> listUsersInOrg(String credJson, String orgGuid) {
        return listUsersByRoleScope(credJson, "organization_guids", orgGuid);
    }

    public List<CfUser> listUsersInSpace(String credJson, String spaceGuid) {
        return listUsersByRoleScope(credJson, "space_guids", spaceGuid);
    }

    private List<CfUser> listUsersByRoleScope(String credJson, String filterParam, String scopeGuid) {
        CfCtx ctx = cfCtx(credJson);
        Map<String, CfUser> seen = new LinkedHashMap<>();
        String next = ctx.base() + "/v3/roles?per_page=200&include=user&" + filterParam + "=" + scopeGuid;
        while (next != null) {
            JsonNode body = sendJson("GET", next, ctx.token(), null);
            for (JsonNode u : body.path("included").path("users")) {
                String guid = optString(u, "guid");
                if (guid == null || seen.containsKey(guid)) continue;
                seen.put(guid, new CfUser(guid,
                        optString(u, "username"),
                        optString(u, "origin")));
            }
            next = optString(body.path("pagination").path("next"), "href");
        }
        return new ArrayList<>(seen.values());
    }

    public void deleteRole(String credJson, String roleGuid) {
        CfCtx ctx = cfCtx(credJson);
        sendJson("DELETE", ctx.base() + "/v3/roles/" + roleGuid, ctx.token(), null);
    }

    public Optional<String> findServiceOfferingGuid(String credJson, String offeringName) {
        CfCtx ctx = cfCtx(credJson);
        JsonNode body = sendJson("GET",
                ctx.base() + "/v3/service_offerings?names=" + encode(offeringName), ctx.token(), null);
        for (JsonNode r : body.path("resources")) {
            String guid = optString(r, "guid");
            if (guid != null) return Optional.of(guid);
        }
        return Optional.empty();
    }

    public Optional<String> findServicePlanGuid(String credJson, String offeringGuid, String planName) {
        CfCtx ctx = cfCtx(credJson);
        JsonNode body = sendJson("GET",
                ctx.base() + "/v3/service_plans?names=" + encode(planName)
                        + "&service_offering_guids=" + offeringGuid,
                ctx.token(), null);
        for (JsonNode r : body.path("resources")) {
            String guid = optString(r, "guid");
            if (guid != null) return Optional.of(guid);
        }
        return Optional.empty();
    }

    public List<ServiceInstance> findInstancesByPlanInOrg(String credJson, String orgGuid,
                                                         String planGuid) {
        CfCtx ctx = cfCtx(credJson);
        List<Space> spaces = listSpaces(credJson, orgGuid);
        List<ServiceInstance> out = new ArrayList<>();
        for (Space sp : spaces) {
            String url = ctx.base() + "/v3/service_instances?per_page=200&type=managed"
                    + "&service_plan_guids=" + planGuid
                    + "&space_guids=" + sp.guid();
            out.addAll(paginate(url, ctx.token(),
                    b -> b.path("resources"),
                    r -> new ServiceInstance(
                            optString(r, "guid"),
                            optString(r, "name") + " (space=" + sp.name() + ")",
                            optString(r.path("last_operation"), "state"))));
        }
        return out;
    }

    public List<ServiceKey> listServiceKeys(String credJson, String instanceGuid) {
        CfCtx ctx = cfCtx(credJson);
        JsonNode body = sendJson("GET",
                ctx.base() + "/v3/service_credential_bindings?per_page=200&type=key"
                        + "&service_instance_guids=" + instanceGuid,
                ctx.token(), null);
        List<ServiceKey> out = new ArrayList<>();
        for (JsonNode r : body.path("resources")) {
            out.add(new ServiceKey(optString(r, "guid"), optString(r, "name")));
        }
        return out;
    }

    public Optional<ServiceInstance> findManagedServiceInstance(String credJson,
                                                                String spaceGuid, String name) {
        CfCtx ctx = cfCtx(credJson);
        JsonNode body = sendJson("GET",
                ctx.base() + "/v3/service_instances?names=" + encode(name)
                        + "&space_guids=" + spaceGuid + "&type=managed",
                ctx.token(), null);
        for (JsonNode r : body.path("resources")) {
            return Optional.of(new ServiceInstance(
                    optString(r, "guid"),
                    optString(r, "name"),
                    optString(r.path("last_operation"), "state")));
        }
        return Optional.empty();
    }

    public ProvisionedJob createManagedServiceInstance(String credJson, String spaceGuid,
                                                       String planGuid, String name) {
        CfCtx ctx = cfCtx(credJson);
        allowlist.requireAllowed(ctx.base(), "cf.apiUrl");
        String body = "{\"type\":\"managed\",\"name\":\"" + name + "\","
                + "\"relationships\":{"
                + "\"service_plan\":{\"data\":{\"guid\":\"" + planGuid + "\"}},"
                + "\"space\":{\"data\":{\"guid\":\"" + spaceGuid + "\"}}}}";
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(ctx.base() + "/v3/service_instances"))
                .timeout(HTTP_TIMEOUT)
                .header("Authorization", "Bearer " + ctx.token())
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> res;
        try {
            res = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new CisException("CF POST /v3/service_instances failed: " + e.getMessage(), e);
        }
        if (res.statusCode() / 100 != 2) {
            String hint = res.statusCode() == 403 ? CfHints.MISSING_SPACE_DEVELOPER : "";
            log.warn("CF POST /v3/service_instances -> HTTP {} body={}",
                    res.statusCode(), truncate(res.body()));
            throw new CisException("CF POST /v3/service_instances returned HTTP "
                    + res.statusCode() + ": " + truncate(res.body()) + hint,
                    res.statusCode(), truncate(res.body()));
        }
        String jobUrl = res.headers().firstValue("Location").orElse(null);
        String instGuid = null;
        if (res.body() != null && !res.body().isEmpty()) {
            try {
                JsonNode n = mapper.readTree(res.body());
                instGuid = optString(n, "guid");
            } catch (Exception ignored) { /* nothing - async path body may be empty */ }
        }
        return new ProvisionedJob(jobUrl, instGuid);
    }

    public boolean waitForJob(String credJson, String jobUrl, int maxSeconds) {
        if (jobUrl == null) return true;
        String token = obtainToken(parse(credJson));
        long deadline = System.currentTimeMillis() + maxSeconds * 1000L;
        int sleepMs = 2500;
        while (System.currentTimeMillis() < deadline) {
            JsonNode body = sendJson("GET", jobUrl, token, null);
            String state = optString(body, "state");
            if ("COMPLETE".equals(state)) return true;
            if ("FAILED".equals(state)) {
                String err = body.path("errors").isArray() && !body.path("errors").isEmpty()
                        ? body.path("errors").get(0).path("detail").asText("unknown")
                        : "job failed";
                String hint = CfHints.forUpstreamDetail(err);
                throw new CisException("CF job " + jobUrl + " failed: " + err
                        + (hint.isEmpty() ? "" : "  HINT: " + hint), 0, null);
            }
            try { Thread.sleep(sleepMs); } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }

    public Optional<ServiceKey> findServiceKey(String credJson, String instanceGuid, String keyName) {
        CfCtx ctx = cfCtx(credJson);
        JsonNode body = sendJson("GET",
                ctx.base() + "/v3/service_credential_bindings?names=" + encode(keyName)
                        + "&service_instance_guids=" + instanceGuid + "&type=key",
                ctx.token(), null);
        for (JsonNode r : body.path("resources")) {
            return Optional.of(new ServiceKey(
                    optString(r, "guid"),
                    optString(r, "name")));
        }
        return Optional.empty();
    }

    public ProvisionedJob createServiceKey(String credJson, String instanceGuid, String keyName) {
        CfCtx ctx = cfCtx(credJson);
        allowlist.requireAllowed(ctx.base(), "cf.apiUrl");
        String body = "{\"type\":\"key\",\"name\":\"" + keyName + "\","
                + "\"relationships\":{"
                + "\"service_instance\":{\"data\":{\"guid\":\"" + instanceGuid + "\"}}}}";
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(ctx.base() + "/v3/service_credential_bindings"))
                .timeout(HTTP_TIMEOUT)
                .header("Authorization", "Bearer " + ctx.token())
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> res;
        try {
            res = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new CisException("CF POST /v3/service_credential_bindings failed: " + e.getMessage(), e);
        }
        if (res.statusCode() / 100 != 2) {
            throw new CisException("CF POST /v3/service_credential_bindings returned HTTP "
                    + res.statusCode() + ": " + truncate(res.body()),
                    res.statusCode(), truncate(res.body()));
        }
        String jobUrl = res.headers().firstValue("Location").orElse(null);
        String bindingGuid = null;
        if (res.body() != null && !res.body().isEmpty()) {
            try {
                JsonNode n = mapper.readTree(res.body());
                bindingGuid = optString(n, "guid");
            } catch (Exception ignored) { /* async path body may be empty */ }
        }
        return new ProvisionedJob(jobUrl, bindingGuid);
    }

    public String getServiceKeyDetails(String credJson, String bindingGuid) {
        CfCtx ctx = cfCtx(credJson);
        JsonNode body = sendJson("GET",
                ctx.base() + "/v3/service_credential_bindings/" + bindingGuid + "/details",
                ctx.token(), null);
        JsonNode credentials = body.path("credentials");
        try { return mapper.writeValueAsString(credentials); }
        catch (Exception e) {
            throw new CisException("failed to serialise service-key credentials: " + e.getMessage(), e);
        }
    }

    public RoleEntry grantRole(String credJson, String type,
                                String userGuid, String orgGuid, String spaceGuid) {
        if ((orgGuid == null) == (spaceGuid == null)) {
            throw new IllegalArgumentException("createRole: pass exactly one of orgGuid / spaceGuid");
        }
        CfCtx ctx = cfCtx(credJson);
        String body = orgGuid != null
                ? "{\"type\":\"" + type + "\",\"relationships\":{" +
                    "\"user\":{\"data\":{\"guid\":\"" + userGuid + "\"}}," +
                    "\"organization\":{\"data\":{\"guid\":\"" + orgGuid + "\"}}}}"
                : "{\"type\":\"" + type + "\",\"relationships\":{" +
                    "\"user\":{\"data\":{\"guid\":\"" + userGuid + "\"}}," +
                    "\"space\":{\"data\":{\"guid\":\"" + spaceGuid + "\"}}}}";
        JsonNode created = sendJson("POST", ctx.base() + "/v3/roles", ctx.token(), body);
        return new RoleEntry(
                optString(created, "guid"),
                optString(created, "type"),
                userGuid, orgGuid, spaceGuid);
    }

    public String obtainToken(String credJson) {
        return obtainToken(parse(credJson));
    }

    String obtainToken(JsonNode creds) {
        String cfUaaUrl = enforceField(creds, "cfUaaUrl");
        String username = enforceField(creds, "username");
        String cacheKey = tokenCache.key(cfUaaUrl + "#passcode", username);
        String cached = tokenCache.getOrNull(cacheKey);
        if (cached != null) return cached;
        return obtainTokenViaPasscode(creds, cfUaaUrl, cacheKey);
    }

    private String obtainTokenViaPasscode(JsonNode creds, String cfUaaUrl, String cacheKey) {
        String iasPasscodeUrl = enforceField(creds, "iasPasscodeUrl");
        String p12Base64 = enforceField(creds, "p12Base64");
        String p12Password = enforceField(creds, "p12Password");
        String username = enforceField(creds, "username");
        String origin = enforceField(creds, "origin");

        String passcode = fetchPasscodeFromIas(iasPasscodeUrl, p12Base64, p12Password);
        String form = "grant_type=password"
                + "&username=" + encode(username)
                + "&password=" + encode(passcode)
                + "&login_hint=" + encode("{\"origin\":\"" + origin + "\"}");
        return postTokenRequest(cfUaaUrl, form, "passcode", cacheKey);
    }

    private String fetchPasscodeFromIas(String iasPasscodeUrl, String p12Base64, String p12Password) {
        allowlist.requireAllowed(iasPasscodeUrl, "cf.iasPasscodeUrl");
        HttpClient mtls = buildMtlsClient(p12Base64, p12Password);
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(iasPasscodeUrl))
                .timeout(HTTP_TIMEOUT)
                .header("Accept", "application/json")
                .header("User-Agent", "btp-containment/1.0")
                .GET()
                .build();
        HttpResponse<String> res;
        try {
            res = mtls.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new CisException("IAS passcode call failed: " + e.getMessage(), e);
        }
        if (res.statusCode() / 100 != 2) {
            String body = truncate(res.body());
            String detail = (body != null && !body.isBlank()) ? " - " + body : "";
            throw new CisException("IAS passcode endpoint returned HTTP " + res.statusCode() + detail,
                    res.statusCode(), body);
        }
        JsonNode body = parse(res.body());
        String passcode = optString(body, "passcode");
        if (passcode == null || passcode.isBlank()) {
            String trunc = truncate(res.body());
            String detail = (trunc != null && !trunc.isBlank()) ? " - " + trunc : "";
            throw new CisException("IAS passcode response missing 'passcode' field" + detail,
                    res.statusCode(), trunc);
        }
        return passcode;
    }

    private HttpClient buildMtlsClient(String p12Base64, String p12Password) {
        try {
            byte[] p12Bytes = Base64.getDecoder().decode(p12Base64);
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new ByteArrayInputStream(p12Bytes), p12Password.toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, p12Password.toCharArray());
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), null, null);
            return HttpClient.newBuilder()
                    .sslContext(sslContext)
                    .connectTimeout(Duration.ofSeconds(10))
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();
        } catch (Exception e) {
            throw new CisException("failed to build mTLS client from P12: " + e.getMessage(), e);
        }
    }

    private String postTokenRequest(String cfUaaUrl, String form, String flowName, String cacheKey) {
        allowlist.requireAllowed(cfUaaUrl, "cf.cfUaaUrl");
        String basic = Base64.getEncoder().encodeToString("cf:".getBytes(StandardCharsets.UTF_8));
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(cfUaaUrl + "/oauth/token"))
                .timeout(HTTP_TIMEOUT)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .header("Authorization", "Basic " + basic)
                .POST(HttpRequest.BodyPublishers.ofString(form, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> res;
        try {
            res = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new CisException("CF UAA " + flowName + " call failed: " + e.getMessage(), e);
        }
        if (res.statusCode() / 100 != 2) {
            String body = truncate(res.body());
            String detail = (body != null && !body.isBlank()) ? " - " + body : "";
            throw new CisException("CF UAA " + flowName + " grant returned HTTP " + res.statusCode() + detail,
                    res.statusCode(), body);
        }
        JsonNode tokenJson = parse(res.body());
        String access = optString(tokenJson, "access_token");
        if (access == null) {
            throw new CisException("CF UAA response missing access_token",
                    res.statusCode(), truncate(res.body()));
        }
        long ttl = tokenJson.path("expires_in").asLong(3600);
        tokenCache.put(cacheKey, access,
                Duration.ofSeconds(ttl-120));
        log.debug("obtained CF UAA token via {} (ttl={}s)", flowName, ttl);
        return access;
    }

    private <T> List<T> paginate(String firstUrl, String token,
                                 Function<JsonNode, JsonNode> arrayFn,
                                 Function<JsonNode, T> mapFn) {
        List<T> out = new ArrayList<>();
        String next = firstUrl;
        while (next != null) {
            JsonNode body = sendJson("GET", next, token, null);
            for (JsonNode r : arrayFn.apply(body)) {
                out.add(mapFn.apply(r));
            }
            next = optString(body.path("pagination").path("next"), "href");
        }
        return out;
    }

    private JsonNode sendJson(String method, String url, String bearer, String body) {
        allowlist.requireAllowed(url, "cf.apiUrl");
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
        HttpResponse<String> res;
        try {
            res = http.send(b.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new CisException("CF " + method + " " + url + " failed: " + e.getMessage(), e);
        }
        if (res.statusCode() / 100 != 2) {
            String errBody = truncate(res.body());
            String detail = (errBody != null && !errBody.isBlank()) ? " - " + errBody : "";
            throw new CisException("CF " + method + " " + url + " returned HTTP "
                    + res.statusCode() + detail,
                    res.statusCode(), errBody);
        }
        if (res.body() == null || res.body().isEmpty()) return mapper.createObjectNode();
        return parse(res.body());
    }

    private JsonNode parse(String json) {
        try { return mapper.readTree(json); }
        catch (Exception e) { throw new CisException("Failed to parse JSON: " + e.getMessage(), e); }
    }

    private static String enforceField(JsonNode node, String field) {
        JsonNode v = node.path(field);
        if (!v.isTextual())
            throw new CisException("missing required field: " + field, 0, null);
        return v.asText();
    }

    private static String optString(JsonNode node, String field) {
        JsonNode v = node.path(field);
        return v.isTextual() ? v.asText() : null;
    }

    private static String encode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String truncate(String s) {
        if (s == null) return null;
        return s.length() <= 50 ? s : s.substring(0, 50) + "...";
    }

    public record Organization(String guid, String name) {}
    public record Space(String guid, String name, String orgGuid) {}
    public record CfUser(String guid, String username, String origin) {}
    public record RoleEntry(String guid, String type, String userGuid,
                            String orgGuid, String spaceGuid) {}
    public record ServiceInstance(String guid, String name, String lastOperationState) {}
    public record ServiceKey(String guid, String name) {}
    public record ProvisionedJob(String jobUrl, String guid) {}
    public record OrgWalkDiagnostic(
            List<CfUser> matches,
            int orgsScanned,
            int spacesScanned,
            int uniqueUsersSeen,
            List<String> usernamesSample
    ) {}
}
