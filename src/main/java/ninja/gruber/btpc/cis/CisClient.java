// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.cis;
import ninja.gruber.btpc.cis.domain.SubaccountCandidate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ninja.gruber.btpc.config.UrlAllowlist;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;

@Component
public class CisClient {

    private static final Logger log = LoggerFactory.getLogger(CisClient.class);
    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(20);

    private final HttpClient http;
    private final ObjectMapper mapper;
    private final CisTokenCache tokenCache;
    private final UrlAllowlist allowlist;

    public CisClient(ObjectMapper mapper, CisTokenCache tokenCache, UrlAllowlist allowlist) {
        this.mapper = mapper;
        this.tokenCache = tokenCache;
        this.allowlist = allowlist;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    // Cheap auth probe for the health-check job: acquire a UAA token only,
    // no accounts call. Any non-2xx surfaces as CisException for the caller.
    public void ping(String serviceKeyJson) {
        obtainOauthToken(parse(serviceKeyJson));
    }

    public List<SubaccountCandidate> listSubaccounts(String serviceKeyJson) {
        JsonNode key = parse(serviceKeyJson);
        String accountsBase = enforceField(key.path("endpoints"), "accounts_service_url");
        String token = obtainOauthToken(key);
        JsonNode body = getJson(accountsBase + "/accounts/v1/subaccounts", token);
        return parseSubaccountList(body);
    }

    String obtainOauthToken(JsonNode key) {
        JsonNode uaa = key.path("uaa");
        String uaaUrl = enforceField(uaa, "url");
        allowlist.requireAllowed(uaaUrl, "cis.uaa.url");
        String clientId = enforceField(uaa, "clientid");
        String clientSecret = enforceField(uaa, "clientsecret");

        String cacheKey = tokenCache.key(uaaUrl, clientId);
        String cached = tokenCache.getOrNull(cacheKey);
        if (cached != null) return cached;

        String form = "grant_type=client_credentials" +
                "&response_type=token";

        String basicAuth = Base64.getEncoder().encodeToString(
                (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8)); //see sap-help -> or form fields...

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(uaaUrl + "/oauth/token"))
                .timeout(HTTP_TIMEOUT)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .header("Authorization", "Basic " + basicAuth)
                .POST(HttpRequest.BodyPublishers.ofString(form, StandardCharsets.UTF_8))
                .build();

        HttpResponse<String> res;
        try {
            res = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            JsonNode tokenJson = parse(res.body());
            String access = enforceField(tokenJson, "access_token");
            long ttlSec = tokenJson.path("expires_in").asLong(3600);
            tokenCache.put(cacheKey, access, Duration.ofSeconds(ttlSec));
            log.debug("obtained UAA token for {} (ttl={}s)", clientId, ttlSec);
            return access;
        } catch (Exception e) {
            throw new CisException("UAA call failed: " + e.getMessage(), e);
        }
    }

    JsonNode getJson(String url, String bearer) {
        allowlist.requireAllowed(url, "cis.accounts_service_url");
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(HTTP_TIMEOUT)
                .header("Authorization", "Bearer " + bearer)
                .header("Accept", "application/json")
                .GET()
                .build();
        HttpResponse<String> res;
        try {
            res = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (res.statusCode() / 100 != 2) {
                throw new CisException(
                        "CIS GET " + url + " returned HTTP " + res.statusCode(),
                        res.statusCode(),
                        truncate(res.body()));
            }
            return parse(res.body());
        } catch (Exception e) {
            throw new CisException("CIS call failed: " + e.getMessage(), e);
        }
    }

    private List<SubaccountCandidate> parseSubaccountList(JsonNode body) {
        JsonNode arr = body.has("value") && body.get("value").isArray()
                ? body.get("value")
                : body;
        if (!arr.isArray()) {
            throw new CisException("Accounts service response was not an array; got "
                    + body.getNodeType(), 200, truncate(body.toString()));
        }
        List<SubaccountCandidate> out = new ArrayList<>();
        for (Iterator<JsonNode> it = arr.elements(); it.hasNext(); ) {
            JsonNode n = it.next();
            out.add(new SubaccountCandidate(
                    optString(n, "guid"),
                    optString(n, "displayName"),
                    optString(n, "subdomain"),
                    optString(n, "region"),
                    optString(n, "parentType"),
                    optString(n, "parentGUID"),
                    optString(n, "globalAccountGUID"),
                    n.has("betaEnabled") && n.get("betaEnabled").asBoolean(false),
                    optString(n, "description"),
                    optString(n, "state"),
                    optString(n, "stateMessage"),
                    optString(n, "usedForProduction")
            ));
        }
        return out;
    }

    private JsonNode parse(String json) {
        try {
            return mapper.readTree(json);
        } catch (Exception e) {
            throw new CisException("Failed to parse JSON: " + e.getMessage(), e);
        }
    }

    private static String enforceField(JsonNode node, String field) {
        JsonNode v = node.path(field);
        if (!v.isTextual() || v.asText().isBlank()) {
            throw new CisException("missing required field: " + field, 0, null);
        }
        return v.asText();
    }

    private static String optString(JsonNode node, String field) {
        JsonNode v = node.path(field);
        return v.isTextual() ? v.asText() : null;
    }

    private static String truncate(String s) {
        if (s == null) return null;
        return s.length() <= 50 ? s : s.substring(0, 50) + "...";
    }
}
