// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.audit.custom.sinks;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ninja.gruber.btpc.audit.IAuditForward.AuditEvent;
import ninja.gruber.btpc.audit.custom.domain.AuditSinkConfig;
import ninja.gruber.btpc.audit.custom.AuditSinkService;
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
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

@Component
public class BtpAuditLogForwarder implements AuditForwarder {

    private static final Logger log = LoggerFactory.getLogger(BtpAuditLogForwarder.class);
    private static final Duration TIMEOUT = Duration.ofSeconds(5);
    private static final DateTimeFormatter ISO = DateTimeFormatter.ISO_OFFSET_DATE_TIME;

    private final AuditSinkService configService;
    private final CisTokenCache tokenCache;
    private final UrlAllowlist allowlist;
    private final ObjectMapper mapper;
    private final HttpClient plainHttp;

    public BtpAuditLogForwarder(AuditSinkService configService, CisTokenCache tokenCache,
                                UrlAllowlist allowlist, ObjectMapper mapper) {
        this.configService = configService;
        this.tokenCache = tokenCache;
        this.allowlist = allowlist;
        this.mapper = mapper;
        this.plainHttp = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    @Override public AuditSinkConfig.Kind kind() { return AuditSinkConfig.Kind.BTP_AUDIT_LOG; }

    @Override
    public void send(AuditEvent event) throws Exception {
        AuditSinkConfig cfg = configService.find(kind()).orElse(null);
        if (cfg == null || !cfg.enabled()) return;
        JsonNode key = parseServiceKey();
        if (key == null) return;
        String token = obtainToken(key);
        post(key, token, buildSecurityEventBody(event));
    }

    @Override
    public String testConnection() throws Exception {
        JsonNode key = parseServiceKeyOrThrow();
        String token = obtainToken(key);
        Map<String, Object> probe = Map.of(
                "uuid", UUID.randomUUID().toString(),
                "user", "btp-containment-system",
                "time", ISO.format(OffsetDateTime.now(ZoneOffset.UTC)),
                "tenant", optString(creds(key), "tenantid"),
                "data", "btp-containment: connection test ping");
        post(key, token, probe);
        return "BTP Audit Log Service accepted the test event.";
    }

    private void post(JsonNode key, String token, Object body) throws Exception {
        String url = optString(key, "url");
        if (url.isBlank()) throw new IllegalStateException("service key missing top-level 'url'");
        allowlist.requireAllowed(url, "audit-log.url");
        String endpoint = url.replaceAll("/+$", "") + "/audit-log/oauth2/v2/security-events";
        String payload = mapper.writeValueAsString(body);
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .timeout(TIMEOUT)
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> res = plainHttp.send(req, HttpResponse.BodyHandlers.ofString());
        if (res.statusCode() / 100 != 2) {
            log.warn("BTP Audit Log HTTP {} - body: {}", res.statusCode(), truncate(res.body()));
            throw new IllegalStateException("BTP Audit Log returned HTTP " + res.statusCode());
        }
    }

    private String obtainToken(JsonNode key) throws Exception {
        JsonNode uaa = creds(key);
        String certUrl = optString(uaa, "certurl");
        String clientId = optString(uaa, "clientid");
        String certPem = optString(uaa, "certificate");
        String keyPem = optString(uaa, "key");
        if (certUrl.isBlank() || clientId.isBlank() || certPem.isBlank() || keyPem.isBlank()) {
            throw new IllegalStateException(
                    "audit-log service key missing uaa.certurl / clientid / certificate / key - " +
                            "expected an x509-credentials binding");
        }
        allowlist.requireAllowed(certUrl, "audit-log.certurl");
        String cacheKey = tokenCache.key(certUrl, clientId);
        String cached = tokenCache.getOrNull(cacheKey);
        if (cached != null) return cached;

        String tokenEndpoint = certUrl.replaceAll("/+$", "")
                + "/oauth/token?grant_type=client_credentials"
                + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8);
        HttpClient mtls = buildMtlsClient(certPem, keyPem);
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(tokenEndpoint))
                .timeout(TIMEOUT)
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        HttpResponse<String> res = mtls.send(req, HttpResponse.BodyHandlers.ofString());
        if (res.statusCode() / 100 != 2) {
            log.warn("Audit-log UAA token (x509) HTTP {} - body: {}",
                    res.statusCode(), truncate(res.body()));
            throw new CisException("Audit-log UAA token (x509) returned HTTP " + res.statusCode(),
                    res.statusCode(), null);
        }
        JsonNode body = mapper.readTree(res.body());
        String access = body.path("access_token").asText(null);
        if (access == null) throw new IllegalStateException("Audit-log UAA response missing access_token");
        long ttl = body.path("expires_in").asLong(3600);
        tokenCache.put(cacheKey, access, Duration.ofSeconds(Math.max(60, ttl - 60)));
        return access;
    }

    private static HttpClient buildMtlsClient(String certPem, String keyPem) {
        try {
            X509Certificate cert = parseX509(certPem);
            PrivateKey privateKey = parsePkcs8(keyPem);
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            char[] pwd = "btpc".toCharArray();   // in-memory only, never touches disk
            ks.setKeyEntry("audit-log", privateKey, pwd, new Certificate[]{cert});
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, pwd);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), null, null);
            return HttpClient.newBuilder()
                    .sslContext(ctx)
                    .connectTimeout(Duration.ofSeconds(3))
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException(
                    "failed to build mTLS client from audit-log service key: " + e.getMessage(), e);
        }
    }

    private static X509Certificate parseX509(String pem) throws Exception {
        byte[] der = pemToDer(pem, "CERTIFICATE");
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
    }

    private static PrivateKey parsePkcs8(String pem) throws Exception {
        byte[] der = pemToDer(pem, "PRIVATE KEY");
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception ignore) {
            return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
        }
    }

    private static byte[] pemToDer(String pem, String label) {
        String normalised = pem.replace("\\n", "\n").trim();
        String startMarker = "-----BEGIN " + label + "-----";
        String endMarker = "-----END " + label + "-----";
        int start = normalised.indexOf(startMarker);
        int end = normalised.indexOf(endMarker);
        if (start < 0 || end < 0) {
            throw new IllegalStateException("PEM missing " + startMarker + " / " + endMarker);
        }
        String body = normalised.substring(start + startMarker.length(), end)
                .replaceAll("\\s+", "");
        return Base64.getDecoder().decode(body);
    }

    private Map<String, Object> buildSecurityEventBody(AuditEvent e) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("uuid", UUID.randomUUID().toString());
        m.put("user", e.actor() == null ? "unknown" : e.actor());
        m.put("time", ISO.format(OffsetDateTime.now(ZoneOffset.UTC)));
        m.put("tenant", e.systemId() == null ? "global" : e.systemId());
        StringBuilder data = new StringBuilder()
                .append("action=").append(e.action())
                .append(" outcome=").append(e.outcome())
                .append(" target=").append(e.targetUserEmail());
        if (e.errorMessage() != null) data.append(" error=").append(e.errorMessage());
        m.put("data", data.toString());
        return m;
    }

    private static JsonNode creds(JsonNode key) {
        JsonNode uaa = key.path("uaa");
        return uaa.isMissingNode() ? key : uaa;
    }

    private JsonNode parseServiceKey() throws Exception {
        String json = configService.decryptSecret(kind()).orElse(null);
        if (json == null || json.isBlank()) return null;
        return mapper.readTree(json);
    }

    private JsonNode parseServiceKeyOrThrow() throws Exception {
        JsonNode j = parseServiceKey();
        if (j == null) throw new IllegalStateException("no service-key saved");
        return j;
    }

    private static String optString(JsonNode node, String field) {
        JsonNode v = node.path(field);
        return v.isTextual() ? v.asText() : "";
    }

    private static String truncate(String s) {
        if (s == null) return "";
        return s.length() <= 300 ? s : s.substring(0, 300) + "...";
    }
}
