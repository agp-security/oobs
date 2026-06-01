// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.audit.custom.sinks;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ninja.gruber.btpc.audit.IAuditForward.AuditEvent;
import ninja.gruber.btpc.audit.custom.domain.AuditSinkConfig;
import ninja.gruber.btpc.audit.custom.AuditSinkService;
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
import java.util.LinkedHashMap;
import java.util.Map;

@Component
public class SplunkHecForwarder implements AuditForwarder {

    private static final Logger log = LoggerFactory.getLogger(SplunkHecForwarder.class);
    private static final Duration TIMEOUT = Duration.ofSeconds(3);

    private final AuditSinkService configService;
    private final UrlAllowlist allowlist;
    private final ObjectMapper mapper;
    private final HttpClient http;

    public SplunkHecForwarder(AuditSinkService configService, UrlAllowlist allowlist,
                              ObjectMapper mapper) {
        this.configService = configService;
        this.allowlist = allowlist;
        this.mapper = mapper;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(2))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    @Override public AuditSinkConfig.Kind kind() { return AuditSinkConfig.Kind.SPLUNK_HEC; }

    @Override
    public void send(AuditEvent event) throws Exception {
        AuditSinkConfig cfg = configService.find(kind()).orElse(null);
        if (cfg == null || !cfg.enabled()) return;
        String token = configService.decryptSecret(kind()).orElse(null);
        if (token == null || token.isBlank()) {
            log.warn("Splunk HEC: no token configured");
            return;
        }
        String url = textOrEmpty(cfg.configPlaintext(), "url");
        if (url.isBlank()) {
            log.warn("Splunk HEC: no URL configured");
            return;
        }
        post(url, token, cfg.configPlaintext(), buildEventBody(event));
    }

    @Override
    public String testConnection() throws Exception {
        AuditSinkConfig cfg = configService.getOrThrow(kind());
        String token = configService.decryptSecret(kind())
                .orElseThrow(() -> new IllegalStateException("no token saved"));
        String url = textOrEmpty(cfg.configPlaintext(), "url");
        if (url.isBlank()) throw new IllegalStateException("url is required");
        allowlist.requireAllowed(url, "splunk.test.url");
        Map<String, Object> probe = new LinkedHashMap<>();
        probe.put("message", "splunk connection test");
        probe.put("test", true);
        post(url, token, cfg.configPlaintext(), Map.of("event", probe));
        return "Splunk HEC accepted the test event (HTTP 2xx).";
    }

    private void post(String url, String token, JsonNode cfg, Object body) throws Exception {
        allowlist.requireAllowed(url, "splunk.url");
        String endpoint = url.replaceAll("/+$", "") + "/services/collector" + buildQueryString(cfg);
        String payload = mapper.writeValueAsString(body);
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .timeout(TIMEOUT)
                .header("Authorization", "Splunk " + token)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (res.statusCode() / 100 != 2) {
            throw new IllegalStateException(
                    "Splunk HEC returned HTTP " + res.statusCode());
        }
    }

    private static String buildQueryString(JsonNode cfg) {
        if (cfg == null) return "";
        StringBuilder qs = new StringBuilder();
        appendParam(qs, "index", textOrEmpty(cfg, "index"));
        appendParam(qs, "source", textOrEmpty(cfg, "source"));
        appendParam(qs, "sourcetype", textOrEmpty(cfg, "sourcetype"));
        return qs.isEmpty() ? "" : "?" + qs;
    }

    private static void appendParam(StringBuilder qs, String name, String value) {
        if (value == null || value.isBlank()) return;
        if (!qs.isEmpty()) qs.append('&');
        qs.append(name).append('=').append(URLEncoder.encode(value, StandardCharsets.UTF_8));
    }

    private Object buildEventBody(AuditEvent e) {
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("event", mapper.convertValue(e, Map.class));
        AuditSinkConfig cfg = configService.find(kind()).orElse(null);
        if (cfg != null) {
            String host = textOrEmpty(cfg.configPlaintext(), "host");
            if (!host.isBlank()) envelope.put("host", host);
        }
        return envelope;
    }

    private static String textOrEmpty(JsonNode node, String field) {
        if (node == null) return "";
        JsonNode v = node.path(field);
        return v.isTextual() ? v.asText() : "";
    }
}
