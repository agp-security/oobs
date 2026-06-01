// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.enroll;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ninja.gruber.btpc.domain.CredentialKind;
import ninja.gruber.btpc.domain.ParsedServiceKey;
import ninja.gruber.btpc.config.UrlAllowlist;
import org.springframework.stereotype.Component;

import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class ServiceKeyClassifier {

    private static final Pattern REGION_FROM_URL =
            Pattern.compile("https?://[^/]*\\.([a-z]{2}\\d{1,3})\\.hana\\.ondemand\\.com");

    private final ObjectMapper mapper;
    private final UrlAllowlist allowlist;

    public ServiceKeyClassifier(ObjectMapper mapper, UrlAllowlist allowlist) {
        this.mapper = mapper;
        this.allowlist = allowlist;
    }

    public ParsedServiceKey classify(String rawJson) {
        JsonNode root;
        try {
            root = mapper.readTree(rawJson);
        } catch (Exception e) {
            throw new IllegalArgumentException("Service key is not valid JSON: " + e.getMessage(), e);
        }
        if (!root.isObject()) {
            throw new IllegalArgumentException("Service key JSON must be an object");
        }

        ParsedServiceKey p;
        if (looksLikeIas(root)) p = classifyIas(root, rawJson);
        else if (looksLikeCis(root)) p = classifyCis(root, rawJson);
        else if (looksLikeXsuaaApiaccess(root)) p = classifyXsuaaApiaccess(root, rawJson);
        else throw new IllegalArgumentException(
                    "Unrecognised service key shape. Expected CIS central-viewer, IAS, or XSUAA api-access.");

        validateUrls(root, p.kind());
        return p;
    }

    private void validateUrls(JsonNode root, CredentialKind kind) {
        switch (kind) {
            case CIS -> {
                checkUrl(root.path("endpoints"), "accounts_service_url", "endpoints.accounts_service_url");
                checkUrl(root.path("uaa"), "url", "uaa.url");
                checkUrl(root.path("uaa"), "apiurl", "uaa.apiurl");
                checkUrl(root.path("uaa"), "sburl", "uaa.sburl");
            }
            case IAS -> {
                checkUrl(root, "url", "url");
                checkUrl(root, "btp-tenant-api", "btp-tenant-api");
                checkUrl(root, "authorization_endpoint", "authorization_endpoint");
                checkUrl(root, "end_session_endpoint", "end_session_endpoint");
            }
            case XSUAA_APIACCESS -> {
                // The api-access plan comes in two shapes: legacy "nested under
                // uaa" and the modern "flat at root". Use whichever has the
                // discriminating fields.
                JsonNode creds = xsuaaCredsNode(root);
                checkUrl(creds, "url", "url");
                checkUrl(creds, "apiurl", "apiurl");
                checkUrl(creds, "sburl", "sburl");
            }
        }
    }

    public static JsonNode xsuaaCredsNode(JsonNode root) {
        JsonNode uaa = root.path("uaa");
        if (uaa.hasNonNull("apiurl") && uaa.hasNonNull("clientid")) return uaa;
        return root;
    }

    private void checkUrl(JsonNode parent, String field, String dottedName) {
        JsonNode v = parent.path(field);
        if (v.isTextual() && !v.asText().isBlank()) {
            allowlist.requireAllowed(v.asText(), dottedName);
        }
    }

    private static boolean looksLikeIas(JsonNode root) {
        return root.hasNonNull("btp-tenant-api")
                && root.hasNonNull("app_tid")
                && root.hasNonNull("clientid");
    }

    private static boolean looksLikeCis(JsonNode root) {
        String svc = textOrEmpty(root, "sap.cloud.service");
        return svc.startsWith("com.sap.core.commercial.service.")
                && root.has("endpoints")
                && root.has("uaa");
    }

    private static boolean looksLikeXsuaaApiaccess(JsonNode root) {
        if (root.hasNonNull("sap.cloud.service")) return false;
        if (root.hasNonNull("btp-tenant-api")) return false;
        JsonNode uaa = root.path("uaa");
        if (uaa.hasNonNull("apiurl") && uaa.hasNonNull("clientid")) return true;
        return root.hasNonNull("apiurl")
                && root.hasNonNull("clientid")
                && root.hasNonNull("xsappname");
    }

    private ParsedServiceKey classifyXsuaaApiaccess(JsonNode root, String raw) {
        JsonNode creds = xsuaaCredsNode(root);
        UUID subGuid = null;
        String sid = textOrEmpty(creds, "subaccountid");
        if (sid.isEmpty()) sid = textOrEmpty(root, "subaccountid");
        if (!sid.isEmpty()) {
            try { subGuid = UUID.fromString(sid); }
            catch (Exception ignored) { /* leave null */ }
        }
        String region = inferRegion(textOrEmpty(creds, "url"));
        if (region == null) region = inferRegion(textOrEmpty(creds, "apiurl"));
        String identityZone = textOrEmpty(creds, "identityzone");
        return new ParsedServiceKey(
                CredentialKind.XSUAA_APIACCESS,
                subGuid,
                region,
                identityZone.isEmpty() ? null : identityZone,
                raw);
    }

    private ParsedServiceKey classifyIas(JsonNode root, String raw) {
        UUID appTid = parseUuid(textOrEmpty(root, "app_tid"), "app_tid");
        String region = inferRegion(textOrEmpty(root, "btp-tenant-api"));
        return new ParsedServiceKey(
                CredentialKind.IAS,
                appTid,
                region,
                null,
                raw);
    }

    private ParsedServiceKey classifyCis(JsonNode root, String raw) {
        String svc = textOrEmpty(root, "sap.cloud.service");
        boolean isCentral;
        if (svc.endsWith(".central")) {
            isCentral = true;
        } else if (svc.endsWith(".local")) {
            isCentral = false;
        } else {
            //fallback
            String xsm = textOrEmpty(root.path("uaa"), "xsmasterappname");/*opt*/
            if (xsm.startsWith("cis-central")) isCentral = true;
            else if (xsm.startsWith("cis-local")) isCentral = false;
            else throw new IllegalArgumentException(
                        "CIS service key: cannot determine plan from sap.cloud.service=" + svc);
        }
        if (!isCentral) {
            throw new IllegalArgumentException(
                    "CIS local-plan keys are no longer supported. Use a CIS Central-Viewer service key " +
                    "(plan 'central', role 'Subaccount Viewer' or equivalent).");
        }

        JsonNode uaa = root.path("uaa");
        String region = inferRegion(textOrEmpty(uaa, "url"));
        if (region == null) region = inferRegion(textOrEmpty(uaa, "apiurl"));

        String identityZone = textOrEmpty(uaa, "identityzone");

        return new ParsedServiceKey(
                CredentialKind.CIS,
                null,
                region,
                identityZone.isEmpty() ? null : identityZone,
                raw);
    }

    private static UUID parseUuid(String s, String field) {
        try {
            return UUID.fromString(s);
        } catch (Exception e) {
            throw new IllegalArgumentException(field + " is not a valid UUID: " + s);
        }
    }

    private static String inferRegion(String url) {
        if (url == null || url.isBlank()) return null;
        Matcher m = REGION_FROM_URL.matcher(url);
        return m.find() ? m.group(1) : null;
    }

    private static String textOrEmpty(JsonNode node, String field) {
        JsonNode v = node.path(field);
        return v.isTextual() ? v.asText() : "";
    }
}
