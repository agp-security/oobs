// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

sap.ui.define([], function () {
    "use strict";

    var DEFAULTS = { user: "alice@example.com", scopes: "btpc.admin,btpc.responder" };

    function resolveAuth(component) {
        if (component && typeof component.getModel === "function") {
            var m = component.getModel("devAuth");
            if (m) {
                var d = m.getData();
                if (d && d.user) return { user: d.user, scopes: d.scopes || "", source: "model" };
            }
        }
        try {
            var raw = localStorage.getItem("btpc.devAuth");
            if (raw) {
                var p = JSON.parse(raw);
                if (p && p.user) return { user: p.user, scopes: p.scopes || "", source: "localStorage" };
            }
        } catch (_) { /* incognito */ }
        return { user: DEFAULTS.user, scopes: DEFAULTS.scopes, source: "defaults" };
    }

    // Approuter CSRF token (xs-app.json: csrfProtection:true on /api/(.*)).
    // Cached module-wide; fetched lazily before the first modifying request
    // and refreshed on a 403 "x-csrf-token: Required" rejection. Locally there
    // is no approuter so the fetch returns no header and this stays null - the
    // Spring dev chain has CSRF disabled, so an absent token is harmless.
    var csrfToken = null;

    function fetchCsrfToken(auth) {
        return fetch("/api/v1/whoami", {
            method: "GET",
            headers: {
                "X-Test-User": auth.user,
                "X-Test-Scopes": auth.scopes,
                "x-csrf-token": "fetch",
                "Accept": "application/json"
            }
        }).then(function (res) {
            var t = res.headers.get("x-csrf-token");
            if (t) csrfToken = t;
            return csrfToken;
        });
    }

    function call(component, method, path, body) {
        var auth = resolveAuth(component);
        var modifying = method !== "GET" && method !== "HEAD";

        function doFetch() {
            var headers = {
                "X-Test-User": auth.user,
                "X-Test-Scopes": auth.scopes,
                "Accept": "application/json"
            };
            if (body !== undefined && body !== null) headers["Content-Type"] = "application/json";
            if (modifying && csrfToken) headers["x-csrf-token"] = csrfToken;
            return fetch(path, {
                method: method,
                headers: headers,
                body: body !== undefined && body !== null ? JSON.stringify(body) : undefined
            });
        }

        var first = (modifying && !csrfToken) ? fetchCsrfToken(auth).then(doFetch) : doFetch();

        return first.then(function (res) {
            // Approuter rejected an absent/stale token - refresh once and retry.
            if (res.status === 403 && modifying &&
                (res.headers.get("x-csrf-token") || "").toLowerCase() === "required") {
                csrfToken = null;
                return fetchCsrfToken(auth).then(doFetch);
            }
            return res;
        }).then(function (res) {
            return res.text().then(function (text) {
                var data = null;
                if (text && text.length > 0) {
                    try { data = JSON.parse(text); }
                    catch (_) { data = { message: text.substring(0, 500) }; }
                }
                if (!res.ok) {
                    var msg = (data && data.message) ? data.message
                            : (res.status === 401 ? "HTTP 401 - not authenticated."
                            : (res.status === 403 ? "HTTP 403 - missing scope or CSRF token."
                            : ("HTTP " + res.status + (res.statusText ? " - " + res.statusText : ""))));
                    var err = new Error(msg);
                    err.status = res.status;
                    err.payload = data;
                    throw err;
                }
                return data;
            });
        });
    }

    return {
        // --- subaccounts ---
        listSubaccounts: function (c) { return call(c, "GET", "/api/v1/subaccounts"); },
        getSubaccount: function (c, id) { return call(c, "GET", "/api/v1/subaccounts/" + encodeURIComponent(id)); },
        enrollSubaccount: function (c, payload) { return call(c, "POST", "/api/v1/subaccounts", payload); },
        quickAddSubaccount: function (c, payload) { return call(c, "POST", "/api/v1/subaccounts/quick-add", payload); },
        deleteSubaccount: function (c, id) { return call(c, "DELETE", "/api/v1/subaccounts/" + encodeURIComponent(id)); },
        updateLabel: function (c, id, label) {
            return call(c, "PATCH", "/api/v1/subaccounts/" + encodeURIComponent(id) + "/label", { label: label });
        },
        updateMetadata: function (c, id, payload) {
            return call(c, "PATCH", "/api/v1/subaccounts/" + encodeURIComponent(id) + "/metadata", payload);
        },
        attachCredential: function (c, id, serviceKey) {
            return call(c, "POST", "/api/v1/subaccounts/" + encodeURIComponent(id) + "/credentials",
                { serviceKey: serviceKey });
        },
        provisionXsuaaApiAccess: function (c, id) {
            return call(c, "POST",
                "/api/v1/subaccounts/" + encodeURIComponent(id) + "/provision-xsuaa-apiaccess");
        },
        attachCfTechnicalUser: function (c, id, payload) {
            return call(c, "POST", "/api/v1/subaccounts/" + encodeURIComponent(id) + "/cf-technical-user",
                payload);
        },
        copyCfTechnicalUser: function (c, id, sourceId, payload) {
            return call(c, "POST", "/api/v1/subaccounts/" + encodeURIComponent(id)
                + "/cf-technical-user/copy-from/" + encodeURIComponent(sourceId), payload);
        },
        // Pin the subaccount to a specific CF Cloud Controller org guid.
        // Pass null/empty to clear the pin. Without this set, the
        // cf_revoke_org_roles action fails fast rather than risk fanning
        // out to other orgs the technical user can see.
        setCfOrgId: function (c, id, cfOrgId) {
            return call(c, "PATCH", "/api/v1/subaccounts/" + encodeURIComponent(id) + "/cf-org-id",
                { cfOrgId: cfOrgId || null });
        },
        // --- CIS discovery (ad-hoc, key not persisted) ---
        discoverFromCis: function (c, serviceKey) {
            return call(c, "POST", "/api/v1/cis/discover", { serviceKey: serviceKey });
        },

        // --- saved central-viewer keys (persisted, auto-synced) ---
        listSavedKeys: function (c) { return call(c, "GET", "/api/v1/discovery/keys"); },
        saveCentralKey: function (c, payload) { return call(c, "POST", "/api/v1/discovery/keys", payload); },
        updateSavedKey: function (c, id, payload) { return call(c, "PATCH", "/api/v1/discovery/keys/" + encodeURIComponent(id), payload); },
        deleteSavedKey: function (c, id) { return call(c, "DELETE", "/api/v1/discovery/keys/" + encodeURIComponent(id)); },
        triggerSavedKeySync: function (c, id) { return call(c, "POST", "/api/v1/discovery/keys/" + encodeURIComponent(id) + "/sync"); },

        // --- discovered candidates ---
        listCandidates: function (c, onlyPromotable) {
            // V12: dismiss is gone. onlyPromotable=true filters to rows that
            // don't have a currently-enrolled subaccount (= what the operator
            // can still add); omit / false returns everything for an overview.
            var qs = onlyPromotable ? "?onlyPromotable=true" : "";
            return call(c, "GET", "/api/v1/discovery/candidates" + qs);
        },
        deleteCandidate: function (c, id) {
            return call(c, "DELETE", "/api/v1/discovery/candidates/" + encodeURIComponent(id));
        },

        // --- contacts ---
        listContacts: function (c, subaccountId) {
            return call(c, "GET", "/api/v1/subaccounts/" + encodeURIComponent(subaccountId) + "/contacts");
        },
        addContact: function (c, subaccountId, payload) {
            return call(c, "POST", "/api/v1/subaccounts/" + encodeURIComponent(subaccountId) + "/contacts", payload);
        },
        updateContact: function (c, subaccountId, id, payload) {
            return call(c, "PUT", "/api/v1/subaccounts/" + encodeURIComponent(subaccountId) + "/contacts/" + encodeURIComponent(id), payload);
        },
        deleteContact: function (c, subaccountId, id) {
            return call(c, "DELETE", "/api/v1/subaccounts/" + encodeURIComponent(subaccountId) + "/contacts/" + encodeURIComponent(id));
        },

        // --- protected users ---
        listProtected: function (c) { return call(c, "GET", "/api/v1/protected-users"); },
        addProtection: function (c, payload) { return call(c, "POST", "/api/v1/protected-users", payload); },
        disableProtection: function (c, id) { return call(c, "DELETE", "/api/v1/protected-users/" + encodeURIComponent(id)); },

        // --- SoD ---
        listConflictSets: function (c) { return call(c, "GET", "/api/v1/sod/conflict-sets"); },
        createConflictSet: function (c, p) { return call(c, "POST", "/api/v1/sod/conflict-sets", p); },
        updateConflictSet: function (c, id, p) { return call(c, "PUT", "/api/v1/sod/conflict-sets/" + encodeURIComponent(id), p); },
        setConflictEnabled: function (c, id, en) { return call(c, "PATCH", "/api/v1/sod/conflict-sets/" + encodeURIComponent(id) + "/enabled", { enabled: en }); },
        deleteConflictSet: function (c, id) { return call(c, "DELETE", "/api/v1/sod/conflict-sets/" + encodeURIComponent(id)); },
        runSodScan: function (c, subaccountId) { return call(c, "POST", "/api/v1/sod/scan", { subaccountId: subaccountId }); },

        // --- containment ---
        runContainment: function (c, payload) { return call(c, "POST", "/api/v1/containment", payload); },
        runUnlock: function (c, payload) { return call(c, "POST", "/api/v1/containment/unlock", payload); },
        previewUnlock: function (c, userEmail, subaccountIds) {
            var qs = "?userEmail=" + encodeURIComponent(userEmail);
            (subaccountIds || []).forEach(function (id) { qs += "&subaccountIds=" + encodeURIComponent(id); });
            return call(c, "GET", "/api/v1/containment/unlock-preview" + qs);
        },
        listCertificates: function (c) { return call(c, "GET", "/api/v1/certificates"); },
        analyzeUser: function (c, email) {
            return call(c, "GET", "/api/v1/user-analysis?email=" + encodeURIComponent(email));
        },
        // 200 from the server, paginated to 20 visible by the Table's growing
        // setting - operator clicks "More" or scrolls to load the next batch.
        recentContainmentEvents: function (c) { return call(c, "GET", "/api/v1/logs?limit=200"); },
        // Aggregates XSUAA /sap/rest/identity-providers across the supplied
        // subaccounts (or every enrolled one when the array is empty) and
        // returns { origins: [{originKey, name, type, active, seenIn:[...]}],
        //           errors: [{subaccountId, subaccountDisplayName, error}] }.
        discoverOrigins: function (c, subaccountIds) {
            var qs = (subaccountIds && subaccountIds.length)
                ? "?subaccountIds=" + subaccountIds.map(encodeURIComponent).join(",")
                : "";
            return call(c, "GET", "/api/v1/xsuaa/identity-providers" + qs);
        },

        // --- audit log (filtered list + CSV/JSON export) ---
        listAuditEvents: function (c, filters) {
            // filters: { action, outcome, actor, targetEmail, fromDate, toDate,
            //            subaccountId, systemType, iasTenantId, limit }
            var qs = Object.keys(filters || {})
                .filter(function (k) { var v = filters[k]; return v !== undefined && v !== null && v !== ""; })
                .map(function (k) { return encodeURIComponent(k) + "=" + encodeURIComponent(filters[k]); })
                .join("&");
            return call(c, "GET", "/api/v1/logs" + (qs ? "?" + qs : ""));
        },
        downloadAuditExport: function (component, filters, format) {
            // fetch the export with the same auth headers as every other API
            // call (so it works in local profile too), then turn the body
            // into a Blob and drive a synthetic <a download> click. The file
            // never sits in user memory longer than necessary; URL.revokeObjectURL
            // releases the blob handle after the click fires.
            var fmt = (format || "csv").toLowerCase();
            var f = Object.assign({}, filters || {}, { format: fmt });
            var qs = Object.keys(f)
                .filter(function (k) { var v = f[k]; return v !== undefined && v !== null && v !== ""; })
                .map(function (k) { return encodeURIComponent(k) + "=" + encodeURIComponent(f[k]); })
                .join("&");
            var url = "/api/v1/logs/export" + (qs ? "?" + qs : "");
            var auth = resolveAuth(component);
            return fetch(url, {
                method: "GET",
                headers: { "X-Test-User": auth.user, "X-Test-Scopes": auth.scopes }
            }).then(function (res) {
                if (!res.ok) {
                    return res.text().then(function (txt) {
                        throw new Error("Export failed: HTTP " + res.status + " - " + (txt || "").substring(0, 200));
                    });
                }
                return res.blob();
            }).then(function (blob) {
                var stamp = new Date().toISOString().replace(/[:T]/g, "-").replace(/\..*$/, "");
                var filename = "audit-events-" + stamp + "." + fmt;
                var a = document.createElement("a");
                a.href = URL.createObjectURL(blob);
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(a.href);
            });
        },
        getHealth: function () {
            // Public endpoint - no headers needed
            return fetch("/api/v1/health").then(function (r) { return r.json(); });
        },

        // --- whoami (debug) ---
        whoami: function (c) { return call(c, "GET", "/api/v1/whoami"); },

        // --- app config (operator-tunable settings) ---
        listAppConfig: function (c) { return call(c, "GET", "/api/v1/app-config"); },
        setAppConfig: function (c, key, value) {
            return call(c, "PUT", "/api/v1/app-config/" + encodeURIComponent(key), { value: value });
        },

        // --- IAS tenants (Stage B: top-level, not per-subaccount) ---
        listIasTenants: function (c) { return call(c, "GET", "/api/v1/ias-tenants"); },
        createIasTenant: function (c, payload) { return call(c, "POST", "/api/v1/ias-tenants", payload); },
        updateIasTenantMeta: function (c, id, payload) {
            return call(c, "PATCH", "/api/v1/ias-tenants/" + encodeURIComponent(id) + "/meta", payload);
        },
        updateIasTenantCreds: function (c, id, payload) {
            return call(c, "PUT", "/api/v1/ias-tenants/" + encodeURIComponent(id) + "/credentials", payload);
        },
        deleteIasTenant: function (c, id) { return call(c, "DELETE", "/api/v1/ias-tenants/" + encodeURIComponent(id)); },

        // --- origin profiles (named, savable origin-key sets) ---
        listOriginProfiles: function (c) { return call(c, "GET", "/api/v1/origin-profiles"); },
        createOriginProfile: function (c, payload) { return call(c, "POST", "/api/v1/origin-profiles", payload); },
        updateOriginProfile: function (c, id, payload) {
            return call(c, "PUT", "/api/v1/origin-profiles/" + encodeURIComponent(id), payload);
        },
        deleteOriginProfile: function (c, id) {
            return call(c, "DELETE", "/api/v1/origin-profiles/" + encodeURIComponent(id));
        },

        // --- health checks (token probes across CIS / XSUAA / CF / IAS) ---
        runHealthCheck: function (c) { return call(c, "POST", "/api/v1/health-check/run"); },
        latestHealthCheck: function (c) { return call(c, "GET", "/api/v1/health-check/latest"); },

        // --- audit sinks (Splunk HEC + BTP Audit Log Service) ---
        listAuditSinks: function (c) { return call(c, "GET", "/api/v1/audit-sinks"); },
        saveAuditSink: function (c, kind, body) {
            return call(c, "PUT", "/api/v1/audit-sinks/" + encodeURIComponent(kind), body);
        },
        testAuditSink: function (c, kind) {
            return call(c, "POST", "/api/v1/audit-sinks/" + encodeURIComponent(kind) + "/test");
        }
    };
});
