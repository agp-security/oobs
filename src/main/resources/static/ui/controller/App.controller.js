// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

sap.ui.define([
    "sap/ui/core/mvc/Controller",
    "sap/ui/core/Fragment",
    "sap/ui/model/json/JSONModel",
    "sap/m/MessageBox",
    "sap/m/MessageToast",
    "sap/m/BusyDialog",
    "btpc/model/api"
], function (Controller, Fragment, JSONModel, MessageBox, MessageToast, BusyDialog, api) {
    "use strict";

    return Controller.extend("btpc.controller.App", {

        // =================== lifecycle ===================

        onInit: function () {
            // Nav model: drives visible-bound sections in App.view.xml.
            // Default = subaccounts so something renders on first paint.
            this.getView().setModel(new JSONModel({ currentPage: "subaccounts" }), "nav");

            // Shell view-model. The is* flags drive UI gating - sections /
            // buttons bind their visible/enabled to these so a responder
            // never sees the credential dialogs etc. Defaults below are
            // CONSERVATIVE (everything off) so the UI stays locked down
            // until /whoami has confirmed which scopes the user actually has.
            this.getView().setModel(new JSONModel({
                userLabel: this._i18n("shellUserAnon"),
                scopesLabel: "",
                initials: "?",
                devAuthEnabled: false,
                profilesLabel: "?",
                version: "?",
                isAdmin: false,
                isResponder: false,
                isSodViewer: false,
                isViewer: false,
                hasAnyRole: false
            }), "shell");

            // SoD view-model
            this.getView().setModel(new JSONModel({
                conflictSets: [],
                scanSubaccountId: null,
                lastScan: null
            }), "sod");
            // Seed the containment view-model up front so bindings have something
            // to read while the first GET /health returns.
            this.getView().setModel(new JSONModel({
                // Multi-tenant model. Empty arrays === "all" for the
                // tenant/subaccount pickers; the server treats null/empty
                // identically.
                iasTenantIds: [],
                subaccountIds: [],
                userEmail: "",
                actIasDeactivate: true,
                actIasStripGroups: false,
                actStripRoles: true,
                actDeleteShadow: true,
                actCfRevokeOrg: false,
                originMode: "all",         // 'all' | 'list' | 'discovered' | 'profile'
                originsList: "",           // CSV used in 'list' mode
                discoveredOrigins: [],     // populated by .onDiscoverOrigins
                discoverErrors: [],
                discoverBusy: false,
                selectedOrigins: [],       // chosen from discoveredOrigins
                originProfileId: "",       // chosen from saved profiles ('profile' mode)
                dryRun: true,
                comment: "",                // operator note / incident ticket id
                lastResult: null,
                events: [],
                unlockSubaccountIds: [],
                unlockIasTenantIds: [],
                unlockEmail: "",
                unlockDryRun: true,
                unlockComment: "",
                unlockActIasActivate: true,
                unlockActIasRestoreGroups: false,
                // Per-restore toggles. Default both ON so the unlock keeps
                // the historic "restore everything that was locked" muscle
                // memory; operators can untick to scope the restore.
                unlockActXsuaaRestore: true,
                unlockActCfRestore: true,
                unlockPreview: null,
                unlockPreviewBusy: false,
                lastUnlock: null
            }), "contain");
            // Discovery view-model (saved Central-Viewer keys + discovered candidates)
            this.getView().setModel(new JSONModel({
                savedKeys: [],
                candidates: [],
                showOnlyPromotable: true     // V12: default to "still missing"
            }), "discovery");
            // Logs view-model: filter values + the loaded rows.
            this.getView().setModel(new JSONModel({
                filters: {
                    action: "", outcome: "", systemType: "", actor: "", targetEmail: "",
                    fromDate: "", toDate: "", limit: 200
                },
                rows: []
            }), "logs");
            // KPI + trend models must exist before the first paint - the tile
            // sparklines and the Logs-tab microcharts bind against them, and
            // a missing named model means UI5 silently skips the binding (no
            // re-attach when the model is added later for aggregation
            // bindings like LineMicroChart.points). Seed both with empty
            // 14-day buckets so the charts render as a flat baseline until
            // refreshKpis() fills them in.
            this.getView().setModel(new JSONModel({
                protectionCount: 0,
                recentContainmentCount: 0,
                recentFailureCount: 0,
                conflictSetCount: 0,
                candidateCount: 0,
                enabledSinkCount: 0,
                recentEventWindow: 0
            }), "kpis");
            // Activity-driven trends: each point is an actual active day (for
            // lock/fail) or an enroll/unenroll event (for subaccount count).
            // Empty arrays render as blank until the first data fetch fills
            // them - acceptable since refreshKpis() runs immediately after.
            this.getView().setModel(new JSONModel({
                containmentTrend: [],
                failureTrend: [],
                subaccountTrend: [],
                outcomeBuckets: [],
                containmentMax: 0, containmentMean: 0, containmentMaxLabel: "0",
                containmentFirstLabel: "", containmentLastLabel: "",
                failureMax: 0, failureMean: 0, failureMaxLabel: "0",
                failureFirstLabel: "", failureLastLabel: "",
                subaccountMax: 0, subaccountMean: 0,
                subaccountStartLabel: "0", subaccountMaxLabel: "0",
                subaccountFirstLabel: "", subaccountLastLabel: ""
            }), "trends");
            this.loadSubaccounts().then(this.loadProtected.bind(this)).then(this.refreshKpis.bind(this));
            this._refreshShell();
        },

        _refreshShell: function () {
            var c = this.getOwnerComponent();
            var shell = this.getView().getModel("shell");
            // /health is public - pulls profile + dev-auth flag + version
            fetch("/api/v1/health")
                .then(function (r) { return r.json(); })
                .then(function (h) {
                    shell.setProperty("/profilesLabel", (h.profiles || []).join(","));
                    shell.setProperty("/devAuthEnabled", !!h.devAuthEnabled);
                    shell.setProperty("/version", h.version || "?");
                })
                .catch(function () {});
            // /whoami is auth-required - reflects the actual server-side principal.
            // We turn the scopes array into a Set + per-role booleans so the
            // view bindings (visible / enabled) can drive UI gating directly.
            api.whoami(c)
                .then(function (w) {
                    var name = w && w.user ? w.user : (w && w.authenticated === false ? "anonymous" : "?");
                    shell.setProperty("/userLabel", name);
                    var scopes = (w && w.scopes) || [];
                    shell.setProperty("/scopesLabel", scopes.join(", "));
                    var has = function (s) { return scopes.indexOf("btpc." + s) >= 0; };
                    // Admin's role-template grants all four scopes, so the
                    // isAdmin path automatically unlocks the responder/sod
                    // UI too without needing a separate role assignment.
                    var admin    = has("admin");
                    var responder = admin || has("responder");
                    var sodViewer = admin || has("sod_viewer");
                    var viewer    = admin || responder || sodViewer || has("viewer");
                    shell.setProperty("/isAdmin",     admin);
                    shell.setProperty("/isResponder", responder);
                    shell.setProperty("/isSodViewer", sodViewer);
                    shell.setProperty("/isViewer",    viewer);
                    shell.setProperty("/hasAnyRole",  admin || responder || sodViewer || viewer);
                    shell.setProperty("/initials", initialsOf(name));
                })
                .catch(function () {
                    shell.setProperty("/userLabel", "anonymous");
                    shell.setProperty("/initials", "?");
                });

            function initialsOf(name) {
                if (!name) return "?";
                // foo@bar.com -> F; "Alice Bob" -> AB
                if (name.indexOf("@") !== -1) return name.charAt(0).toUpperCase();
                var parts = name.split(/\s+/).filter(Boolean);
                if (parts.length === 0) return "?";
                if (parts.length === 1) return parts[0].charAt(0).toUpperCase();
                return (parts[0].charAt(0) + parts[parts.length - 1].charAt(0)).toUpperCase();
            }
        },

        // =================== shell / user menu ===================

        onAvatarPressed: function (oEvent) {
            var self = this;
            var view = this.getView();
            var openAt = oEvent.getParameter("avatar") || oEvent.getSource();
            var open = function () { self._userMenu.openBy(openAt); };
            if (!this._userMenu) {
                Fragment.load({
                    id: view.getId(),
                    name: "btpc.view.UserMenu",
                    controller: this
                }).then(function (pop) {
                    self._userMenu = pop;
                    view.addDependent(pop);
                    open();
                });
            } else {
                open();
            }
        },

        onHomePressed: function () {
            this.byId("tabs").setSelectedKey("subaccounts");
            this.loadSubaccounts();
        },

        onOpenSettings: function () {
            // SettingsDialog now holds only user-scoped settings (dev-auth,
            // server-state read-out). Infrastructure config (audit sinks +
            // external-email allowlist) moved to the Admin tab.
            if (this._userMenu) this._userMenu.close();
            var view = this.getView();
            var self = this;
            if (!this._settingsDialog) {
                Fragment.load({
                    id: view.getId(),
                    name: "btpc.view.SettingsDialog",
                    controller: this
                }).then(function (dlg) {
                    self._settingsDialog = dlg;
                    view.addDependent(dlg);
                    dlg.open();
                });
            } else {
                this._settingsDialog.open();
            }
        },

        _loadAppConfig: function () {
            var view = this.getView();
            if (!view.getModel("appcfg")) {
                view.setModel(new JSONModel({
                    externalEmailDomains: "",
                    externalEmailDomainsOverridden: false,
                    healthAutoIntervalSeconds: "0"
                }), "appcfg");
            }
            api.listAppConfig(this.getOwnerComponent()).then(function (cfg) {
                var m = view.getModel("appcfg");
                if (!m) return;
                var ext = (cfg && cfg["external_email.internal_domains"]) || {};
                m.setProperty("/externalEmailDomains", ext.value || "");
                m.setProperty("/externalEmailDomainsOverridden", !!ext.overridden);
                var hci = (cfg && cfg["health.auto.interval_seconds"]) || {};
                m.setProperty("/healthAutoIntervalSeconds", hci.value || "0");
            }).catch(function (e) {
                MessageToast.show("Could not load app config: " + e.message);
            });
            // Audit sinks (Splunk HEC + BTP Audit Log) load in parallel - the
            // settings dialog shows both cards together.
            this._loadAuditSinks();
        },

        onSaveHealthAutoInterval: function () {
            var view = this.getView();
            var v = (view.getModel("appcfg").getProperty("/healthAutoIntervalSeconds") || "0").trim();
            if (!/^\d+$/.test(v)) {
                MessageBox.error("Interval must be a non-negative integer (seconds). 0 disables.");
                return;
            }
            var self = this;
            api.setAppConfig(this.getOwnerComponent(), "health.auto.interval_seconds", v)
                .then(function (state) {
                    view.getModel("appcfg").setProperty("/healthAutoIntervalSeconds", state.value || "0");
                    MessageToast.show(self._i18n("settingsHealthAutoSaved"));
                })
                .catch(self._showError.bind(self));
        },

        onRunHealthCheck: function () {
            var view = this.getView();
            if (!view.getModel("health")) {
                view.setModel(new JSONModel({ report: null, busy: false }), "health");
            }
            var m = view.getModel("health");
            m.setProperty("/busy", true);
            var self = this;
            // ETA: ~2s per probe (XSUAA + CF)  subaccount count + ~3s per
            // IAS tenant + ~2s per central key. Matches the per-action
            // numbers used in containment, scaled for the probe-only path.
            var saCount = (view.getModel("data")
                && (view.getModel("data").getProperty("/subaccounts") || []).length) || 0;
            var tenCount = (view.getModel("iasTenants")
                && (view.getModel("iasTenants").getProperty("/list") || []).length) || 0;
            var centralCount = (view.getModel("discovery")
                && (view.getModel("discovery").getProperty("/savedKeys") || []).length) || 0;
            var eta = saCount * 2 * 2 + tenCount * self._PROGRESS_PER_TENANT_S + centralCount * 2;
            var prog = self._openProgressDialog("Health check", eta);
            api.runHealthCheck(this.getOwnerComponent())
                .then(function (r) {
                    prog.done();
                    self._flattenHealthReport(r);
                    m.setProperty("/report", r);
                    var failed = r.totalProbes - r.okProbes;
                    MessageToast.show(failed === 0
                        ? ("Health check OK - " + r.okProbes + "/" + r.totalProbes + " probes")
                        : ("Health check - " + failed + " failed of " + r.totalProbes));
                    return self.refreshKpis();
                })
                .catch(function (err) { prog.done(); self._showError(err); })
                .finally(function () { m.setProperty("/busy", false); });
        },

        loadLatestHealthCheck: function () {
            var view = this.getView();
            if (!view.getModel("health")) {
                view.setModel(new JSONModel({ report: null, busy: false }), "health");
            }
            var m = view.getModel("health");
            var self = this;
            api.latestHealthCheck(this.getOwnerComponent())
                .then(function (r) {
                    if (r) {
                        self._flattenHealthReport(r);
                        m.setProperty("/report", r);
                    }
                })
                .catch(function () { /* no run yet */ });
        },

        // Backend returns nested perSubaccount[{displayName, probes:[...]}].
        // The view binds a flat table to one row per (subaccount, probe);
        // the subaccount label repeats for readability and sorting. perTenant
        // is already one probe per row but we mirror the shape so both tables
        // share columns.
        _flattenHealthReport: function (r) {
            var flat = [];
            (r.perSubaccount || []).forEach(function (sa) {
                (sa.probes || []).forEach(function (p) {
                    flat.push({
                        displayName: sa.displayName,
                        kind: p.kind,
                        outcome: p.outcome,
                        latencyMs: p.latencyMs,
                        message: p.message
                    });
                });
                if (!sa.probes || sa.probes.length === 0) {
                    flat.push({
                        displayName: sa.displayName,
                        kind: "-", outcome: "-", latencyMs: null,
                        message: "(no credentials attached)"
                    });
                }
            });
            r.perSubaccountFlat = flat;
            r.perTenantFlat = (r.perTenant || []).map(function (t) {
                return {
                    displayName: t.displayName,
                    iasHost: t.iasHost,
                    outcome: t.probe && t.probe.outcome,
                    latencyMs: t.probe && t.probe.latencyMs,
                    message: t.probe && t.probe.message
                };
            });
            r.perCentralKeyFlat = (r.perCentralKey || []).map(function (c) {
                return {
                    label: c.label || "(unnamed)",
                    globalAccountName: c.globalAccountName,
                    outcome: c.probe && c.probe.outcome,
                    latencyMs: c.probe && c.probe.latencyMs,
                    message: c.probe && c.probe.message
                };
            });
        },

        _loadAuditSinks: function () {
            var view = this.getView();
            var blank = {
                splunk: { enabled: false, config: {}, hasSecret: false, secret: "",
                          lastTestAt: null, lastTestStatus: null, lastTestMessage: "" },
                btp:    { enabled: false, config: {}, hasSecret: false, secret: "",
                          lastTestAt: null, lastTestStatus: null, lastTestMessage: "" }
            };
            if (!view.getModel("sinks")) view.setModel(new JSONModel(blank), "sinks");
            else view.getModel("sinks").setData(blank);
            api.listAuditSinks(this.getOwnerComponent()).then(function (list) {
                var m = view.getModel("sinks");
                (list || []).forEach(function (s) {
                    var slot = s.kind === "splunk_hec" ? "splunk"
                            : s.kind === "btp_audit_log" ? "btp" : null;
                    if (!slot) return;
                    m.setProperty("/" + slot + "/enabled", !!s.enabled);
                    m.setProperty("/" + slot + "/config", s.config || {});
                    m.setProperty("/" + slot + "/hasSecret", !!s.hasSecret);
                    m.setProperty("/" + slot + "/lastTestAt", s.lastTestAt);
                    m.setProperty("/" + slot + "/lastTestStatus", s.lastTestStatus);
                    m.setProperty("/" + slot + "/lastTestMessage", s.lastTestMessage);
                });
            }).catch(function (e) { MessageToast.show("Could not load audit sinks: " + e.message); });
        },

        // press="...('kind')" passes the literal string as the second arg of the handler
        onSaveAuditSink: function (oEvt, kind) {
            var slot = kind === "splunk_hec" ? "splunk"
                    : kind === "btp_audit_log" ? "btp" : null;
            if (!slot) return;
            var view = this.getView();
            var data = view.getModel("sinks").getProperty("/" + slot);
            var self = this;
            var body = {
                enabled: !!data.enabled,
                config: data.config || {},
                secret: data.secret || ""  // blank = keep existing
            };
            api.saveAuditSink(this.getOwnerComponent(), kind, body)
                .then(function () {
                    MessageToast.show(self._i18n("toastAuditSinkSaved"));
                    return self._loadAuditSinks();
                })
                .catch(self._showError.bind(self));
        },

        onTestAuditSink: function (oEvt, kind) {
            var self = this;
            api.testAuditSink(this.getOwnerComponent(), kind)
                .then(function (res) {
                    MessageToast.show(res.ok
                        ? (self._i18n("toastAuditSinkTestOk") + " " + (res.message || ""))
                        : (self._i18n("toastAuditSinkTestFailed") + " " + (res.message || "")));
                    return self._loadAuditSinks();
                })
                .catch(self._showError.bind(self));
        },

        onSaveExternalEmailDomains: function () {
            var view = this.getView();
            var value = view.getModel("appcfg").getProperty("/externalEmailDomains") || "";
            var self = this;
            api.setAppConfig(this.getOwnerComponent(), "external_email.internal_domains", value)
                .then(function (state) {
                    view.getModel("appcfg").setProperty("/externalEmailDomains", state.value || "");
                    view.getModel("appcfg").setProperty("/externalEmailDomainsOverridden", !!state.overridden);
                    MessageToast.show(self._i18n("settingsExtEmailSaved"));
                })
                .catch(function (e) { MessageToast.show("Save failed: " + e.message); });
        },

        onCloseSettings: function () {
            if (this._settingsDialog) this._settingsDialog.close();
        },

        onOpenAbout: function () {
            if (this._userMenu) this._userMenu.close();
            var view = this.getView();
            var self = this;
            if (!this._aboutDialog) {
                Fragment.load({
                    id: view.getId(),
                    name: "btpc.view.AboutDialog",
                    controller: this
                }).then(function (dlg) {
                    self._aboutDialog = dlg;
                    view.addDependent(dlg);
                    dlg.open();
                });
            } else {
                this._aboutDialog.open();
            }
        },

        onCloseAbout: function () {
            if (this._aboutDialog) this._aboutDialog.close();
        },

        onLogout: function () {
            if (this._userMenu) this._userMenu.close();
            // Cloud: approuter handles real logout. Local: clear dev-auth and reload.
            // Either way, just navigate to /logout - approuter consumes it; in
            // local profile it 404s (which we render as a quiet 404).
            try { localStorage.removeItem("btpc.devAuth"); } catch (_) {}
            window.location.href = "/logout";
        },

        onTabSelect: function (oEvent) {
            var key = oEvent.getParameter("key");
            if (key === "subaccounts") this.loadSubaccounts();
            else if (key === "protected") this.loadProtected();
            else if (key === "containment") {
                this.onRefreshContainmentEvents();
                // Tenant picker in the containment form needs the current
                // tenant list. Cheap call, always fresh.
                this.onRefreshIasTenants();
                // Origin profiles populate the 'profile' mode dropdown.
                this.loadOriginProfiles();
            }
            else if (key === "health") {
                // Hydrate the matrix from the cached last run so the
                // dedicated page isn't blank on first visit.
                this.loadLatestHealthCheck();
            }
            else if (key === "sod") this.onRefreshConflictSets();
            else if (key === "discovery") this.loadDiscovery();
            else if (key === "logs") this.onApplyLogFilters();
            else if (key === "iasTenants") this.onRefreshIasTenants();
            else if (key === "certificates") this.loadCertificates();
            else if (key === "userAnalysis") this._ensureUserAnalysisModel();
            else if (key === "admin") this._loadAdminTab();
        },

        // ---------------- user analysis ----------------

        _ensureUserAnalysisModel: function () {
            var view = this.getView();
            if (!view.getModel("userAnalysis")) {
                view.setModel(new JSONModel({
                    email: "",
                    filter: "",
                    busy: false,
                    viewMode: "table",   // "table" | "graph"
                    lastReport: null,
                    summaryText: "",
                    tenantsHit: 0,
                    subaccountsHit: 0,
                    // Bound to the table views:
                    tenants: [],         // flattened tenant rows (filtered)
                    subaccountRows: [],  // flattened (subaccount, assignment) rows
                    errors: [],          // [{subaccountName, message}]
                    // Bound to the networkgraph view:
                    graphNodes: [],
                    graphLines: []
                }), "userAnalysis");
            }
        },

        onRunUserAnalysis: function () {
            var view = this.getView();
            this._ensureUserAnalysisModel();
            var m = view.getModel("userAnalysis");
            var email = (m.getProperty("/email") || "").trim();
            var emailCheck = this._validateEmail(email);
            if (!emailCheck.ok) { MessageBox.error("Email: " + emailCheck.error); return; }
            m.setProperty("/email", emailCheck.cleaned);
            m.setProperty("/busy", true);
            var self = this;
            api.analyzeUser(this.getOwnerComponent(), emailCheck.cleaned)
                .then(function (rep) {
                    self._processUserAnalysisReport(rep);
                })
                .catch(self._showError.bind(self))
                .finally(function () { m.setProperty("/busy", false); });
        },

        // Flattens the backend response into table-friendly rows + summary.
        // Filter is applied as part of the flatten so onUserAnalysisFilterChange
        // can re-run it cheaply against the cached lastReport.
        _processUserAnalysisReport: function (rep) {
            var m = this.getView().getModel("userAnalysis");
            m.setProperty("/lastReport", rep);
            this._refreshUserAnalysisRows();
        },

        onUserAnalysisFilterChange: function () {
            this._refreshUserAnalysisRows();
        },

        _refreshUserAnalysisRows: function () {
            var m = this.getView().getModel("userAnalysis");
            var rep = m.getProperty("/lastReport");
            if (!rep) return;
            var q = (m.getProperty("/filter") || "").toLowerCase().trim();
            var match = function (s) {
                if (!q) return true;
                return s != null && String(s).toLowerCase().indexOf(q) >= 0;
            };

            // ---- Tenant rows ----
            var tenants = [];
            var tenantsHit = 0;
            (rep.iasTenants || []).forEach(function (t) {
                var groupsText = (t.iasGroups || []).map(function (g) {
                    return g.displayName || g.id;
                }).join(", ");
                var presence;
                if (t.error) presence = "error";
                else if (!t.userFound) presence = "not present";
                else presence = (t.iasUserActive === false ? "deactivated" : "active");
                var row = {
                    displayName: t.displayName,
                    iasHost: t.iasHost,
                    userFound: !!t.userFound,
                    iasUserActive: t.iasUserActive,
                    presenceLabel: presence,
                    groupsText: groupsText,
                    error: t.error || ""
                };
                if (!q || match(row.displayName) || match(row.iasHost)
                        || match(row.groupsText) || match(row.presenceLabel)) {
                    tenants.push(row);
                }
                if (t.userFound) tenantsHit++;
            });

            // ---- Subaccount assignment rows (one per assignment) ----
            var subRows = [];
            var errors = [];
            var saHit = 0;
            (rep.subaccounts || []).forEach(function (sa) {
                var anyAssignment = false;
                (sa.shadowUsers || []).forEach(function (su) {
                    anyAssignment = true;
                    var row = {
                        subaccountName: sa.displayName, region: sa.region,
                        source: "XSUAA (shadow)",
                        assignment: su.id,
                        context: "origin=" + su.origin
                    };
                    if (!q || match(row.subaccountName) || match(row.region)
                            || match(row.source) || match(row.assignment) || match(row.context)) {
                        subRows.push(row);
                    }
                });
                (sa.directRcs || []).forEach(function (r) {
                    anyAssignment = true;
                    var row = {
                        subaccountName: sa.displayName, region: sa.region,
                        source: "XSUAA (direct)",
                        assignment: r.roleCollection,
                        context: "origin=" + r.origin
                    };
                    if (!q || match(row.subaccountName) || match(row.region)
                            || match(row.source) || match(row.assignment) || match(row.context)) {
                        subRows.push(row);
                    }
                });
                (sa.mappedRcs || []).forEach(function (r) {
                    anyAssignment = true;
                    var row = {
                        subaccountName: sa.displayName, region: sa.region,
                        source: "XSUAA (via IAS group)",
                        assignment: r.roleCollection,
                        context: "origin=" + r.origin + ", via group=" + r.viaIasGroup
                    };
                    if (!q || match(row.subaccountName) || match(row.region)
                            || match(row.source) || match(row.assignment) || match(row.context)) {
                        subRows.push(row);
                    }
                });
                (sa.cfRoles || []).forEach(function (r) {
                    anyAssignment = true;
                    var ctx = "org=" + (r.orgGuid || "").substring(0, 8) + "...";
                    if (r.spaceName) ctx += ", space=" + r.spaceName;
                    var row = {
                        subaccountName: sa.displayName, region: sa.region,
                        source: "CF",
                        assignment: r.type,
                        context: ctx
                    };
                    if (!q || match(row.subaccountName) || match(row.region)
                            || match(row.source) || match(row.assignment) || match(row.context)) {
                        subRows.push(row);
                    }
                });
                if (anyAssignment) saHit++;
                (sa.errors || []).forEach(function (e) {
                    errors.push({ subaccountName: sa.displayName, message: e });
                });
            });

            m.setProperty("/tenants", tenants);
            m.setProperty("/subaccountRows", subRows);
            m.setProperty("/errors", errors);
            m.setProperty("/tenantsHit", tenantsHit);
            m.setProperty("/subaccountsHit", saHit);
            m.setProperty("/summaryText",
                tenantsHit + " IAS tenant(s) host this user, "
                + saHit + " subaccount(s) grant assignments, "
                + subRows.length + " row(s) shown");
            this._buildUserAnalysisGraph(rep);
        },

        // Networkgraph builder. Hub-and-spoke shape with the user at the
        // center. Three rings around it:
        //   - left: IAS tenants the user exists in, with IAS group children
        //   - right: subaccounts where the user has assignments, with role
        //     collection / CF role children
        // The `group` field clusters node neighbours visually in LayeredLayout.
        // Status mapping reuses the same Information/Warning/Success/Error
        // palette as the rest of the UI.
        _buildUserAnalysisGraph: function (rep) {
            if (!rep) return;
            var m = this.getView().getModel("userAnalysis");
            var nodes = [];
            var lines = [];
            var rootKey = "user";
            nodes.push({
                key: rootKey,
                title: rep.email,
                description: "subject",
                status: "Information",
                icon: "sap-icon://person-placeholder"
            });

            var truncate = function (s, n) {
                if (s == null) return "";
                s = String(s);
                return s.length > n ? s.substring(0, n - 1) + "..." : s;
            };

            // --- IAS tenants ---
            (rep.iasTenants || []).forEach(function (t, i) {
                if (!t.userFound) return;        // skip tenants where the user doesn't exist
                var tKey = "ias-" + i;
                var tStatus = t.iasUserActive === false ? "Warning" : "Success";
                nodes.push({
                    key: tKey,
                    title: t.displayName,
                    description: t.iasHost + (t.iasUserActive === false ? " (deactivated)" : ""),
                    status: tStatus,
                    icon: "sap-icon://locked"
                });
                lines.push({ from: rootKey, to: tKey });
                (t.iasGroups || []).forEach(function (g, j) {
                    var gKey = tKey + "-grp-" + j;
                    nodes.push({
                        key: gKey,
                        title: truncate(g.displayName || g.id, 32),
                        description: "IAS group",
                        status: "Information",
                        icon: "sap-icon://group" + i
                    });
                    lines.push({ from: tKey, to: gKey });
                });
            });

            // --- Subaccounts ---
            (rep.subaccounts || []).forEach(function (sa, i) {
                var hasAny = (sa.shadowUsers || []).length > 0
                          || (sa.directRcs || []).length > 0
                          || (sa.mappedRcs || []).length > 0
                          || (sa.cfRoles || []).length > 0;
                if (!hasAny) return;
                var saKey = "sa-" + i;
                nodes.push({
                    key: saKey,
                    title: sa.displayName,
                    description: sa.region,
                    status: "Success",
                    icon: "sap-icon://building"
                });
                lines.push({ from: rootKey, to: saKey });

                // Direct + mapped role collections - dedupe by RC name so
                // a user who has the same RC both directly and via mapping
                // shows as one node with a note in the description.
                var rcByName = {};
                (sa.directRcs || []).forEach(function (r) {
                    var k = r.roleCollection;
                    if (!rcByName[k]) rcByName[k] = { rc: k, sources: [], origins: [] };
                    rcByName[k].sources.push("direct");
                    rcByName[k].origins.push(r.origin);
                });
                (sa.mappedRcs || []).forEach(function (r) {
                    var k = r.roleCollection;
                    if (!rcByName[k]) rcByName[k] = { rc: k, sources: [], origins: [] };
                    rcByName[k].sources.push("via " + r.viaIasGroup);
                    rcByName[k].origins.push(r.origin);
                });
                Object.keys(rcByName).forEach(function (name, j) {
                    var d = rcByName[name];
                    var rcKey = saKey + "-rc-" + j;
                    var viaMapping = d.sources.some(function (s) { return s !== "direct"; });
                    nodes.push({
                        key: rcKey,
                        title: truncate(d.rc, 36),
                        description: d.sources.join(", "),
                        // Warning state when the RC is granted only via a mapping
                        // rule (no shadow membership yet) - useful to spot
                        // pre-login risks.
                        status: viaMapping && d.sources.length === 1 ? "Warning" : "Information",
                        icon: "sap-icon://key" + i
                    });
                    lines.push({ from: saKey, to: rcKey });
                });

                // CF roles. Group by org first (only one org per subaccount today
                // because of the pinned cf_org_id), then space subnodes hang off.
                if ((sa.cfRoles || []).length > 0 && sa.cfRoles[0].orgGuid) {
                    var orgKey = saKey + "-org";
                    nodes.push({
                        key: orgKey,
                        title: "CF org",
                        description: truncate(sa.cfRoles[0].orgGuid, 12),
                        status: "Success",
                        icon: "sap-icon://cargo-train" + i
                    });
                    lines.push({ from: saKey, to: orgKey });
                    var spaceKeys = {};
                    (sa.cfRoles || []).forEach(function (r, j) {
                        var parent = orgKey;
                        if (r.spaceGuid) {
                            var sKey = saKey + "-sp-" + r.spaceGuid;
                            if (!spaceKeys[sKey]) {
                                spaceKeys[sKey] = true;
                                nodes.push({
                                    key: sKey,
                                    title: r.spaceName || "space",
                                    description: "CF space",
                                    status: "Information",
                                    icon: "sap-icon://product" + i
                                });
                                lines.push({ from: orgKey, to: sKey });
                            }
                            parent = sKey;
                        }
                        var roleKey = saKey + "-role-" + j;
                        nodes.push({
                            key: roleKey,
                            title: r.type,
                            description: r.spaceName ? "space role" : "org role",
                            status: "Information",
                            icon: "sap-icon://shield" + i
                        });
                        lines.push({ from: parent, to: roleKey });
                    });
                }
            });

            m.setProperty("/graphNodes", nodes);
            m.setProperty("/graphLines", lines);
        },

        // ---------------- certificates tab ----------------

        loadCertificates: function () {
            var view = this.getView();
            if (!view.getModel("certs")) {
                view.setModel(new JSONModel({ rows: [], busy: false, expiringSoon: 0 }), "certs");
            }
            var m = view.getModel("certs");
            m.setProperty("/busy", true);
            api.listCertificates(this.getOwnerComponent())
                .then(function (rows) {
                    rows = rows || [];
                    var soon = rows.filter(function (r) {
                        return r.daysUntilExpiry !== null && r.daysUntilExpiry <= 30;
                    }).length;
                    m.setProperty("/rows", rows);
                    m.setProperty("/expiringSoon", soon);
                })
                .catch(this._showError.bind(this))
                .finally(function () { m.setProperty("/busy", false); });
        },

        // SideNavigation drives the (now-hidden) IconTabBar.selectedKey.
        // We keep IconTabBar as the actual content host because all the
        // existing IconTabFilter children + bindings already live there.
        onNavItemSelect: function (oEvent) {
            this._navigateToKey(oEvent.getParameter("item").getKey());
        },

        // KPI tile press -> same navigation path as SideNavigation click.
        // press="...('subaccounts')" passes the literal key string as the
        // second argument; we route through _navigateToKey so the SideNav
        // selected mark stays in lockstep with the active content.
        onKpiPress: function (oEvt, key) { this._navigateToKey(key); },

        // Dedicated wrapper for buttons that don't pass through the
        // press="onKpiPress('admin')" two-arg pattern correctly (the
        // health-page "Configure in Admin" button was being called with
        // the literal as the first arg -> _navigateToKey(undefined) -> no-op).
        // Using a plain handler bypasses the binding quirk.
        onGoToAdmin:        function () { this._navigateToKey("admin"); },
        onGoToContainment:  function () { this._navigateToKey("containment"); },
        onGoToSubaccounts:  function () { this._navigateToKey("subaccounts"); },

        _navigateToKey: function (key) {
            if (!key) return;
            // Visible-bound sections in App.view.xml read `nav>/currentPage`;
            // setting it here makes the matching section render + hides the
            // others. No NavContainer absolute-positioning gotcha, no
            // IconTabBar tab-strip hack.
            var view = this.getView();
            if (!view.getModel("nav")) {
                view.setModel(new JSONModel({ currentPage: key }), "nav");
            } else {
                view.getModel("nav").setProperty("/currentPage", key);
            }
            // Sync SideNavigation's selected highlight.
            var sideNav = this.byId("sideNav");
            if (sideNav) {
                if (typeof sideNav.setSelectedKey === "function") {
                    sideNav.setSelectedKey(key);
                } else {
                    var list = sideNav.getItem && sideNav.getItem();
                    if (list && list.getItems) {
                        list.getItems().forEach(function (it) {
                            if (it.getKey && it.getKey() === key && list.setSelectedItem) {
                                list.setSelectedItem(it);
                            }
                        });
                    }
                }
            }
            // Trigger the same load logic onTabSelect handles.
            this.onTabSelect({ getParameter: function () { return key; } });
        },

        // Admin tab loads the audit sinks + the external-email app-config
        // value (which the SettingsDialog used to host).
        _loadAdminTab: function () {
            this._loadAuditSinks();
            this._loadAppConfig();
            this.loadOriginProfiles();
        },

        // Date formatter shared by tables - IAS tenants table uses this on
        // updatedAt. Tolerant of null / undefined / non-ISO strings.
        fmtDate: function (raw) {
            if (!raw) return "";
            try {
                var d = new Date(raw);
                if (isNaN(d.getTime())) return raw;
                return d.toISOString().replace("T", " ").replace(/\..*$/, "");
            } catch (_) { return raw; }
        },

        // =================== dev-auth bar ===================

        onSaveDevAuth: function () {
            var auth = this.getOwnerComponent().getModel("devAuth").getData();
            localStorage.setItem("btpc.devAuth", JSON.stringify({
                user: auth.user || "", scopes: auth.scopes || ""
            }));
            MessageToast.show("Dev auth saved");
            this.onInit();
        },

        // =================== subaccounts list ===================

        loadSubaccounts: function () {
            var c = this.getOwnerComponent();
            return api.listSubaccounts(c)
                .then(function (list) {
                    c.getModel("data").setProperty("/subaccounts", list || []);
                })
                .catch(this._showError.bind(this));
        },

        onRefresh: function () {
            this.loadSubaccounts();
            this.refreshKpis();
        },

        // Buckets recent events into per-day counts (last 14 days) so the
        // KPI tile sparklines and the Logs-tab trend panel have data. Two
        // series: containmentTrend (lock/unlock actions per day) and
        // failureTrend (failed events per day). Plus outcomeBuckets for
        // a column chart breakdown. Stamped on a shared `trends` model;
        // the views bind sap.suite.ui.microchart against the arrays.
        _computeTrends: function (events, lockVerbs) {
            var view = this.getView();
            if (!view.getModel("trends")) {
                view.setModel(new JSONModel({
                    containmentTrend: [],
                    failureTrend: [],
                    subaccountTrend: [],
                    outcomeBuckets: []
                }), "trends");
            }
            var m = view.getModel("trends");
            var MAX_POINTS = 14;
            var todayKey = new Date().toISOString().slice(0, 10);

            // Rolling 14-day window keyed by day. ColumnMicroChart needs a
            // fixed column count per chart so the visual cadence matches
            // calendar time - a single recent spike used to look like a
            // downward slope on the line chart because earlier zero-days
            // were elided. With the zero-fill the chart correctly shows
            // one tall bar surrounded by flat baseline days.
            function lastNDays(n) {
                var out = [];
                var d = new Date(todayKey + "T00:00:00Z");
                for (var i = n - 1; i >= 0; i--) {
                    var dt = new Date(d.getTime());
                    dt.setUTCDate(d.getUTCDate() - i);
                    out.push(dt.toISOString().slice(0, 10));
                }
                return out;
            }
            var windowDays = lastNDays(MAX_POINTS);

            var lockByDay = {}, failByDay = {};
            (events || []).forEach(function (e) {
                var day = (e.startedAt || "").slice(0, 10);
                if (!day) return;
                if (lockVerbs[e.action]) lockByDay[day] = (lockByDay[day] || 0) + 1;
                if (e.outcome === "failed") failByDay[day] = (failByDay[day] || 0) + 1;
            });
            // Each point carries BOTH the line-chart fields (x, xLabel, y)
            // and the column-chart fields (label, value) so the same array
            // drives whichever chart type the view picks.
            function fillTrend(byDay) {
                return windowDays.map(function (d, i) {
                    var n = byDay[d] || 0;
                    return {
                        x: i,
                        xLabel: d.substring(5),
                        y: n,
                        label: (i === 0 || i === windowDays.length - 1) ? d.substring(5) : "",
                        value: n
                    };
                });
            }
            var contTrend = fillTrend(lockByDay);
            var failTrend = fillTrend(failByDay);

            // Cumulative enrolled-subaccount curve as a stair-step over the
            // same 14-day window the column charts use. We back-solve the
            // starting count from "current count minus net delta visible in
            // the window" so the line lands at today's real count even when
            // earlier audit history is missing.
            var subs = (view.getModel("data") && view.getModel("data").getProperty("/subaccounts")) || [];
            var current = subs.length;
            var deltaByDay = {};
            subs.forEach(function (s) {
                var day = (s.enrolledAt || "").slice(0, 10);
                if (day) deltaByDay[day] = (deltaByDay[day] || 0) + 1;
            });
            (events || []).forEach(function (e) {
                if (e.action !== "unenroll") return;
                var day = (e.startedAt || "").slice(0, 10);
                if (day) deltaByDay[day] = (deltaByDay[day] || 0) - 1;
            });
            // Sum only the deltas that fall inside the window - older deltas
            // are baked into the starting count instead, otherwise the line
            // would jump above the real "current" value.
            var windowSet = {};
            windowDays.forEach(function (d) { windowSet[d] = true; });
            var windowDelta = 0;
            Object.keys(deltaByDay).forEach(function (d) {
                if (windowSet[d]) windowDelta += deltaByDay[d];
            });
            var startCount = current - windowDelta;
            if (startCount < 0) startCount = 0;
            var running = startCount;
            var subTrend = windowDays.map(function (d, i) {
                running += (deltaByDay[d] || 0);
                if (running < 0) running = 0;
                return {
                    x: i,
                    xLabel: d.substring(5),
                    y: running,
                    label: (i === 0 || i === windowDays.length - 1) ? d.substring(5) : "",
                    value: running
                };
            });

            function statsFor(trend) {
                var max = 0, sum = 0;
                trend.forEach(function (p) {
                    if (p.y > max) max = p.y;
                    sum += p.y;
                });
                return {
                    max: max,
                    mean: trend.length ? sum / trend.length : 0,
                    first: trend.length ? trend[0].xLabel : "",
                    last: trend.length ? trend[trend.length - 1].xLabel : ""
                };
            }
            var contStats = statsFor(contTrend);
            var failStats = statsFor(failTrend);
            var subStats  = statsFor(subTrend);
            var subStart  = subTrend.length ? subTrend[0].y : current;

            m.setProperty("/containmentTrend", contTrend);
            m.setProperty("/failureTrend", failTrend);
            m.setProperty("/subaccountTrend", subTrend);

            m.setProperty("/containmentMax", contStats.max);
            m.setProperty("/containmentMean", contStats.mean);
            m.setProperty("/containmentMaxLabel", "max " + contStats.max);
            m.setProperty("/containmentFirstLabel", contStats.first);
            m.setProperty("/containmentLastLabel",  contStats.last);

            m.setProperty("/failureMax", failStats.max);
            m.setProperty("/failureMean", failStats.mean);
            m.setProperty("/failureMaxLabel", "max " + failStats.max);
            m.setProperty("/failureFirstLabel", failStats.first);
            m.setProperty("/failureLastLabel",  failStats.last);

            m.setProperty("/subaccountMax", subStats.max);
            m.setProperty("/subaccountMean", subStats.mean);
            m.setProperty("/subaccountStartLabel", String(subStart));
            m.setProperty("/subaccountMaxLabel", String(subStats.max));
            m.setProperty("/subaccountFirstLabel", subStats.first);
            m.setProperty("/subaccountLastLabel",  subStats.last);

            var outcomeCounts = { ok: 0, failed: 0, "dry-run": 0, skipped: 0, partial: 0 };
            (events || []).forEach(function (e) {
                if (outcomeCounts[e.outcome] != null) outcomeCounts[e.outcome]++;
            });
            m.setProperty("/outcomeBuckets", [
                { label: "OK",       value: outcomeCounts.ok,         color: "Good" },
                { label: "Partial",  value: outcomeCounts.partial,    color: "Critical" },
                { label: "Skipped",  value: outcomeCounts.skipped,    color: "Critical" },
                { label: "Dry-run",  value: outcomeCounts["dry-run"], color: "Neutral" },
                { label: "Failed",   value: outcomeCounts.failed,     color: "Error" }
            ]);
        },

        // KPI strip - refreshed on each top-level refresh + tab change. Keeps
        // the four glance-tiles in sync without forcing every other view to
        // re-fetch its underlying lists.
        refreshKpis: function () {
            var view = this.getView();
            if (!view.getModel("kpis")) {
                view.setModel(new JSONModel({
                    protectionCount: 0,
                    recentContainmentCount: 0,
                    recentFailureCount: 0,
                    conflictSetCount: 0,
                    candidateCount: 0,
                    enabledSinkCount: 0
                }), "kpis");
            }
            var m = view.getModel("kpis");
            var c = this.getOwnerComponent();
            // Cheap parallel fetches - each catch is empty because a failing
            // KPI lookup shouldn't surface as an error toast; the tile just
            // stays at its last known value (or zero).
            api.listProtected(c).then(function (list) {
                m.setProperty("/protectionCount", (list || []).length);
            }).catch(function () {});
            var self = this;
            api.recentContainmentEvents(c).then(function (list) {
                var arr = list || [];
                var lockVerbs = {
                    ias_deactivate: 1, ias_activate: 1,
                    ias_strip_groups: 1, ias_restore_groups: 1,
                    xsuaa_strip_roles: 1, xsuaa_restore_roles: 1,
                    xsuaa_delete_shadow: 1,
                    cf_revoke_org_roles: 1, cf_restore_org_roles: 1,
                    // cf_revoke_tokens stays here so historical rows (the
                    // action was removed in this commit) still count toward
                    // the 14-day activity tile until they age out.
                    cf_revoke_tokens: 1
                };
                m.setProperty("/recentContainmentCount",
                    arr.filter(function (r) { return lockVerbs[r.action]; }).length);
                m.setProperty("/recentFailureCount",
                    arr.filter(function (r) { return r.outcome === "failed"; }).length);
                m.setProperty("/recentEventWindow", arr.length);
                self._computeTrends(arr, lockVerbs);
            }).catch(function () {});
            api.listConflictSets(c).then(function (list) {
                m.setProperty("/conflictSetCount",
                    (list || []).filter(function (r) { return r.enabled; }).length);
            }).catch(function () {});
            api.listCandidates(c, true).then(function (list) {
                m.setProperty("/candidateCount", (list || []).length);
            }).catch(function () {});
            api.listAuditSinks(c).then(function (list) {
                m.setProperty("/enabledSinkCount",
                    (list || []).filter(function (s) { return s.enabled; }).length);
            }).catch(function () {});
            // Ensure iasTenants is populated so its tile has something to count.
            if (!view.getModel("iasTenants")) this.onRefreshIasTenants();
        },

        onSubaccountFilterChange: function (oEvent) {
            // Client-side filter - small data set (one row per enrolled
            // subaccount); a server round-trip would be overkill.
            var q = (oEvent.getParameter("newValue") || "").toLowerCase().trim();
            var table = this.byId("subaccountTable");
            var binding = table.getBinding("items");
            if (!binding) return;
            if (!q) { binding.filter([]); return; }
            // sap.ui.model.Filter / FilterOperator - pull them in lazily.
            sap.ui.require(["sap/ui/model/Filter", "sap/ui/model/FilterOperator"], function (Filter, Op) {
                var filters = ["cisDisplayName", "label", "region", "globalAccountName", "globalAccountId", "subaccountGuid", "stage"]
                    .map(function (path) { return new Filter(path, Op.Contains, q); });
                binding.filter(new Filter({ filters: filters, and: false }));
            });
        },

        onDeleteRow: function (oEvent) {
            var row = oEvent.getSource().getBindingContext("data").getObject();
            var self = this;
            MessageBox.confirm(self._i18n("confirmUnenrollText"), {
                title: self._i18n("confirmUnenrollTitle"),
                actions: [self._i18n("confirmUnenrollOk"), MessageBox.Action.CANCEL],
                emphasizedAction: self._i18n("confirmUnenrollOk"),
                onClose: function (action) {
                    if (action !== self._i18n("confirmUnenrollOk")) return;
                    api.deleteSubaccount(self.getOwnerComponent(), row.id)
                        .then(function () { MessageToast.show(self._i18n("toastUnenrolled")); return self.loadSubaccounts(); })
                        .catch(self._showError.bind(self));
                }
            });
        },

        // =================== enroll dialog ===================

        onOpenEnroll: function () {
            var view = this.getView();
            var self = this;
            view.setModel(new JSONModel({
                mode: "pending",     // start on the pending list - fastest path for the common case
                label: "",
                globalAccountName: "",
                globalAccountId: "",
                stage: "",
                key1: "", key1Validation: "",
                candidates: [],            // pending candidates from saved-key syncs
                discoverCandidates: [],    // ad-hoc results from a pasted key
                discoveryHint: "",
                quickName: "",
                quickGuid: "",
                quickRegion: "",
                saveKey: false,
                saveIntervalMinutes: 60
            }), "enroll");
            // Pre-load pending candidates so the "From sync" tab has data the
            // moment the dialog opens.
            api.listCandidates(this.getOwnerComponent(), "pending")
                .then(function (list) {
                    var m = self.getView().getModel("enroll");
                    m.setProperty("/candidates", list || []);
                    // If there are no pending candidates default to Discover instead
                    // so the user isn't staring at an empty list.
                    if (!list || list.length === 0) m.setProperty("/mode", "discover");
                })
                .catch(function () { /* non-fatal - leave list empty */ });
            if (!this._enrollDialog) {
                Fragment.load({
                    id: view.getId(),
                    name: "btpc.view.EnrollDialog",
                    controller: this
                }).then(function (dlg) {
                    self._enrollDialog = dlg;
                    view.addDependent(dlg);
                    dlg.open();
                });
            } else {
                this._enrollDialog.open();
            }
        },

        onCancelEnroll: function () {
            if (this._enrollDialog) this._enrollDialog.close();
        },

        onEnrollModeChange: function () {
            // No reset needed between modes; the three sub-models are independent.
            // Re-fetch pending candidates when the user switches to that tab so
            // the count is fresh if a sync ran in the background.
            var m = this.getView().getModel("enroll");
            if (m.getProperty("/mode") === "pending") this.onRefreshPending();
        },

        onKey1Change: function (oEvt) { this._validateKey("/key1", oEvt.getParameter("value")); },

        _validateKey: function (slot, value) {
            var m = this.getView().getModel("enroll");
            var v = (value || "").trim();
            if (!v) { m.setProperty(slot + "Validation", ""); return; }
            try {
                var parsed = JSON.parse(v);
                m.setProperty(slot + "Validation", this._sniffKey(parsed));
            } catch (e) {
                m.setProperty(slot + "Validation",
                    this._i18n("sniffInvalid").replace("{0}", e.message));
            }
        },

        _sniffKey: function (obj) {
            if (!obj || typeof obj !== "object") return this._i18n("sniffUnknown");
            var svc = obj["sap.cloud.service"];
            if (typeof svc === "string") {
                if (svc.indexOf("service.central") !== -1) return this._i18n("sniffCisCentral");
                if (svc.indexOf("service.local")   !== -1) return this._i18n("sniffCisLocalRejected");
            }
            if (obj["btp-tenant-api"] && obj["app_tid"]) return this._i18n("sniffIas");
            // XSUAA api-access: nested-under-uaa (legacy) OR flat-at-root (modern).
            var uaa = obj.uaa || {};
            if (uaa.apiurl && uaa.clientid) return this._i18n("sniffXsuaa");
            if (obj.apiurl && obj.clientid && obj.xsappname) return this._i18n("sniffXsuaa");
            return this._i18n("sniffUnknown");
        },

        // No client-side auto-extract needed: the Discover flow pulls the
        // canonical values from CIS (via _captureCandidate), and Manual mode
        // is fully typed in by the admin.
        _autoExtractFromKey: function (m, parsed) {},

        onRefreshPending: function () {
            var self = this;
            return api.listCandidates(this.getOwnerComponent(), "pending")
                .then(function (list) {
                    self.getView().getModel("enroll").setProperty("/candidates", list || []);
                })
                .catch(self._showError.bind(self));
        },

        onPendingFilterChange: function (oEvent) {
            var q = (oEvent.getParameter("newValue") || "").toLowerCase().trim();
            var table = this.byId("enrollPendingTable");
            var binding = table && table.getBinding("items");
            if (!binding) return;
            if (!q) { binding.filter([]); return; }
            sap.ui.require(["sap/ui/model/Filter", "sap/ui/model/FilterOperator"], function (Filter, Op) {
                var filters = ["displayName", "region", "subaccountGuid", "globalAccountGuid", "subdomain"]
                    .map(function (p) { return new Filter(p, Op.Contains, q); });
                binding.filter(new Filter({ filters: filters, and: false }));
            });
        },

        _selectedRows: function (tableId, model) {
            var table = this.byId(tableId);
            if (!table) return [];
            return table.getSelectedItems().map(function (it) {
                return it.getBindingContext(model).getObject();
            });
        },

        _bulkEnroll: function (items) {
            // N sequential POSTs. Promise.allSettled so partial success surfaces
            // every failure individually rather than aborting on the first.
            var self = this;
            var c = this.getOwnerComponent();
            return Promise.all(items.map(function (body) {
                return api.enrollSubaccount(c, body)
                    .then(function (sa) { return { ok: true, guid: body.subaccountGuid, sa: sa }; })
                    .catch(function (err) { return { ok: false, guid: body.subaccountGuid, error: err.message }; });
            })).then(function (results) {
                var ok = results.filter(function (r) { return r.ok; }).length;
                var failed = results.filter(function (r) { return !r.ok; });
                if (failed.length === 0) {
                    MessageToast.show("Enrolled " + ok + " subaccount(s)");
                } else {
                    var lines = failed.slice(0, 5).map(function (r) {
                        return " - " + r.guid + ": " + r.error;
                    }).join("\n");
                    MessageBox.warning(
                        "Enrolled " + ok + " of " + results.length + ".\n" +
                        "Failed:\n" + lines +
                        (failed.length > 5 ? "\n(+" + (failed.length - 5) + " more)" : ""));
                }
                return self.loadSubaccounts();
            });
        },

        onBulkEnrollPending: function () {
            var rows = this._selectedRows("enrollPendingTable", "enroll");
            if (rows.length === 0) { MessageBox.error("Pick at least one candidate"); return; }
            var bodies = rows.map(function (r) {
                return {
                    subaccountGuid: r.subaccountGuid,
                    cisDisplayName: r.displayName,
                    region: r.region,
                    globalAccountId: r.globalAccountGuid || null,
                    discoveredId: r.id,
                    serviceKeys: []
                };
            });
            var self = this;
            this._bulkEnroll(bodies)
                .then(function () { return self.onRefreshPending(); })
                .then(function () { if (self._enrollDialog) self._enrollDialog.close(); });
        },

        // V12: bulk dismiss removed alongside the dismiss concept. Candidates
        // either get enrolled or stay in the list. Hard-delete via DELETE
        // /api/v1/discovery/candidates/{id} if a stale row really needs to go.

        onDiscoverCis: function () {
            var m = this.getView().getModel("enroll");
            var self = this;
            var c = this.getOwnerComponent();
            var key = (m.getProperty("/key1") || "").trim();
            if (!key) { MessageBox.error("Paste a CIS Central-Viewer service key first."); return; }

            // Optionally save the key for periodic sync BEFORE discovering -
            // makes the side-effect order obvious to the user (you ticked save,
            // we saved). If the save fails, discovery still runs.
            var preflight = m.getProperty("/saveKey")
                ? api.saveCentralKey(c, {
                        serviceKey: key,
                        syncIntervalMinutes: Number(m.getProperty("/saveIntervalMinutes")) || 60,
                        syncEnabled: true
                    })
                    .then(function () { MessageToast.show(self._i18n("toastSavedKeyAdded")); })
                    .catch(function (err) {
                        MessageBox.warning("Failed to save key for auto-sync: " +
                            (err && err.message ? err.message : err) +
                            " - discovery will still run.");
                    })
                : Promise.resolve();

            preflight
                .then(function () { return api.discoverFromCis(c, key); })
                .then(function (resp) {
                    var list = (resp && resp.subaccounts) ? resp.subaccounts : [];
                    m.setProperty("/discoverCandidates", list);
                    m.setProperty("/discoveryHint",
                        "Found " + list.length + " subaccount(s). Tick the ones to enroll, then click Enroll selected.");
                })
                .catch(self._showError.bind(self));
        },

        onBulkEnrollDiscover: function () {
            var rows = this._selectedRows("enrollDiscoverTable", "enroll");
            if (rows.length === 0) { MessageBox.error("Pick at least one subaccount"); return; }
            var bodies = rows.map(function (r) {
                return {
                    subaccountGuid: r.guid,
                    cisDisplayName: r.displayName,
                    region: r.region,
                    globalAccountId: r.globalAccountGuid || null,
                    serviceKeys: []
                };
            });
            var self = this;
            this._bulkEnroll(bodies)
                .then(function () { if (self._enrollDialog) self._enrollDialog.close(); });
        },

        onConfirmManualEnroll: function () {
            var d = this.getView().getModel("enroll").getData();
            var self = this;
            if (!d.quickName || !d.quickName.trim()) { MessageBox.error("Subaccount name is required"); return; }
            if (!d.quickGuid || !d.quickGuid.trim()) { MessageBox.error("Subaccount GUID is required"); return; }
            if (!d.quickRegion || !d.quickRegion.trim()) { MessageBox.error("Region is required"); return; }
            var guid = d.quickGuid.trim();
            if (!this._isUuid(guid)) {
                MessageBox.error("Subaccount GUID must be a UUID (8-4-4-4-12 hex with dashes)");
                return;
            }
            if (d.globalAccountId && d.globalAccountId.trim()
                    && !this._isUuid(d.globalAccountId.trim())) {
                MessageBox.error("Global account ID must be a UUID (or leave blank)");
                return;
            }
            if (/\s/.test(d.quickRegion.trim())) {
                MessageBox.error("Region must not contain whitespace");
                return;
            }
            var payload = {
                subaccountGuid: guid,
                cisDisplayName: d.quickName.trim(),
                region: d.quickRegion.trim()
            };
            if (d.label && d.label.trim()) payload.label = d.label.trim();
            if (d.globalAccountName && d.globalAccountName.trim()) payload.globalAccountName = d.globalAccountName.trim();
            if (d.globalAccountId && d.globalAccountId.trim()) payload.globalAccountId = d.globalAccountId.trim();
            if (d.stage && d.stage.trim()) payload.stage = d.stage.trim();
            api.quickAddSubaccount(this.getOwnerComponent(), payload)
                .then(function () {
                    self._enrollDialog.close();
                    MessageToast.show(self._i18n("toastEnrolled"));
                    return self.loadSubaccounts();
                })
                .catch(self._showError.bind(self));
        },

        // =================== edit dialog ===================

        onOpenEdit: function (oEvent) {
            var row = oEvent.getSource().getBindingContext("data").getObject();
            var view = this.getView();
            var self = this;

            // Fetch contacts AND IAS tenants in parallel so the edit dialog's
            // tenant-picker dropdown has its options the moment the dialog
            // opens (no flash of empty Select).
            Promise.all([
                api.listContacts(this.getOwnerComponent(), row.id),
                api.listIasTenants(this.getOwnerComponent()),
                api.getSubaccount(this.getOwnerComponent(), row.id)   // get fresh cfOrgId + capabilities
            ]).then(function (results) {
                var contacts = results[0];
                var tenants = results[1] || [];
                var fresh = results[2];
                view.setModel(new JSONModel({
                    id: row.id,
                    subaccountGuid: row.subaccountGuid,
                    cisDisplayName: row.cisDisplayName,
                    label: row.label || "",
                    globalAccountName: row.globalAccountName || "",
                    globalAccountId: row.globalAccountId || "",
                    stage: row.stage || "",
                    region: row.region,
                    capabilities: fresh.capabilities || row.capabilities,
                    cfOrgId: fresh.cfOrgId || "",
                    contacts: contacts || [],
                    newKey: "", newKeyValidation: "", newKeyValid: false,
                    newKeyShowKindSelector: false, newKeyOverrideKind: "xsuaa_apiaccess",
                    newContact: { name: "", email: "", role: "security", notes: "" }
                }), "edit");
                if (!view.getModel("iasTenants")) {
                    view.setModel(new JSONModel({ list: tenants }), "iasTenants");
                } else {
                    view.getModel("iasTenants").setProperty("/list", tenants);
                }
                if (!self._editDialog) {
                    Fragment.load({
                        id: view.getId(),
                        name: "btpc.view.EditDialog",
                        controller: self
                    }).then(function (dlg) {
                        self._editDialog = dlg;
                        view.addDependent(dlg);
                        dlg.open();
                    });
                } else {
                    self._editDialog.open();
                }
            }).catch(self._showError.bind(self));
        },

        onSaveCfOrgId: function () {
            var view = this.getView();
            var m = view.getModel("edit");
            var id = m.getProperty("/id");
            var raw = (m.getProperty("/cfOrgId") || "").trim();
            // Empty input clears the pin. A non-empty value must be a UUID;
            // server enforces too but a client-side check spares the round-trip.
            var uuidRe = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
            if (raw.length > 0 && !uuidRe.test(raw)) {
                MessageBox.error("cf_org_id must be a UUID (or empty to clear)");
                return;
            }
            var self = this;
            api.setCfOrgId(this.getOwnerComponent(), id, raw || null)
                .then(function (sa) {
                    m.setProperty("/cfOrgId", sa.cfOrgId || "");
                    MessageToast.show(self._i18n("toastCfOrgIdSaved"));
                })
                .catch(self._showError.bind(self));
        },

        onCloseEdit: function () {
            if (this._editDialog) this._editDialog.close();
            this.loadSubaccounts();
        },

        onSaveLabel: function () {
            var m = this.getView().getModel("edit");
            var id = m.getProperty("/id");
            var label = m.getProperty("/label") || "";
            var self = this;
            api.updateLabel(this.getOwnerComponent(), id, label)
                .then(function () { MessageToast.show(self._i18n("toastLabelSaved")); })
                .catch(self._showError.bind(self));
        },

        onSaveMetadata: function () {
            var m = this.getView().getModel("edit");
            var id = m.getProperty("/id");
            var gaId = (m.getProperty("/globalAccountId") || "").trim();
            var payload = {
                label: m.getProperty("/label") || null,
                globalAccountId: gaId || null,
                globalAccountName: m.getProperty("/globalAccountName") || null,
                stage: m.getProperty("/stage") || null
            };
            // Loose client-side UUID check so we don't ship "not-a-uuid" to
            // the server and get a 400 with a less friendly message.
            if (gaId && !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(gaId)) {
                MessageBox.error("Global Account ID must be a UUID (or empty).");
                return;
            }
            var self = this;
            api.updateMetadata(this.getOwnerComponent(), id, payload)
                .then(function () { MessageToast.show("Metadata saved"); return self.loadSubaccounts(); })
                .catch(self._showError.bind(self));
        },

        onEditNewKeyChange: function (oEvt) {
            var m = this.getView().getModel("edit");
            var v = (oEvt.getParameter("value") || "").trim();
            if (!v) {
                m.setProperty("/newKeyValidation", "");
                m.setProperty("/newKeyValid", false);
                return;
            }
            try {
                var parsed = JSON.parse(v);
                // IAS no longer accepts a pasted service key - the admin
                // uses the dedicated "Add IAS credential" dialog with three
                // structured fields. Block the paste flow when an IAS-shaped
                // blob lands here so we don't silently round-trip via the
                // generic /credentials endpoint.
                if (parsed && parsed["btp-tenant-api"] && parsed["app_tid"]) {
                    m.setProperty("/newKeyValidation", this._i18n("sniffIasUseDialog"));
                    m.setProperty("/newKeyValid", false);
                    return;
                }
                m.setProperty("/newKeyValidation", this._sniffKey(parsed));
                m.setProperty("/newKeyValid", true);
            } catch (e) {
                m.setProperty("/newKeyValidation", this._i18n("sniffInvalid").replace("{0}", e.message));
                m.setProperty("/newKeyValid", false);
            }
        },

        onAttachKey: function () {
            var m = this.getView().getModel("edit");
            var id = m.getProperty("/id");
            var key = (m.getProperty("/newKey") || "").trim();
            var self = this;
            api.attachCredential(this.getOwnerComponent(), id, key)
                .then(function (sa) {
                    m.setProperty("/capabilities", sa.capabilities);
                    m.setProperty("/newKey", "");
                    m.setProperty("/newKeyValidation", "");
                    m.setProperty("/newKeyValid", false);
                    MessageToast.show(self._i18n("toastKeyAttached"));
                })
                .catch(self._showError.bind(self));
        },

        // Server-side auto-provision flow: scan for + create (if missing)
        // the xsuaa apiaccess instance via the CF technical user, create
        // a service key with the deterministic name, fetch credentials,
        // and store as the XSUAA api-access credential for this subaccount.
        // Long-running (CF jobs can take ~30s), so the button shows busy
        // while the request is in flight; the BusyDialog gives the operator
        // a visible elapsed counter on top.
        onAutoProvisionXsuaa: function () {
            var view = this.getView();
            var m = view.getModel("edit");
            var id = m.getProperty("/id");
            var self = this;
            // Same confirmation pattern as live containment - this overwrites
            // any existing XSUAA api-access credential.
            var confirmRun = function () {
                m.setProperty("/autoProvisionBusy", true);
                // CF jobs in trial can take 30-60s for apiaccess provisioning;
                // include the binding fetch too. 90s is a reasonable estimate.
                var prog = self._openProgressDialog(
                        self._i18n("autoProvisionXsuaaBtn"), 90);
                api.provisionXsuaaApiAccess(self.getOwnerComponent(), id)
                    .then(function (sa) {
                        prog.done();
                        m.setProperty("/capabilities", sa.capabilities);
                        MessageToast.show(self._i18n("autoProvisionXsuaaDone"));
                    })
                    .catch(function (err) { prog.done(); self._showError(err); })
                    .finally(function () { m.setProperty("/autoProvisionBusy", false); });
            };
            MessageBox.confirm(self._i18n("autoProvisionXsuaaConfirm"), {
                title: self._i18n("autoProvisionXsuaaBtn"),
                actions: [MessageBox.Action.OK, MessageBox.Action.CANCEL],
                emphasizedAction: MessageBox.Action.OK,
                onClose: function (act) { if (act === MessageBox.Action.OK) confirmRun(); }
            });
        },

        // =================== IAS tenants (Stage B) ===================

        onRefreshIasTenants: function () {
            var view = this.getView();
            return api.listIasTenants(this.getOwnerComponent()).then(function (list) {
                var m = view.getModel("iasTenants");
                if (!m) {
                    view.setModel(new JSONModel({ list: list || [] }), "iasTenants");
                } else {
                    m.setProperty("/list", list || []);
                }
            }).catch(this._showError.bind(this));
        },

        onOpenAddIasTenant: function () {
            this._openIasTenantDialog({
                editMode: false,
                dialogTitle: this._i18n("dlgIasTenantTitleCreate"),
                id: null,
                displayName: "",
                url: "",
                p12Base64: "",
                p12Password: "",
                p12Status: ""
            });
        },

        onOpenEditIasTenant: function (oEvt) {
            var ctx = oEvt.getSource().getBindingContext("iasTenants");
            var row = ctx.getObject();
            this._openIasTenantDialog({
                editMode: true,
                dialogTitle: this._i18n("dlgIasTenantTitleEdit"),
                id: row.id,
                displayName: row.displayName,
                url: "https://" + row.iasHost,    // URL is locked in edit mode
                p12Base64: "",
                p12Password: "",
                p12Status: ""
            });
        },

        // Mirrors onCfTechP12Selected - FileUploader hands us the File, we
        // base64-encode it client-side so the JSON POST carries the cert.
        onIasP12Selected: function (oEvent) {
            var files = oEvent.getParameter("files");
            var m = this.getView().getModel("ias");
            if (!files || files.length === 0) {
                m.setProperty("/p12Status", "");
                m.setProperty("/p12Base64", "");
                return;
            }
            var file = files[0];
            var self = this;
            var reader = new FileReader();
            reader.onload = function (e) {
                // data URL prefix -> base64 only.
                var dataUrl = e.target.result;
                var comma = dataUrl.indexOf(",");
                var b64 = comma >= 0 ? dataUrl.substring(comma + 1) : dataUrl;
                m.setProperty("/p12Base64", b64);
                m.setProperty("/p12Status",
                    self._i18n("cfTechP12LoadedFmt").replace("{0}", file.name)
                        .replace("{1}", String(file.size)));
            };
            reader.onerror = function () {
                MessageBox.error("Failed to read the P12 file");
            };
            reader.readAsDataURL(file);
        },

        _openIasTenantDialog: function (initial) {
            var view = this.getView();
            var self = this;
            view.setModel(new JSONModel(initial), "ias");
            if (!this._iasDialog) {
                Fragment.load({
                    id: view.getId(),
                    name: "btpc.view.AddIasDialog",
                    controller: this
                }).then(function (dlg) {
                    self._iasDialog = dlg;
                    view.addDependent(dlg);
                    dlg.open();
                });
            } else {
                this._iasDialog.open();
            }
        },

        onCancelAddIas: function () {
            if (this._iasDialog) this._iasDialog.close();
        },

        onConfirmAddIas: function () {
            var d = this.getView().getModel("ias").getData();
            var self = this;
            if (!d.displayName || !d.displayName.trim()) { MessageBox.error("displayName is required"); return; }
            // In edit mode, p12 is optional (only re-uploaded if a fresh file
            // was selected). The empty-password case is fine - SAP-issued P12s
            // are sometimes unprotected, so we don't require p12Password.
            if (!d.editMode) {
                if (!d.url || !d.url.trim()) { MessageBox.error("url is required"); return; }
                var urlCheck = this._validateUrl(d.url, { requireHttps: true });
                if (!urlCheck.ok) { MessageBox.error(urlCheck.error); return; }
                d.url = urlCheck.cleaned;   // trimmed value goes into the payload
                if (!d.p12Base64) { MessageBox.error("Pick a .p12 file"); return; }
            }

            var promise;
            if (d.editMode) {
                // Two updates: meta always, creds only when operator picked
                // a fresh P12 (otherwise existing creds are kept).
                promise = api.updateIasTenantMeta(this.getOwnerComponent(), d.id,
                        { displayName: d.displayName.trim() });
                if (d.p12Base64) {
                    promise = promise.then(function () {
                        return api.updateIasTenantCreds(self.getOwnerComponent(), d.id, {
                            displayName: d.displayName.trim(),
                            url: d.url.trim(),
                            p12Base64: d.p12Base64,
                            p12Password: d.p12Password || ""
                        });
                    });
                }
            } else {
                promise = api.createIasTenant(this.getOwnerComponent(), {
                    displayName: d.displayName.trim(),
                    url: d.url.trim(),
                    p12Base64: d.p12Base64,
                    p12Password: d.p12Password || ""
                });
            }
            promise.then(function () {
                self._iasDialog.close();
                MessageToast.show(self._i18n(d.editMode ? "toastIasTenantUpdated" : "toastIasTenantCreated"));
                return self.onRefreshIasTenants();
            }).catch(self._showError.bind(self));
        },

        onDeleteIasTenant: function (oEvt) {
            var ctx = oEvt.getSource().getBindingContext("iasTenants");
            var row = ctx.getObject();
            var self = this;
            var msg = this._i18n("confirmDeleteIasTenant").replace("{0}", row.displayName);
            MessageBox.confirm(msg, {
                onClose: function (act) {
                    if (act !== MessageBox.Action.OK) return;
                    api.deleteIasTenant(self.getOwnerComponent(), row.id)
                        .then(function () {
                            MessageToast.show(self._i18n("toastIasTenantDeleted"));
                            return self.onRefreshIasTenants();
                        })
                        .catch(self._showError.bind(self));
                }
            });
        },

        // =================== add CF technical user ===================

        onOpenAddCfTechUser: function () {
            var view = this.getView();
            var self = this;
            var currentSubId = (view.getModel("edit") && view.getModel("edit").getProperty("/id")) || null;
            // Build the "reuse from existing" list: every other subaccount whose
            // capabilities.cfTechnicalUser is true. Excludes the current
            // subaccount (which is the target of the dialog).
            var allSubaccounts = (view.getModel("data") && view.getModel("data").getProperty("/subaccounts")) || [];
            var reuseSources = allSubaccounts.filter(function (s) {
                return s.id !== currentSubId
                    && s.capabilities && s.capabilities.cfTechnicalUser;
            });
            view.setModel(new JSONModel({
                mode: "new",                // 'new' | 'reuse'
                reuseSources: reuseSources,
                reuseFromSubaccountId: "",
                cfApiUrl: "",
                cfUaaUrl: "",
                username: "",
                origin: "",
                iasPasscodeUrl: "",
                p12Base64: "",
                p12Password: "",
                p12Status: ""
            }), "cfTech");
            if (!this._cfTechDialog) {
                Fragment.load({
                    id: view.getId(),
                    name: "btpc.view.AddCfTechUserDialog",
                    controller: this
                }).then(function (dlg) {
                    self._cfTechDialog = dlg;
                    view.addDependent(dlg);
                    dlg.open();
                });
            } else {
                this._cfTechDialog.open();
            }
        },

        onCancelAddCfTechUser: function () {
            if (this._cfTechDialog) this._cfTechDialog.close();
        },

        onCfTechP12Selected: function (oEvent) {
            // FileUploader gives us either a "files" param (modern browsers)
            // or "newValue" (the filename only). Read the file into a base64
            // string client-side so we can ship it in the JSON payload.
            var files = oEvent.getParameter("files");
            var m = this.getView().getModel("cfTech");
            if (!files || files.length === 0) {
                m.setProperty("/p12Status", "");
                m.setProperty("/p12Base64", "");
                return;
            }
            var file = files[0];
            var self = this;
            var reader = new FileReader();
            reader.onload = function (e) {
                // e.target.result is "data:application/x-pkcs12;base64,XXXX"
                // - strip the data-URL prefix so we just keep the base64.
                var dataUrl = e.target.result;
                var comma = dataUrl.indexOf(",");
                var b64 = comma >= 0 ? dataUrl.substring(comma + 1) : dataUrl;
                m.setProperty("/p12Base64", b64);
                m.setProperty("/p12Status",
                    self._i18n("cfTechP12LoadedFmt").replace("{0}", file.name)
                        .replace("{1}", String(file.size)));
            };
            reader.onerror = function () {
                MessageBox.error("Failed to read the P12 file");
            };
            reader.readAsDataURL(file);
        },

        onConfirmAddCfTechUser: function () {
            var d = this.getView().getModel("cfTech").getData();
            var m = this.getView().getModel("edit");
            var id = m.getProperty("/id");
            // Client-side validation (server enforces too).
            if (!d.cfApiUrl || !d.cfApiUrl.trim()) { MessageBox.error("cfApiUrl is required"); return; }
            if (!d.cfUaaUrl || !d.cfUaaUrl.trim()) { MessageBox.error("cfUaaUrl is required"); return; }
            var apiCheck = this._validateUrl(d.cfApiUrl, { requireHttps: true });
            if (!apiCheck.ok) { MessageBox.error("cfApiUrl: " + apiCheck.error); return; }
            var uaaCheck = this._validateUrl(d.cfUaaUrl, { requireHttps: true });
            if (!uaaCheck.ok) { MessageBox.error("cfUaaUrl: " + uaaCheck.error); return; }
            d.cfApiUrl = apiCheck.cleaned;
            d.cfUaaUrl = uaaCheck.cleaned;
            var self = this;
            var p;
            if (d.mode === "reuse") {
                if (!d.reuseFromSubaccountId) {
                    MessageBox.error("Pick a subaccount to reuse the CF technical user from");
                    return;
                }
                p = api.copyCfTechnicalUser(this.getOwnerComponent(), id, d.reuseFromSubaccountId, {
                    cfApiUrl: d.cfApiUrl,
                    cfUaaUrl: d.cfUaaUrl
                });
            } else {
                if (!d.username || !d.username.trim()) { MessageBox.error("username is required"); return; }
                if (!d.origin || !d.origin.trim()) { MessageBox.error("origin is required"); return; }
                if (/\s/.test(d.origin.trim())) {
                    MessageBox.error("origin must not contain whitespace");
                    return;
                }
                if (!d.iasPasscodeUrl || !d.iasPasscodeUrl.trim()) {
                    MessageBox.error("iasPasscodeUrl is required"); return;
                }
                var pcCheck = this._validateUrl(d.iasPasscodeUrl, { requireHttps: true });
                if (!pcCheck.ok) { MessageBox.error("iasPasscodeUrl: " + pcCheck.error); return; }
                if (!d.p12Base64) { MessageBox.error("Pick a .p12 file"); return; }
                if (!d.p12Password) { MessageBox.error("P12 password is required"); return; }
                p = api.attachCfTechnicalUser(this.getOwnerComponent(), id, {
                    cfApiUrl: d.cfApiUrl,
                    cfUaaUrl: d.cfUaaUrl,
                    username: d.username.trim(),
                    origin: d.origin.trim(),
                    iasPasscodeUrl: pcCheck.cleaned,
                    p12Base64: d.p12Base64,
                    p12Password: d.p12Password
                });
            }
            p.then(function (sa) {
                m.setProperty("/capabilities", sa.capabilities);
                self._cfTechDialog.close();
                MessageToast.show(self._i18n("toastCfTechUserAttached"));
            }).catch(self._showError.bind(self));
        },

        onAddContact: function () {
            var m = this.getView().getModel("edit");
            var id = m.getProperty("/id");
            var nc = m.getProperty("/newContact");
            if (!nc.name || !nc.name.trim()) { MessageBox.error("Name is required"); return; }
            var contactEmailCheck = this._validateEmail(nc.email);
            if (!contactEmailCheck.ok) { MessageBox.error("Email: " + contactEmailCheck.error); return; }
            var self = this;
            api.addContact(this.getOwnerComponent(), id, {
                name: nc.name.trim(), email: contactEmailCheck.cleaned,
                role: nc.role, notes: (nc.notes || "").trim() || null
            }).then(function (created) {
                var contacts = m.getProperty("/contacts") || [];
                contacts.push(created);
                m.setProperty("/contacts", contacts);
                m.setProperty("/newContact", { name: "", email: "", role: "security", notes: "" });
                MessageToast.show(self._i18n("toastContactAdded"));
            }).catch(self._showError.bind(self));
        },

        onDeleteContact: function (oEvent) {
            var ctx = oEvent.getSource().getBindingContext("edit");
            var contact = ctx.getObject();
            var m = this.getView().getModel("edit");
            var subId = m.getProperty("/id");
            var self = this;
            api.deleteContact(this.getOwnerComponent(), subId, contact.id)
                .then(function () {
                    var contacts = (m.getProperty("/contacts") || []).filter(function (c) { return c.id !== contact.id; });
                    m.setProperty("/contacts", contacts);
                    MessageToast.show(self._i18n("toastContactDeleted"));
                })
                .catch(self._showError.bind(self));
        },

        // =================== protected users ===================

        loadProtected: function () {
            var c = this.getOwnerComponent();
            return api.listProtected(c)
                .then(function (list) {
                    c.getModel("data").setProperty("/protected", list || []);
                })
                .catch(this._showError.bind(this));
        },

        onRefreshProtected: function () { this.loadProtected(); },

        // Used by the Protected Users table Scope column.
        // Resolves to one of:
        //   "Global"
        //   "Subaccount: <name> (<region>)"
        //   "IAS tenant: <name> (<host>)"
        //   "<unknown>" if the referenced row isn't loaded
        fmtScope: function (subId, iasTenantId) {
            if (!subId && !iasTenantId) return this._i18n("scopeGlobal");
            if (subId) {
                var subs = this.getView().getModel("data")
                    && (this.getView().getModel("data").getProperty("/subaccounts") || []);
                for (var i = 0; subs && i < subs.length; i++) {
                    if (subs[i].id === subId) {
                        return this._i18n("scopeSubaccountPrefix") + " "
                            + subs[i].cisDisplayName + " (" + subs[i].region + ")";
                    }
                }
            } else if (iasTenantId) {
                var ten = this.getView().getModel("iasTenants")
                    && (this.getView().getModel("iasTenants").getProperty("/list") || []);
                for (var j = 0; ten && j < ten.length; j++) {
                    if (ten[j].id === iasTenantId) {
                        return this._i18n("scopeIasTenantPrefix") + " "
                            + ten[j].displayName + " (" + ten[j].iasHost + ")";
                    }
                }
            }
            return this._i18n("scopeUnknown");
        },

        onOpenAddProtection: function () {
            var view = this.getView();
            view.setModel(new JSONModel({
                // scopeIndex: 0=global, 1=subaccount, 2=ias tenant
                scopeIndex: 0,
                subaccountId: null,
                iasTenantId: null,
                userEmail: "", reason: "", expiresAt: ""
            }), "protect");
            // Make sure the IAS tenant picker has data - same load the
            // edit-subaccount dialog uses.
            if (!view.getModel("iasTenants")) {
                this.onRefreshIasTenants();
            }
            var self = this;
            if (!this._protectDialog) {
                Fragment.load({
                    id: view.getId(),
                    name: "btpc.view.ProtectAddDialog",
                    controller: this
                }).then(function (dlg) {
                    self._protectDialog = dlg;
                    view.addDependent(dlg);
                    dlg.open();
                });
            } else {
                this._protectDialog.open();
            }
        },

        onCancelAddProtection: function () {
            if (this._protectDialog) this._protectDialog.close();
        },

        // RadioButtonGroup select fires AFTER the new scopeIndex is committed
        // to the model. Pre-fill the matching id (subaccount / IAS tenant)
        // with the first available item so the Select renders that item AND
        // the bound key is real - otherwise the Select shows the first item
        // visually but {protect>/subaccountId} stays null and the confirm
        // step rejects the form. forceSelection="false" on the Select keeps
        // the choice explicit when there are no items at all.
        onProtectScopeChange: function () {
            var view = this.getView();
            var m = view.getModel("protect");
            var idx = m.getProperty("/scopeIndex");
            if (idx === 1 && !m.getProperty("/subaccountId")) {
                var subs = (view.getModel("data")
                        && view.getModel("data").getProperty("/subaccounts")) || [];
                if (subs.length > 0) m.setProperty("/subaccountId", subs[0].id);
            } else if (idx === 2 && !m.getProperty("/iasTenantId")) {
                var tenants = (view.getModel("iasTenants")
                        && view.getModel("iasTenants").getProperty("/list")) || [];
                if (tenants.length > 0) m.setProperty("/iasTenantId", tenants[0].id);
            }
        },

        onConfirmAddProtection: function () {
            var d = this.getView().getModel("protect").getData();
            var emailCheck = this._validateEmail(d.userEmail);
            if (!emailCheck.ok) { MessageBox.error("User email: " + emailCheck.error); return; }
            if (!d.reason || !d.reason.trim()) { MessageBox.error("Reason is required"); return; }
            var payload = {
                userEmail: emailCheck.cleaned,
                reason: d.reason.trim()
            };
            if (d.scopeIndex === 1) {
                if (!d.subaccountId) { MessageBox.error("Pick a subaccount, or switch scope"); return; }
                payload.subaccountId = d.subaccountId;
            } else if (d.scopeIndex === 2) {
                if (!d.iasTenantId) { MessageBox.error("Pick an IAS tenant, or switch scope"); return; }
                payload.iasTenantId = d.iasTenantId;
            }
            if (d.expiresAt && d.expiresAt.trim()) payload.expiresAt = d.expiresAt.trim();
            var self = this;
            api.addProtection(this.getOwnerComponent(), payload)
                .then(function () {
                    self._protectDialog.close();
                    MessageToast.show(self._i18n("toastProtectionAdded"));
                    return self.loadProtected();
                })
                .catch(self._showError.bind(self));
        },

        // =================== containment ===================

        // Action presets - quick way to flip the toggles without ticking each
        // box. "All" enables every per-tenant + per-subaccount action; "Kick"
        // is the session-killing pair (IAS deactivate + strip groups, which
        // cuts off new logins and drops every IAS group membership in one
        // shot); "IAS only" sets the two IAS checks ON and the XSUAA/CF ones
        // OFF (the preset's name said "IAS only" but the old behaviour was
        // "clear everything", which produced a no-op run).
        onContainPresetAll: function () {
            var m = this.getView().getModel("contain");
            m.setProperty("/actIasDeactivate", true);
            m.setProperty("/actIasStripGroups", true);
            m.setProperty("/actStripRoles", true);
            m.setProperty("/actDeleteShadow", true);
            m.setProperty("/actCfRevokeOrg", true);
        },
        onContainPresetKick: function () {
            // Session kill without role/shadow mutations: deactivate IAS (cuts
            // off new logins) + strip IAS group memberships (drops everything
            // the user is a direct member of in the tenant). XSUAA roles and
            // CF org roles stay so the unlock path doesn't have to replay them
            // when the operator only wanted to interrupt the session.
            var m = this.getView().getModel("contain");
            m.setProperty("/actIasDeactivate", true);
            m.setProperty("/actIasStripGroups", true);
            m.setProperty("/actStripRoles", false);
            m.setProperty("/actDeleteShadow", false);
            m.setProperty("/actCfRevokeOrg", false);
        },
        onContainPresetClear: function () {
            // "IAS only": tick both IAS checks, clear the XSUAA + CF checks.
            // Pairs with leaving the subaccount picker empty for a pure
            // IAS-tenant-scoped lock.
            var m = this.getView().getModel("contain");
            m.setProperty("/actIasDeactivate", true);
            m.setProperty("/actIasStripGroups", true);
            m.setProperty("/actStripRoles", false);
            m.setProperty("/actDeleteShadow", false);
            m.setProperty("/actCfRevokeOrg", false);
        },

        // Two-button entry points. "Test" forces dry-run, "Run" forces live
        // and shows the confirm box. The shared body lives in
        // _runContainmentCommon and reads the explicit dryRun argument
        // instead of the (removed) checkbox state.
        onTestContainment: function () { this._runContainmentCommon(true); },
        onRunContainment:  function () { this._runContainmentCommon(false); },

        _runContainmentCommon: function (dryRun) {
            var m = this.getView().getModel("contain");
            var d = m.getData();
            var emailCheck = this._validateEmail(d.userEmail);
            if (!emailCheck.ok) { MessageBox.error("Target email: " + emailCheck.error); return; }
            d.userEmail = emailCheck.cleaned;
            // Empty pickers -> server-side default "all enrolled" / "every
            // linked tenant". The actions list carries every step (IAS + XSUAA + CF).
            var subaccountIds = Array.isArray(d.subaccountIds) ? d.subaccountIds : [];
            var tenantIds = Array.isArray(d.iasTenantIds) ? d.iasTenantIds : [];
            // Order matches the server-side priority in ContainmentService:
            // strip roles, then revoke CF org roles, then delete the shadow
            // user. Server enforces this too, but sending in-order keeps the
            // audit timeline readable.
            var actions = [];
            if (d.actIasDeactivate)  actions.push("ias_deactivate");
            if (d.actIasStripGroups) actions.push("ias_strip_groups");
            if (d.actStripRoles)     actions.push("xsuaa_strip_roles");
            if (d.actCfRevokeOrg)    actions.push("cf_revoke_org_roles");
            if (d.actDeleteShadow)   actions.push("xsuaa_delete_shadow");
            if (actions.length === 0) {
                MessageBox.error("Pick at least one action to perform");
                return;
            }

            // Origin payload - only set when not "all". "list" splits the CSV
            // textarea; "discovered" uses the operator's MultiComboBox picks.
            var originMode = d.originMode || "all";
            var origins = null;
            if (originMode === "list") {
                origins = (d.originsList || "")
                    .split(/[\s,]+/)
                    .map(function (s) { return s.trim(); })
                    .filter(Boolean);
                if (origins.length === 0) {
                    MessageBox.error("Origin mode 'list' needs at least one origin key");
                    return;
                }
            } else if (originMode === "discovered") {
                origins = Array.isArray(d.selectedOrigins) ? d.selectedOrigins.slice() : [];
                if (origins.length === 0) {
                    MessageBox.error("Pick at least one discovered origin (or switch to 'all')");
                    return;
                }
            } else if (originMode === "profile") {
                if (!d.originProfileId) {
                    MessageBox.error("Pick an origin profile (or switch to 'all')"); return;
                }
                var profiles = (this.getView().getModel("profiles")
                    && this.getView().getModel("profiles").getProperty("/list")) || [];
                var prof = profiles.find(function (p) { return p.id === d.originProfileId; });
                if (!prof || !Array.isArray(prof.originKeys) || prof.originKeys.length === 0) {
                    MessageBox.error("Selected profile has no origin keys"); return;
                }
                // Server doesn't know about profile IDs (yet) - resolve to a
                // 'list' on the wire so the audit row records the resolved keys.
                originMode = "list";
                origins = prof.originKeys.slice();
            }

            var run = function (self) {
                var payload = {
                    userEmail: d.userEmail.trim(),
                    actions: actions,
                    dryRun: dryRun,
                    originMode: originMode
                };
                if (subaccountIds.length > 0) payload.subaccountIds = subaccountIds;
                if (tenantIds.length > 0) payload.iasTenantIds = tenantIds;
                if (origins) payload.origins = origins;
                if (d.comment && d.comment.trim()) payload.comment = d.comment.trim();
                // ETA: tenant count  per-tenant + action count  subaccount count  per-action.
                // Resolve "all" pickers to actual counts known to the UI.
                var saAll = (self.getView().getModel("data")
                    && (self.getView().getModel("data").getProperty("/subaccounts") || []).length) || 1;
                var tenAll = (self.getView().getModel("iasTenants")
                    && (self.getView().getModel("iasTenants").getProperty("/list") || []).length) || 0;
                var effSa = subaccountIds.length > 0 ? subaccountIds.length : saAll;
                var effTen = tenantIds.length > 0 ? tenantIds.length : tenAll;
                var eta = effTen * self._PROGRESS_PER_TENANT_S
                        + effSa * actions.length * self._PROGRESS_PER_ACTION_S;
                var prog = self._openProgressDialog(
                        (payload.dryRun ? "Containment (dry-run)" : "Containment"), eta);
                api.runContainment(self.getOwnerComponent(), payload)
                    .then(function (resp) {
                        prog.done();
                        self._enrichIasResults(resp);
                        m.setProperty("/lastResult", resp);
                        var globalReasons = resp.globalProtectionReasons || [];
                        var blockedAny = (resp.perSubaccount || []).some(function (s) {
                            return s.blockedByProtection;
                        });
                        if (globalReasons.length > 0) {
                            MessageBox.warning(
                                "Request BLOCKED - the target is globally protected: "
                                    + globalReasons.join("; "),
                                { title: "Globally protected" });
                        } else if (blockedAny) {
                            MessageBox.warning(
                                "Some subaccounts BLOCKED - the target is in Protected Users.",
                                { title: "Protected" });
                        } else if (resp.dryRun) {
                            MessageToast.show("Dry-run complete - nothing was mutated.");
                        } else {
                            MessageToast.show("Containment completed.");
                        }
                        return self.onRefreshContainmentEvents();
                    })
                    .catch(function (err) { prog.done(); self._showError(err); });
            };

            // Confirm only on the live path - Test (dry-run) goes straight
            // through. Single kill switch since the server-wide
            // allowMutations toggle is gone.
            if (!dryRun) {
                var self = this;
                MessageBox.warning(
                    "You are about to perform LIVE mutations against IAS / XSUAA / CF for " +
                    d.userEmail + ". Undo only via the Unlock flow. Continue?", {
                        title: "Confirm live containment",
                        actions: [MessageBox.Action.OK, MessageBox.Action.CANCEL],
                        emphasizedAction: MessageBox.Action.OK,
                        onClose: function (a) {
                            if (a === MessageBox.Action.OK) run(self);
                        }
                    });
            } else {
                run(this);
            }
        },

        // Read-only "what would be re-granted" preview for the operator.
        // Calls /containment/unlock-preview and stores the result for the
        // table binding inside the Unlock panel.
        onPreviewUnlock: function () {
            var m = this.getView().getModel("contain");
            var d = m.getData();
            var emailCheck = this._validateEmail(d.unlockEmail);
            if (!emailCheck.ok) { MessageBox.error("Target email: " + emailCheck.error); return; }
            var subaccountIds = Array.isArray(d.unlockSubaccountIds) ? d.unlockSubaccountIds : [];
            var self = this;
            m.setProperty("/unlockPreviewBusy", true);
            api.previewUnlock(this.getOwnerComponent(), emailCheck.cleaned, subaccountIds)
                .then(function (rows) {
                    // Flatten one row per (subaccount, origin) for the table.
                    var flat = [];
                    (rows || []).forEach(function (r) {
                        if (!r.perOrigin || r.perOrigin.length === 0) {
                            flat.push({
                                subaccountId: r.subaccountId,
                                displayName: r.displayName,
                                snapshotId: r.snapshotId,
                                origin: "-",
                                roleCollections: [],
                                roleCollectionsText: "",
                                note: r.note || "(no roles to restore)"
                            });
                            return;
                        }
                        r.perOrigin.forEach(function (po) {
                            flat.push({
                                subaccountId: r.subaccountId,
                                displayName: r.displayName,
                                snapshotId: r.snapshotId,
                                origin: po.origin,
                                roleCollections: po.roleCollections || [],
                                roleCollectionsText: (po.roleCollections || []).join(", "),
                                note: r.note || ""
                            });
                        });
                    });
                    m.setProperty("/unlockPreview", flat);
                })
                .catch(self._showError.bind(self))
                .finally(function () { m.setProperty("/unlockPreviewBusy", false); });
        },

        onTestUnlock: function () { this._runUnlockCommon(true); },
        onRunUnlock:  function () { this._runUnlockCommon(false); },

        _runUnlockCommon: function (dryRun) {
            var m = this.getView().getModel("contain");
            var d = m.getData();
            var emailCheck = this._validateEmail(d.unlockEmail);
            if (!emailCheck.ok) { MessageBox.error("Target email: " + emailCheck.error); return; }
            d.unlockEmail = emailCheck.cleaned;
            var subaccountIds = Array.isArray(d.unlockSubaccountIds) ? d.unlockSubaccountIds : [];
            var tenantIds = Array.isArray(d.unlockIasTenantIds) ? d.unlockIasTenantIds : [];
            var unlockActions = [];
            if (d.unlockActIasActivate)      unlockActions.push("ias_activate");
            if (d.unlockActIasRestoreGroups) unlockActions.push("ias_restore_groups");
            if (d.unlockActXsuaaRestore)     unlockActions.push("xsuaa_restore_roles");
            if (d.unlockActCfRestore)        unlockActions.push("cf_restore_org_roles");
            if (unlockActions.length === 0) {
                MessageBox.error("Pick at least one restore action");
                return;
            }
            var payload = {
                userEmail: d.unlockEmail.trim(),
                actions: unlockActions,
                dryRun: dryRun
            };
            if (subaccountIds.length > 0) payload.subaccountIds = subaccountIds;
            if (tenantIds.length > 0) payload.iasTenantIds = tenantIds;
            if (d.unlockComment && d.unlockComment.trim()) payload.comment = d.unlockComment.trim();
            var self = this;
            var go = function () {
                var saAll = (self.getView().getModel("data")
                    && (self.getView().getModel("data").getProperty("/subaccounts") || []).length) || 1;
                var tenAll = (self.getView().getModel("iasTenants")
                    && (self.getView().getModel("iasTenants").getProperty("/list") || []).length) || 0;
                var effSa = subaccountIds.length > 0 ? subaccountIds.length : saAll;
                var effTen = tenantIds.length > 0 ? tenantIds.length : tenAll;
                // Unlock replays IAS + role-collection restore (2 actions/SA) + CF restore.
                var eta = effTen * self._PROGRESS_PER_TENANT_S
                        + effSa * 2 * self._PROGRESS_PER_ACTION_S;
                var prog = self._openProgressDialog(
                        (payload.dryRun ? "Unlock (dry-run)" : "Unlock"), eta);
                api.runUnlock(self.getOwnerComponent(), payload)
                    .then(function (resp) {
                        prog.done();
                        self._enrichIasResults(resp);
                        m.setProperty("/lastUnlock", resp);
                        if (resp.dryRun) MessageToast.show("Unlock dry-run complete.");
                        else MessageToast.show("Unlock completed.");
                        return self.onRefreshContainmentEvents();
                    })
                    .catch(function (err) { prog.done(); self._showError(err); });
            };
            if (!dryRun) {
                MessageBox.warning(
                    "About to RESTORE access for " + d.unlockEmail + " (re-activate IAS user + reassign role collections). Continue?",
                    {
                        title: "Confirm live unlock",
                        actions: [MessageBox.Action.OK, MessageBox.Action.CANCEL],
                        emphasizedAction: MessageBox.Action.OK,
                        onClose: function (a) { if (a === MessageBox.Action.OK) go(); }
                    });
            } else {
                go();
            }
        },

        onDiscoverOrigins: function () {
            var m = this.getView().getModel("contain");
            var d = m.getData();
            var subaccountIds = Array.isArray(d.subaccountIds) ? d.subaccountIds : [];
            m.setProperty("/discoverBusy", true);
            m.setProperty("/discoverErrors", []);
            var self = this;
            api.discoverOrigins(this.getOwnerComponent(), subaccountIds)
                .then(function (resp) {
                    m.setProperty("/discoveredOrigins", resp.origins || []);
                    m.setProperty("/discoverErrors", resp.errors || []);
                    var n = (resp.origins || []).length;
                    var e = (resp.errors || []).length;
                    MessageToast.show("Discovered " + n + " origin(s)" +
                        (e ? " (" + e + " subaccount(s) skipped - see errors)" : ""));
                })
                .catch(self._showError.bind(self))
                .finally(function () { m.setProperty("/discoverBusy", false); });
        },

        loadOriginProfiles: function () {
            var view = this.getView();
            if (!view.getModel("profiles")) {
                view.setModel(new JSONModel({ list: [], editing: null }), "profiles");
            }
            return api.listOriginProfiles(this.getOwnerComponent())
                .then(function (list) {
                    view.getModel("profiles").setProperty("/list", list || []);
                })
                .catch(function () { /* surface errors only on writes */ });
        },

        onSaveProfileFromDiscovered: function () {
            // Save the currently-selected discovered origins as a named profile.
            // Prompt for name + description via a small MessageBox; the user
            // can refine later in Admin -> Origin profiles.
            var d = this.getView().getModel("contain").getData();
            var picked = Array.isArray(d.selectedOrigins) ? d.selectedOrigins.slice() : [];
            if (picked.length === 0) {
                MessageBox.error("Pick at least one discovered origin before saving as a profile");
                return;
            }
            var self = this;
            sap.ui.require(["sap/m/Dialog", "sap/m/Input", "sap/m/Button", "sap/m/Label"],
                    function (Dialog, Input, Button, Label) {
                var nameInput = new Input({ placeholder: "All IAS-mapped users" });
                var descInput = new Input({ placeholder: "Optional description" });
                var dlg = new Dialog({
                    title: self._i18n("originProfileSaveAsTitle"),
                    contentWidth: "30rem",
                    content: [
                        new Label({ text: "Name", required: true }), nameInput,
                        new Label({ text: "Description" }), descInput,
                        new Label({ text: "Keys: " + picked.join(", ") })
                    ],
                    beginButton: new Button({
                        text: "Save", type: "Emphasized", press: function () {
                            var name = (nameInput.getValue() || "").trim();
                            if (!name) { MessageBox.error("Name is required"); return; }
                            api.createOriginProfile(self.getOwnerComponent(), {
                                name: name,
                                description: (descInput.getValue() || "").trim() || null,
                                originKeys: picked
                            }).then(function () {
                                MessageToast.show(self._i18n("originProfileSaved"));
                                dlg.close();
                                return self.loadOriginProfiles();
                            }).catch(self._showError.bind(self));
                        }
                    }),
                    endButton: new Button({ text: "Cancel", press: function () { dlg.close(); } }),
                    afterClose: function () { dlg.destroy(); }
                });
                self.getView().addDependent(dlg);
                dlg.open();
            });
        },

        // ----- Admin -> Origin profiles CRUD -----
        // The editor model carries TWO key sources that get unioned on save:
        //   - discoveredOrigins (rich list from /xsuaa/identity-providers)
        //     plus selectedDiscoveredKeys (the operator's tick marks)
        //   - extraKeysCsv (free-text for stale / extra keys the discover
        //     call doesn't see)
        // The previous shape only had a CSV textarea AND its discover-then-
        // merge path read `o.key` from the response (the API returns
        // `originKey`), so discovery silently dropped every entry. Mirror
        // the containment view's MultiComboBox pattern so the operator
        // visually picks origins with full key/name/type context.
        onNewOriginProfile: function () {
            this.getView().getModel("profiles").setProperty("/editing", {
                id: null, name: "", description: "",
                discoverSubaccountIds: [], discoverBusy: false, discoverErrors: [],
                discoveredOrigins: [], selectedDiscoveredKeys: [],
                extraKeysCsv: ""
            });
        },
        onEditOriginProfile: function (oEvent) {
            var p = oEvent.getSource().getBindingContext("profiles").getObject();
            // Pre-seed selectedDiscoveredKeys with every saved key. After
            // Discover runs the matching ones light up in the picker; the
            // rest stay tracked in the underlying selectedKeys array so
            // they roundtrip on save (no silent loss).
            this.getView().getModel("profiles").setProperty("/editing", {
                id: p.id, name: p.name, description: p.description || "",
                discoverSubaccountIds: [], discoverBusy: false, discoverErrors: [],
                discoveredOrigins: [],
                selectedDiscoveredKeys: (p.originKeys || []).slice(),
                extraKeysCsv: ""
            });
        },

        // Discover origins from the chosen subaccounts and populate the
        // MultiComboBox. Empty subaccount list -> "all enrolled" on the
        // server. Synthesise placeholder entries for keys already in the
        // profile that the current discovery doesn't return - keeps stale
        // keys visible (and pre-ticked) instead of vanishing from the UI.
        onDiscoverOriginsForProfile: function () {
            var m = this.getView().getModel("profiles");
            var e = m.getProperty("/editing") || {};
            var ids = Array.isArray(e.discoverSubaccountIds) ? e.discoverSubaccountIds : [];
            var savedKeys = Array.isArray(e.selectedDiscoveredKeys)
                    ? e.selectedDiscoveredKeys.slice() : [];
            var self = this;
            m.setProperty("/editing/discoverBusy", true);
            m.setProperty("/editing/discoverErrors", []);
            api.discoverOrigins(this.getOwnerComponent(), ids)
                .then(function (resp) {
                    var rows = (resp.origins || []).slice();
                    var seen = {};
                    rows.forEach(function (o) { if (o && o.originKey) seen[o.originKey] = true; });
                    savedKeys.forEach(function (k) {
                        if (k && !seen[k]) {
                            rows.push({ originKey: k, name: "(saved, not in current discovery)",
                                        type: "", active: null, seenIn: [] });
                        }
                    });
                    m.setProperty("/editing/discoveredOrigins", rows);
                    m.setProperty("/editing/discoverErrors", resp.errors || []);
                    MessageToast.show("Discovered " + (resp.origins || []).length + " origin(s)"
                            + ((resp.errors || []).length
                                ? " (" + (resp.errors || []).length + " subaccount(s) skipped)" : ""));
                })
                .catch(self._showError.bind(self))
                .finally(function () { m.setProperty("/editing/discoverBusy", false); });
        },
        onCancelEditOriginProfile: function () {
            this.getView().getModel("profiles").setProperty("/editing", null);
        },
        onSaveOriginProfileEdit: function () {
            var m = this.getView().getModel("profiles");
            var e = m.getProperty("/editing") || {};
            var name = (e.name || "").trim();
            if (!name) { MessageBox.error("Name is required"); return; }
            // Union of picker selection + manual extras, deduped while
            // preserving the picker order then the CSV order.
            var picked = Array.isArray(e.selectedDiscoveredKeys)
                    ? e.selectedDiscoveredKeys : [];
            var extras = (e.extraKeysCsv || "")
                    .split(/[\s,]+/).map(function (s) { return s.trim(); })
                    .filter(Boolean);
            var seen = {};
            var keys = [];
            picked.concat(extras).forEach(function (k) {
                if (k && !seen[k]) { seen[k] = true; keys.push(k); }
            });
            if (keys.length === 0) {
                MessageBox.error("Pick at least one discovered origin or add a key in 'Additional keys'");
                return;
            }
            var body = { name: name, description: (e.description || "").trim() || null,
                         originKeys: keys };
            var self = this;
            var p = e.id
                ? api.updateOriginProfile(self.getOwnerComponent(), e.id, body)
                : api.createOriginProfile(self.getOwnerComponent(), body);
            p.then(function () {
                MessageToast.show(self._i18n("originProfileSaved"));
                m.setProperty("/editing", null);
                return self.loadOriginProfiles();
            }).catch(self._showError.bind(self));
        },
        onDeleteOriginProfile: function (oEvent) {
            var p = oEvent.getSource().getBindingContext("profiles").getObject();
            var self = this;
            MessageBox.confirm("Delete origin profile '" + p.name + "'?", {
                onClose: function (a) {
                    if (a !== MessageBox.Action.OK) return;
                    api.deleteOriginProfile(self.getOwnerComponent(), p.id)
                        .then(function () {
                            MessageToast.show(self._i18n("originProfileDeleted"));
                            return self.loadOriginProfiles();
                        })
                        .catch(self._showError.bind(self));
                }
            });
        },

        onRefreshContainmentEvents: function () {
            var c = this.getOwnerComponent();
            var m = this.getView().getModel("contain");
            return api.recentContainmentEvents(c)
                .then(function (list) { m.setProperty("/events", list || []); })
                .catch(this._showError.bind(this));
        },

        onDisableProtection: function (oEvent) {
            // Same handler name as before so we don't churn the view binding,
            // but the action is now a hard delete on the server side.
            var row = oEvent.getSource().getBindingContext("data").getObject();
            var self = this;
            MessageBox.confirm(self._i18n("confirmDeleteProtectionText"), {
                title: self._i18n("confirmDeleteProtectionTitle"),
                actions: [self._i18n("confirmDeleteOk"), MessageBox.Action.CANCEL],
                emphasizedAction: self._i18n("confirmDeleteOk"),
                onClose: function (action) {
                    if (action !== self._i18n("confirmDeleteOk")) return;
                    api.disableProtection(self.getOwnerComponent(), row.id)
                        .then(function () { MessageToast.show(self._i18n("toastProtectionDeleted")); return self.loadProtected(); })
                        .catch(self._showError.bind(self));
                }
            });
        },

        // =================== SoD ===================

        onRefreshConflictSets: function () {
            var c = this.getOwnerComponent();
            var m = this.getView().getModel("sod");
            return api.listConflictSets(c)
                .then(function (list) { m.setProperty("/conflictSets", list || []); })
                .catch(this._showError.bind(this));
        },

        onOpenAddConflict: function () {
            this._openConflictDialog({
                id: null,
                name: "",
                description: "",
                severity: "high",
                kind: "sod",
                scopeLevel: "subaccount",
                rcsText: "",
                thresholdCount: 5
            });
        },

        onOpenEditConflict: function (oEvent) {
            var row = oEvent.getSource().getBindingContext("sod").getObject();
            this._openConflictDialog({
                id: row.id,
                name: row.name,
                description: row.description || "",
                severity: row.severity,
                kind: row.kind || "sod",
                scopeLevel: row.scopeLevel,
                rcsText: (row.roleCollections || []).join("\n"),
                thresholdCount: row.thresholdCount || 5
            });
        },

        onConflictKindChange: function () {
            this._refreshConflictKindHints();
        },

        _refreshConflictKindHints: function () {
            // Update the hint banner + label text whenever kind changes so the
            // user sees what each kind expects from the role-collections box.
            var m = this.getView().getModel("conflict");
            var kind = m.getProperty("/kind");
            var rcPlaceholder = "Subaccount Administrator\nAudit Log Administrator";
            var emailPlaceholder = "contoso.com\nsap.com\nexample.com";
            if (kind === "critical") {
                m.setProperty("/kindHint", this._i18n("kindHintCritical"));
                m.setProperty("/rcsLabel", this._i18n("dlgConflictRcsLblCritical"));
                m.setProperty("/rcsPlaceholder", rcPlaceholder);
            } else if (kind === "threshold") {
                m.setProperty("/kindHint", this._i18n("kindHintThreshold"));
                m.setProperty("/rcsLabel", this._i18n("dlgConflictRcsLblThreshold"));
                m.setProperty("/rcsPlaceholder", rcPlaceholder);
            } else if (kind === "external_email") {
                m.setProperty("/kindHint", this._i18n("kindHintExternalEmail"));
                m.setProperty("/rcsLabel", this._i18n("dlgConflictRcsLblExternalEmail"));
                m.setProperty("/rcsPlaceholder", emailPlaceholder);
            } else {
                m.setProperty("/kindHint", this._i18n("kindHintSod"));
                m.setProperty("/rcsLabel", this._i18n("dlgConflictRcsLblSod"));
                m.setProperty("/rcsPlaceholder", rcPlaceholder);
            }
        },

        _openConflictDialog: function (initial) {
            var view = this.getView();
            view.setModel(new JSONModel(initial), "conflict");
            this._refreshConflictKindHints();
            var self = this;
            if (!this._conflictDialog) {
                Fragment.load({
                    id: view.getId(),
                    name: "btpc.view.ConflictDialog",
                    controller: this
                }).then(function (dlg) {
                    self._conflictDialog = dlg;
                    view.addDependent(dlg);
                    dlg.open();
                });
            } else {
                this._conflictDialog.open();
            }
        },

        onCancelConflict: function () {
            if (this._conflictDialog) this._conflictDialog.close();
        },

        onSaveConflict: function () {
            var d = this.getView().getModel("conflict").getData();
            if (!d.name || !d.name.trim()) { MessageBox.error("Name is required"); return; }
            var rcs = (d.rcsText || "")
                .split(/[\r\n]+/)
                .map(function (s) { return s.trim(); })
                .filter(function (s) { return s.length > 0; });
            var kind = d.kind || "sod";
            if (kind === "sod" && rcs.length < 2) {
                MessageBox.error("SoD rules require at least two role collections.");
                return;
            }
            if (kind === "critical" && rcs.length < 1) {
                MessageBox.error("Critical rules require at least one role collection.");
                return;
            }
            var thr = null;
            if (kind === "threshold") {
                thr = parseInt(d.thresholdCount, 10);
                if (!thr || thr < 1) {
                    MessageBox.error("Threshold rules require a count >= 1.");
                    return;
                }
            }
            // external_email: rcs may be empty (falls back to global config).
            var payload = {
                name: d.name.trim(),
                description: (d.description || "").trim() || null,
                severity: d.severity,
                kind: kind,
                scopeLevel: d.scopeLevel,
                roleCollections: rcs,
                thresholdCount: thr
            };
            var self = this;
            var promise = d.id
                ? api.updateConflictSet(this.getOwnerComponent(), d.id, payload)
                : api.createConflictSet(this.getOwnerComponent(), payload);
            promise
                .then(function () {
                    self._conflictDialog.close();
                    MessageToast.show("Saved");
                    return self.onRefreshConflictSets();
                })
                .catch(self._showError.bind(self));
        },

        onToggleConflictEnabled: function (oEvent) {
            var enabled = oEvent.getParameter("state");
            var row = oEvent.getSource().getBindingContext("sod").getObject();
            var self = this;
            api.setConflictEnabled(this.getOwnerComponent(), row.id, enabled)
                .then(function () { MessageToast.show("Saved"); return self.onRefreshConflictSets(); })
                .catch(self._showError.bind(self));
        },

        onDeleteConflict: function (oEvent) {
            var row = oEvent.getSource().getBindingContext("sod").getObject();
            var self = this;
            MessageBox.confirm(self._i18n("sodConfirmDeleteText"), {
                title: self._i18n("sodConfirmDeleteTitle"),
                actions: [self._i18n("sodConfirmDeleteOk"), MessageBox.Action.CANCEL],
                emphasizedAction: self._i18n("sodConfirmDeleteOk"),
                onClose: function (a) {
                    if (a !== self._i18n("sodConfirmDeleteOk")) return;
                    api.deleteConflictSet(self.getOwnerComponent(), row.id)
                        .then(function () { MessageToast.show("Deleted"); return self.onRefreshConflictSets(); })
                        .catch(self._showError.bind(self));
                }
            });
        },

        onRunSodScan: function () {
            var m = this.getView().getModel("sod");
            var sid = m.getProperty("/scanSubaccountId");
            if (!sid) { MessageBox.error("Pick a subaccount"); return; }
            var self = this;
            api.runSodScan(this.getOwnerComponent(), sid)
                .then(function (resp) {
                    m.setProperty("/lastScan", resp);
                    MessageToast.show("Scan: " + resp.findings.length + " finding(s)");
                })
                .catch(self._showError.bind(self));
        },

        onContainFromFinding: function (oEvent) {
            var f = oEvent.getSource().getBindingContext("sod").getObject();
            var lastScan = this.getView().getModel("sod").getProperty("/lastScan");
            var sid = this.getView().getModel("sod").getProperty("/scanSubaccountId");
            var contain = this.getView().getModel("contain");
            contain.setProperty("/subaccountIds", sid ? [sid] : []);
            contain.setProperty("/userEmail", f.userEmail);
            // IAS lock is implicit per selected tenant - no toggle.
            contain.setProperty("/actStripRoles", true);
            contain.setProperty("/actDeleteShadow", false);
            contain.setProperty("/dryRun", true);
            this.byId("tabs").setSelectedKey("containment");
            MessageToast.show("Prefilled containment form for " + f.userEmail);
        },

        // =================== discovery (saved keys + candidates) ===================

        loadDiscovery: function () {
            var m = this.getView().getModel("discovery");
            var onlyPromotable = !!m.getProperty("/showOnlyPromotable");
            return Promise.all([
                api.listSavedKeys(this.getOwnerComponent()),
                api.listCandidates(this.getOwnerComponent(), onlyPromotable)
            ]).then(function (results) {
                m.setProperty("/savedKeys", results[0] || []);
                m.setProperty("/candidates", results[1] || []);
            }).catch(this._showError.bind(this));
        },

        onCandidateFilterChange: function () { this.loadDiscovery(); },

        onOpenAddSavedKey: function () {
            var view = this.getView();
            var self = this;
            view.setModel(new JSONModel({
                serviceKey: "",
                label: "",
                syncIntervalMinutes: 60,
                syncEnabled: true,
                validation: ""
            }), "addKey");
            if (!this._addKeyDialog) {
                Fragment.load({
                    id: view.getId(),
                    name: "btpc.view.AddSavedKeyDialog",
                    controller: this
                }).then(function (dlg) {
                    self._addKeyDialog = dlg;
                    view.addDependent(dlg);
                    dlg.open();
                });
            } else {
                this._addKeyDialog.open();
            }
        },

        onCancelAddSavedKey: function () {
            if (this._addKeyDialog) this._addKeyDialog.close();
        },

        onAddSavedKeyChange: function (oEvt) {
            var m = this.getView().getModel("addKey");
            var v = (oEvt.getParameter("value") || "").trim();
            if (!v) { m.setProperty("/validation", ""); return; }
            try {
                var parsed = JSON.parse(v);
                m.setProperty("/validation", this._sniffKey(parsed));
            } catch (e) {
                m.setProperty("/validation", this._i18n("sniffInvalid").replace("{0}", e.message));
            }
        },

        onConfirmAddSavedKey: function () {
            var d = this.getView().getModel("addKey").getData();
            var self = this;
            if (!d.serviceKey || !d.serviceKey.trim()) { MessageBox.error("Paste a CIS Central-Viewer service key"); return; }
            var interval = Number(d.syncIntervalMinutes) || 60;
            if (interval < 1 || interval > 10080) { MessageBox.error("Sync interval must be 1-10080 minutes"); return; }
            api.saveCentralKey(this.getOwnerComponent(), {
                serviceKey: d.serviceKey.trim(),
                label: (d.label || "").trim() || null,
                syncIntervalMinutes: interval,
                syncEnabled: !!d.syncEnabled
            }).then(function () {
                self._addKeyDialog.close();
                MessageToast.show(self._i18n("toastSavedKeyAdded"));
                return self.loadDiscovery();
            }).catch(self._showError.bind(self));
        },

        onToggleSavedKeyEnabled: function (oEvent) {
            var enabled = oEvent.getParameter("state");
            var row = oEvent.getSource().getBindingContext("discovery").getObject();
            var self = this;
            api.updateSavedKey(this.getOwnerComponent(), row.id, { syncEnabled: enabled })
                .then(function () { MessageToast.show(self._i18n("toastSavedKeyUpdated")); return self.loadDiscovery(); })
                .catch(self._showError.bind(self));
        },

        onChangeSavedKeyInterval: function (oEvent) {
            var row = oEvent.getSource().getBindingContext("discovery").getObject();
            var n = Number(oEvent.getParameter("value"));
            if (!n || n < 1 || n > 10080) { return; /* let the input show its own constraint feedback */ }
            var self = this;
            api.updateSavedKey(this.getOwnerComponent(), row.id, { syncIntervalMinutes: n })
                .then(function () { MessageToast.show(self._i18n("toastSavedKeyUpdated")); })
                .catch(self._showError.bind(self));
        },

        onSyncSavedKeyNow: function (oEvent) {
            var row = oEvent.getSource().getBindingContext("discovery").getObject();
            var self = this;
            api.triggerSavedKeySync(this.getOwnerComponent(), row.id)
                .then(function () {
                    MessageToast.show(self._i18n("toastSyncTriggered"));
                    return self.loadDiscovery();
                })
                // After the sync the candidate count may have changed -
                // refresh the KPI strip so the Discovery tile reflects it
                // immediately instead of staying stale until the next tab.
                .then(function () { return self.refreshKpis(); })
                .catch(self._showError.bind(self));
        },

        onDeleteSavedKey: function (oEvent) {
            var row = oEvent.getSource().getBindingContext("discovery").getObject();
            var self = this;
            MessageBox.confirm(self._i18n("confirmDeleteSavedKeyText"), {
                title: self._i18n("confirmDeleteSavedKeyTitle"),
                actions: [self._i18n("confirmDeleteSavedKeyOk"), MessageBox.Action.CANCEL],
                emphasizedAction: self._i18n("confirmDeleteSavedKeyOk"),
                onClose: function (action) {
                    if (action !== self._i18n("confirmDeleteSavedKeyOk")) return;
                    api.deleteSavedKey(self.getOwnerComponent(), row.id)
                        .then(function () { MessageToast.show(self._i18n("toastSavedKeyDeleted")); return self.loadDiscovery(); })
                        .catch(self._showError.bind(self));
                }
            });
        },

        onEnrollCandidate: function (oEvent) {
            var row = oEvent.getSource().getBindingContext("discovery").getObject();
            // Open the enroll dialog pre-filled with the candidate's data and
            // a pinned discoveredId so the row links on success.
            this.onOpenEnroll();
            var m = this.getView().getModel("enroll");
            m.setProperty("/mode", "discover");
            m.setProperty("/subaccountGuid", row.subaccountGuid);
            m.setProperty("/cisDisplayName", row.displayName || "");
            m.setProperty("/region", row.region || "");
            m.setProperty("/globalAccountId", row.globalAccountGuid || null);
            m.setProperty("/discoveredId", row.id);
            m.setProperty("/candidates", [{
                guid: row.subaccountGuid,
                displayName: row.displayName,
                region: row.region,
                parentGuid: row.parentGuid,
                parentType: row.parentType,
                globalAccountGuid: row.globalAccountGuid,
                discoveredId: row.id
            }]);
            m.setProperty("/discoveryHint", "Promoting discovered candidate.");
        },

        // Dismiss / reopen removed in V12. The candidate list is now derived
        // from discovered_subaccounts LEFT JOIN subaccounts; "promotable" = not
        // currently enrolled. Operators can hard-delete a stale candidate row.

        // =================== logs (audit-event browser) ===================

        onApplyLogFilters: function () {
            var m = this.getView().getModel("logs");
            var self = this;
            return api.listAuditEvents(this.getOwnerComponent(), m.getProperty("/filters"))
                .then(function (rows) { m.setProperty("/rows", rows || []); })
                .catch(self._showError.bind(self));
        },

        onResetLogFilters: function () {
            this.getView().getModel("logs").setProperty("/filters", {
                action: "", outcome: "", systemType: "", actor: "", targetEmail: "",
                fromDate: "", toDate: "", limit: 200
            });
            this.onApplyLogFilters();
        },

        onExportLogs: function (oEvent) {
            var fmt = oEvent.getSource().data("format") || "csv";
            var filters = this.getView().getModel("logs").getProperty("/filters");
            // Strip the table-view limit - export uses its own (10k default,
            // 100k ceiling), bounded server-side.
            var f = Object.assign({}, filters);
            delete f.limit;
            var self = this;
            api.downloadAuditExport(this.getOwnerComponent(), f, fmt)
                .then(function () { MessageToast.show(self._i18n("toastExportDone")); })
                .catch(self._showError.bind(self));
        },

        _i18n: function (key) {
            return this.getOwnerComponent().getModel("i18n").getResourceBundle().getText(key);
        },

        _showError: function (err) {
            MessageBox.error(
                this._i18n("toastErrorPrefix") + " " + (err && err.message ? err.message : err),
                { title: "Request failed" }
            );
        },

        // ---------------- progress dialog ----------------

        // Coarse busy indicator for synchronous long-running calls
        // (containment + unlock). The request is one POST, so this is
        // wall-clock feedback, not per-step progress. ETA uses rough
        // per-action wall times tuned against the live BTP roundtrip cost
        // observed during dev; tweak the constants if the real wait drifts.
        _PROGRESS_PER_TENANT_S: 3,      // IAS deactivate / activate
        _PROGRESS_PER_ACTION_S: 5,      // each per-subaccount action

        // Returns a handle with .done() that closes the dialog and reports
        // the actual elapsed time as a toast. Pass an estimateSec hint so
        // the title shows "~Ns expected". A 1s tick updates the elapsed
        // counter so the operator sees the dialog isn't frozen.
        _openProgressDialog: function (label, estimateSec) {
            var start = Date.now();
            var dlg = new BusyDialog({
                title: label,
                text: estimateSec > 0
                    ? ("Estimated ~" + estimateSec + "s - elapsed 0s")
                    : "Working - elapsed 0s",
                showCancelButton: false
            });
            dlg.open();
            var tick = setInterval(function () {
                if (!dlg) return;
                var elapsed = Math.floor((Date.now() - start) / 1000);
                dlg.setText(estimateSec > 0
                    ? ("Estimated ~" + estimateSec + "s - elapsed " + elapsed + "s")
                    : ("Working - elapsed " + elapsed + "s"));
            }, 1000);
            return {
                done: function () {
                    clearInterval(tick);
                    var elapsed = Math.floor((Date.now() - start) / 1000);
                    try { dlg.close(); dlg.destroy(); } catch (e) { /* already closed */ }
                    MessageToast.show(label + " - completed in " + elapsed + "s"
                            + (estimateSec > 0 ? " (est. ~" + estimateSec + "s)" : ""));
                }
            };
        },

        // ---------------- result enrichment ----------------

        // Backend returns iasResults and resolvedIasTenantIds as parallel
        // arrays. The result table wants a single array of objects with
        // tenantId + host + action/outcome/message. Compute that here so the
        // view binding stays simple. Idempotent - safe to call twice.
        // Walks the response and stamps a `summary` object on it:
        //   { ok, partial, skipped, failed, dryRun, total }
        // The view binds an ObjectStatus strip to this so the operator sees
        // overall status without scanning every per-subaccount row. Counts
        // include both the tenant-level IAS steps and the per-subaccount
        // action results.
        _summariseResult: function (resp) {
            var c = { ok: 0, partial: 0, skipped: 0, failed: 0, dryRun: 0, total: 0 };
            var tally = function (outcome) {
                c.total++;
                if (outcome === "ok") c.ok++;
                else if (outcome === "partial") c.partial++;
                else if (outcome === "skipped") c.skipped++;
                else if (outcome === "failed") c.failed++;
                else if (outcome === "dry-run") c.dryRun++;
            };
            var iasTenants = (this.getView().getModel("iasTenants")
                && this.getView().getModel("iasTenants").getProperty("/list")) || [];
            var hostById = {};
            var nameById = {};
            iasTenants.forEach(function (t) {
                if (t && t.id) {
                    hostById[t.id] = t.iasHost || "";
                    nameById[t.id] = t.displayName || "";
                }
            });
            // Flat rows for the unified actions table. One row per action,
            // regardless of whether the source is IAS tenant or subaccount.
            // Sort key (severity desc, then scope) computed once so the UI
            // can sort without re-deriving on every render.
            var allRows = [];
            var severity = { failed: 0, partial: 1, skipped: 2, "dry-run": 3, ok: 4 };
            var iasIds = Array.isArray(resp.resolvedIasTenantIds) ? resp.resolvedIasTenantIds : [];
            (resp.iasResults || []).forEach(function (r, i) {
                var id = iasIds[i] || "";
                tally(r.outcome);
                allRows.push({
                    scope: "IAS",
                    targetTitle: nameById[id] || "IAS tenant",
                    targetSub:   hostById[id] || (id ? id.substring(0, 8) : ""),
                    action: r.action,
                    outcome: r.outcome,
                    message: r.message,
                    severity: severity[r.outcome] != null ? severity[r.outcome] : 9
                });
            });
            (resp.perSubaccount || []).forEach(function (s) {
                if (s.blockedByProtection) {
                    // Render the block as a synthesised row so the operator
                    // sees protection-skipped subaccounts in the same view
                    // instead of buried in a separate "blocked" message.
                    tally("skipped");
                    allRows.push({
                        scope: "Subaccount",
                        targetTitle: s.displayName,
                        targetSub: "BLOCKED (protected user)",
                        action: " - ",
                        outcome: "skipped",
                        message: (s.protectionReasons || []).join("; "),
                        severity: 2
                    });
                    return;
                }
                (s.results || []).forEach(function (r) {
                    tally(r.outcome);
                    allRows.push({
                        scope: "Subaccount",
                        targetTitle: s.displayName,
                        targetSub: "",
                        action: r.action,
                        outcome: r.outcome,
                        message: r.message,
                        severity: severity[r.outcome] != null ? severity[r.outcome] : 9
                    });
                });
            });
            allRows.sort(function (a, b) {
                if (a.severity !== b.severity) return a.severity - b.severity;
                if (a.scope !== b.scope) return a.scope < b.scope ? -1 : 1;
                return a.targetTitle < b.targetTitle ? -1 : 1;
            });
            resp.allActions = allRows;
            resp.summary = c;
            resp.summaryText =
                c.ok + " ok"
                + (c.partial ? " * " + c.partial + " partial" : "")
                + (c.skipped ? " * " + c.skipped + " skipped" : "")
                + (c.failed  ? " * " + c.failed  + " failed"  : "")
                + (c.dryRun  ? " * " + c.dryRun  + " dry-run" : "");
            // Overall state for the summary chip - error wins, then warning,
            // then success/none.
            resp.summaryState =
                c.failed > 0 ? "Error"
                : (c.partial > 0 || c.skipped > 0) ? "Warning"
                : c.ok > 0 ? "Success"
                : "None";
        },

        _enrichIasResults: function (resp) {
            if (resp) this._summariseResult(resp);
            if (!resp || !Array.isArray(resp.iasResults)) {
                if (resp) resp.iasResultsEnriched = [];
                return;
            }
            var ids = Array.isArray(resp.resolvedIasTenantIds) ? resp.resolvedIasTenantIds : [];
            var tenants = (this.getView().getModel("iasTenants")
                && this.getView().getModel("iasTenants").getProperty("/list")) || [];
            var hostById = {};
            var nameById = {};
            tenants.forEach(function (t) {
                if (t && t.id) {
                    hostById[t.id] = t.iasHost || "";
                    nameById[t.id] = t.displayName || "";
                }
            });
            resp.iasResultsEnriched = resp.iasResults.map(function (r, i) {
                var id = ids[i] || "";
                return {
                    iasTenantId: id,
                    iasTenantHost: hostById[id] || "",
                    iasTenantName: nameById[id] || (id ? id.substring(0, 8) : ""),
                    action: r.action,
                    outcome: r.outcome,
                    message: r.message,
                    snapshotId: r.snapshotId
                };
            });
        },

        // ---------------- input validators ----------------
        // Frontend syntax guardrails so operators get feedback before a
        // round-trip and the server-side validator never sees malformed
        // strings. Mirrors the equivalent backend checks where they exist;
        // backend remains authoritative.

        // RFC 4122 UUID (any version). The wider check matches what the
        // backend's UUID.fromString accepts; we don't gate to v4 only,
        // because BTP-issued GUIDs are not strictly v4.
        _isUuid: function (s) {
            if (!s) return false;
            return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(s);
        },

        // Trims and inspects a URL string. Returns { ok, cleaned, error }.
        // `cleaned` is the trimmed value (safe to bind back into the model).
        // Rejected: missing https://, embedded whitespace, leading/trailing
        // whitespace surviving the trim (shouldn't, but defensive).
        _validateUrl: function (raw, opts) {
            opts = opts || {};
            if (raw == null) return { ok: false, cleaned: "", error: "URL is required" };
            var cleaned = String(raw).trim();
            if (!cleaned) return { ok: false, cleaned: "", error: "URL is required" };
            if (/\s/.test(cleaned)) {
                return { ok: false, cleaned: cleaned,
                    error: "URL must not contain whitespace (check for stray spaces or newlines)" };
            }
            if (opts.requireHttps !== false && !/^https:\/\//i.test(cleaned)) {
                return { ok: false, cleaned: cleaned, error: "URL must start with https://" };
            }
            // URL constructor catches the obvious malformed cases (missing
            // host, bad scheme combo, etc). Wrap in try/catch - older
            // browsers throw TypeError on bad input.
            try { new URL(cleaned); }
            catch (e) { return { ok: false, cleaned: cleaned, error: "URL is not parseable" }; }
            return { ok: true, cleaned: cleaned, error: null };
        },

        // Email: minimal "x@y.z" check. Not RFC-perfect; tight enough to
        // catch typos like missing @ or leading whitespace.
        _validateEmail: function (raw) {
            if (raw == null) return { ok: false, cleaned: "", error: "Email is required" };
            var cleaned = String(raw).trim();
            if (!cleaned) return { ok: false, cleaned: "", error: "Email is required" };
            if (/\s/.test(cleaned)) {
                return { ok: false, cleaned: cleaned,
                    error: "Email must not contain whitespace" };
            }
            if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(cleaned)) {
                return { ok: false, cleaned: cleaned, error: "Email is not in user@domain.tld format" };
            }
            return { ok: true, cleaned: cleaned, error: null };
        }
    });
});
