// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

sap.ui.define([
    "sap/ui/core/UIComponent",
    "sap/ui/model/json/JSONModel"
], function (UIComponent, JSONModel) {
    "use strict";
    return UIComponent.extend("btpc.Component", {
        metadata: {
            manifest: "json"
        },
        init: function () {
            UIComponent.prototype.init.apply(this, arguments);

            // Dev-auth state, persisted to localStorage.
            var raw = null;
            try { raw = localStorage.getItem("btpc.devAuth"); }
            catch (e) { console.warn("btpc: localStorage unavailable", e); }
            var auth;
            try { auth = raw ? JSON.parse(raw) : {}; }
            catch (e) {
                console.warn("btpc: localStorage.btpc.devAuth was malformed, resetting", raw, e);
                auth = {};
            }
            if (!auth.user)   auth.user = "alice@example.com";
            if (!auth.scopes) auth.scopes = "btpc.admin,btpc.responder";
            console.info("btpc.Component.init: devAuth model =", auth);
            this.setModel(new JSONModel(auth), "devAuth");

            this.setModel(new JSONModel({
                subaccounts: [],
                protected: []
            }), "data");
        }
    });
});
