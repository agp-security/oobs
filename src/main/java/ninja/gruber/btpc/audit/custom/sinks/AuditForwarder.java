// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.audit.custom.sinks;

import ninja.gruber.btpc.audit.IAuditForward.AuditEvent;
import ninja.gruber.btpc.audit.custom.domain.AuditSinkConfig;

public interface AuditForwarder {

    AuditSinkConfig.Kind kind();

    void send(AuditEvent event) throws Exception;

    String testConnection() throws Exception;
}
