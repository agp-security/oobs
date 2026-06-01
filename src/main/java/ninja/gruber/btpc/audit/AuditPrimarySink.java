// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.audit;

import ninja.gruber.btpc.audit.custom.sinks.AuditForwarder;
import ninja.gruber.btpc.audit.postgres.PostgresAuditSecondarySink;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@Primary
public class AuditPrimarySink implements IAuditForward {

    private static final Logger log = LoggerFactory.getLogger(AuditPrimarySink.class);

    private final PostgresAuditSecondarySink postgres;
    private final List<AuditForwarder> forwarders;

    public AuditPrimarySink(PostgresAuditSecondarySink postgres, List<AuditForwarder> forwarders) {
        this.postgres = postgres;
        this.forwarders = forwarders == null ? List.of() : forwarders;
        log.info("FanoutAuditSink wired with {} forwarder(-s): {}",
                this.forwarders.size(),
                String.join(", ", this.forwarders.stream().map(f -> f.kind().dbValue()).toList()));
    }

    @Override
    public void record(AuditEvent event) {
        postgres.record(event);
        //custom forwarding to splunk and btp audit log service
        for (AuditForwarder f : forwarders) {
            try {
                f.send(event);
            } catch (Exception e) {
                log.warn("audit forwarder {} failed for event action={} corr={}: {}",
                        f.kind().dbValue(), event.action(), event.correlationId(), e.getMessage());
            }
        }
    }
}
