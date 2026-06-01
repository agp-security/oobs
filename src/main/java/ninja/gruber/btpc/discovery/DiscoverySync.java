// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.discovery;

import ninja.gruber.btpc.discovery.domain.CentralViewerKey;

import ninja.gruber.btpc.audit.IAuditForward.ActorSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class DiscoverySync {

    private static final Logger log = LoggerFactory.getLogger(DiscoverySync.class);

    private final CentralKeyService keys;
    private final DiscoveryService discovery;
    private final boolean enabled;

    public DiscoverySync(CentralKeyService keys, DiscoveryService discovery,
                         @Value("${btpc.discovery.scheduler-enabled:true}") boolean enabled) {
        this.keys = keys;
        this.discovery = discovery;
        this.enabled = enabled;
    }

    @Scheduled(fixedDelayString = "${btpc.discovery.tick-seconds:60}")
    public void tick() {
        if (!enabled) return;
        List<CentralViewerKey> due;
        try {
            due = keys.findDueForSync();
        } catch (Exception e) {
            log.warn("Discovery scheduler: findDueForSync failed", e);
            return;
        }
        if (due.isEmpty()) return;
        log.debug("Discovery scheduler: {} key(s) due for sync", due.size());
        for (CentralViewerKey k : due) {
            try {
                discovery.syncOne(k.id(), "system:discovery-sync", ActorSource.SYSTEM);
            } catch (Exception e) {
                log.warn("Discovery scheduler: syncOne({}) leaked exception", k.id(), e);
            }
        }
    }
}
