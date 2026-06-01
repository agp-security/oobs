// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.health;

import ninja.gruber.btpc.appconfig.AppConfigService;
import ninja.gruber.btpc.audit.IAuditForward.ActorSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;

// Periodic auto-runner for HealthCheckService.
//
// `@Scheduled(fixedDelay=...)` requires a compile-time constant, so the
// tick rate here is fixed at 60 seconds. Each tick reads the configured
// interval from app_config (key=health.auto.interval_seconds) and only
// invokes the probe if at least that much wall-clock time has passed
// since the last run. A configured value of 0 / null / unparseable
// disables the job entirely without removing the bean.
@Component
public class ScheduledHealthCheckJob {

    private static final Logger log = LoggerFactory.getLogger(ScheduledHealthCheckJob.class);
    // Hard floor: even if an operator sets `health.auto.interval_seconds=5`
    // we won't actually run more than once a minute, because the @Scheduled
    // tick is 60 s and the gate just lets the next tick through.
    private static final long MIN_INTERVAL_SECONDS = 60L;

    private final AppConfigService config;
    private final HealthCheckService health;
    private final HealthCheckController controller;
    private volatile Instant lastRunAt = Instant.EPOCH;

    public ScheduledHealthCheckJob(AppConfigService config, HealthCheckService health,
                                   HealthCheckController controller) {
        this.config = config;
        this.health = health;
        this.controller = controller;
    }

    @Scheduled(fixedDelay = 60_000L, initialDelay = 30_000L)
    public void tick() {
        Long configured = config.getHealthAutoIntervalSeconds();
        if (configured == null || configured <= 0L) return;
        long effective = Math.max(configured, MIN_INTERVAL_SECONDS);
        Duration elapsed = Duration.between(lastRunAt, Instant.now());
        if (elapsed.toSeconds() < effective) return;
        try {
            HealthCheckService.Report r = health.runAll("system", ActorSource.SYSTEM);
            controller.recordScheduledRun(r);
            lastRunAt = Instant.now();
            log.info("scheduled health-check run done - {}/{} probes ok",
                    r.okProbes(), r.totalProbes());
        } catch (Exception e) {
            // Swallow - the job must not crash the @Scheduled thread. The
            // individual probe failures are already audited per-probe.
            log.warn("scheduled health-check tick failed: {}", e.getMessage(), e);
        }
    }
}
