// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.health;

import ninja.gruber.btpc.audit.IAuditForward.ActorSource;
import ninja.gruber.btpc.config.MethodSecurityConfig;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.concurrent.atomic.AtomicReference;

// Health-check matrix endpoint. Two routes:
//   POST /api/v1/health-check/run    - triggers a probe across every
//                                      credential, returns the report.
//                                      Caches the latest result for the
//                                      GET below so the UI can refresh
//                                      without re-probing.
//   GET  /api/v1/health-check/latest - returns the cached report or null
//                                      if no run has happened yet.
@RestController
@RequestMapping("/api/v1/health-check")
public class HealthCheckController {

    private final HealthCheckService service;
    private final AtomicReference<HealthCheckService.Report> latest = new AtomicReference<>();

    public HealthCheckController(HealthCheckService service) {
        this.service = service;
    }

    @PostMapping("/run")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public HealthCheckService.Report run(Authentication auth) {
        HealthCheckService.Report r = service.runAll(
                auth != null ? auth.getName() : "unknown",
                ActorSource.UI);
        latest.set(r);
        return r;
    }

    @GetMapping("/latest")
    @PreAuthorize(MethodSecurityConfig.VIEWER)
    public HealthCheckService.Report latest() {
        return latest.get();
    }

    // Internal hook for the scheduled job so the latest cache stays warm
    // even when the operator never clicks Run.
    public void recordScheduledRun(HealthCheckService.Report r) {
        latest.set(r);
    }
}
