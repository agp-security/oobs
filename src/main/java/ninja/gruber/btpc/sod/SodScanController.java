// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.sod;

import ninja.gruber.btpc.audit.IAuditForward.ActorSource;
import ninja.gruber.btpc.config.MethodSecurityConfig;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/sod")
public class SodScanController {

    private final SodEngine engine;

    public SodScanController(SodEngine engine) {
        this.engine = engine;
    }

    @PostMapping("/scan")
    @PreAuthorize(MethodSecurityConfig.SOD_VIEWER)
    public SodEngine.ScanResult scan(
            @RequestBody ScanRequest req,
            Authentication auth,
            @RequestHeader(value = "X-Caller-Source", required = false) String src) {
        if (req == null || req.subaccountId == null) {
            throw new IllegalArgumentException("subaccountId is required");
        }
        return engine.scan(req.subaccountId,
                auth != null ? auth.getName() : "unknown",
                parseSource(src));
    }

    public static class ScanRequest { public UUID subaccountId; }

    private static ActorSource parseSource(String s) {
        if (s == null || s.isBlank()) return ActorSource.UI;
        return switch (s.toLowerCase()) {
            case "soar", "soar-api" -> ActorSource.SOAR_API;
            case "system" -> ActorSource.SYSTEM;
            default -> ActorSource.UI;
        };
    }
}
