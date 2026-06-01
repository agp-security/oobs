// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.containment;

import ninja.gruber.btpc.containment.domain.ContainmentDtos;

import ninja.gruber.btpc.audit.IAuditForward.ActorSource;
import ninja.gruber.btpc.config.MethodSecurityConfig;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/containment")
public class ContainmentController {

    private final ContainmentService containmentService;
    private final UnlockService unlockService;

    public ContainmentController(ContainmentService containmentService, UnlockService unlockService) {
        this.containmentService = containmentService;
        this.unlockService = unlockService;
    }

    @PostMapping
    @PreAuthorize(MethodSecurityConfig.RESPONDER)
    public ContainmentDtos.ContainmentResult contain(
            @RequestBody ContainmentDtos.ContainRequest req,
            Authentication auth,
            @RequestHeader(value = "X-Caller-Source", required = false) String sourceHeader) {
        return containmentService.contain(req,
                auth.getName(),
                parseSource(sourceHeader));
    }

    @GetMapping("/unlock-preview")
    @PreAuthorize(MethodSecurityConfig.VIEWER)
    public List<ContainmentDtos.UnlockPreviewEntry> unlockPreview(
            @RequestParam String userEmail,
            @RequestParam(required = false) List<UUID> subaccountIds) {
        return unlockService.previewUnlock(userEmail, subaccountIds);
    }

    @PostMapping("/unlock")
    @PreAuthorize(MethodSecurityConfig.RESPONDER)
    public ContainmentDtos.UnlockResult unlock(
            @RequestBody ContainmentDtos.UnlockRequest req,
            Authentication auth,
            @RequestHeader(value = "X-Caller-Source", required = false) String sourceHeader) {
        return unlockService.unlock(req,
                auth.getName(),
                parseSource(sourceHeader));
    }

    /** only internal for logging -> no functional difference - detect issues using auth.getName() crosschecked.. **/
    private static ActorSource parseSource(String src) {
        if (src == null || src.isBlank()) return ActorSource.UI;
        return switch (src.toLowerCase()) {
            case "soar", "soar-api" -> ActorSource.SOAR_API;
            case "system" -> ActorSource.SYSTEM;
            default -> ActorSource.UI;
        };
    }
}
