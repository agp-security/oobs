// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.useranalysis;

import ninja.gruber.btpc.config.MethodSecurityConfig;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/user-analysis")
public class UserAnalysisController {

    private final UserAnalysisService service;

    public UserAnalysisController(UserAnalysisService service) { this.service = service; }

    @GetMapping
    @PreAuthorize(MethodSecurityConfig.RESPONDER)
    public UserAnalysisService.AnalysisReport analyze(@RequestParam String email) {
        return service.analyze(email);
    }
}
