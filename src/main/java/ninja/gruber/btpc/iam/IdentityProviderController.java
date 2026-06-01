// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.iam;

import ninja.gruber.btpc.config.MethodSecurityConfig;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/xsuaa")
public class IdentityProviderController {

    private final IdentityProviderService discovery;

    public IdentityProviderController(IdentityProviderService discovery) {
        this.discovery = discovery;
    }

    //used to create profiles / origins
    @GetMapping("/identity-providers")
    @PreAuthorize(MethodSecurityConfig.VIEWER)
    public IdentityProviderService.DiscoverResult discover(
            @RequestParam(required = false) List<UUID> subaccountIds) {
        return discovery.discover(subaccountIds);
    }
}
