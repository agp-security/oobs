// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.certinventory;

import ninja.gruber.btpc.config.MethodSecurityConfig;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/certificates")
public class CertificateController {

    private final CertificateInventoryService service;

    public CertificateController(CertificateInventoryService service) {
        this.service = service;
    }

    @GetMapping
    @PreAuthorize(MethodSecurityConfig.VIEWER)
    public List<CertificateInventoryService.CertEntry> list() {
        return service.list();
    }
}
