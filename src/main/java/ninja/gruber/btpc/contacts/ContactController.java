// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.contacts;

import ninja.gruber.btpc.config.MethodSecurityConfig;
import ninja.gruber.btpc.domain.SubaccountContact;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/subaccounts/{subaccountId}/contacts")
public class ContactController {

    private final ContactService service;

    public ContactController(ContactService service) {
        this.service = service;
    }

    @GetMapping
    @PreAuthorize(MethodSecurityConfig.VIEWER)
    public List<SubaccountContact> list(@PathVariable UUID subaccountId) {
        return service.list(subaccountId);
    }

    @PostMapping
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public ResponseEntity<SubaccountContact> add(
            @PathVariable UUID subaccountId,
            @RequestBody ContactService.ContactPayload body,
            Authentication auth) {
        SubaccountContact c = service.add(subaccountId, body,
                auth != null ? auth.getName() : "unknown");
        return ResponseEntity.status(HttpStatus.CREATED).body(c);
    }

    @PutMapping("/{id}")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public SubaccountContact update(
            @PathVariable UUID subaccountId,
            @PathVariable UUID id,
            @RequestBody ContactService.ContactPayload body) {
        return service.update(id, body);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable UUID subaccountId, @PathVariable UUID id) {
        service.delete(id);
    }
}
