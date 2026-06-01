// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.enroll;

import ninja.gruber.btpc.enroll.domain.SubaccountDto;

import ninja.gruber.btpc.audit.IAuditForward.ActorSource;
import ninja.gruber.btpc.config.MethodSecurityConfig;
import ninja.gruber.btpc.domain.Subaccount;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/subaccounts")
public class SubaccountController {

    private final SubaccountService service;

    public SubaccountController(SubaccountService service) {
        this.service = service;
    }

    @PostMapping
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public ResponseEntity<SubaccountDto> enroll(
            @RequestBody SubaccountService.EnrollRequest req,
            Authentication auth,
            @RequestHeader(value = "X-Caller-Source", required = false) String sourceHeader) {
        Subaccount s = service.enroll(req, actorOf(auth), parseSource(sourceHeader));
        return ResponseEntity.status(HttpStatus.CREATED).body(singleDto(s));
    }

    @GetMapping
    @PreAuthorize(MethodSecurityConfig.VIEWER)
    public List<SubaccountDto> list() {
        return SubaccountDto.fromAll(service.list(), service.capabilities(), service.contactCounts());
    }

    @GetMapping("/{id}")
    @PreAuthorize(MethodSecurityConfig.VIEWER)
    public SubaccountDto get(@PathVariable UUID id) {
        return singleDto(service.get(id));
    }

    @PatchMapping("/{id}/label")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public SubaccountDto updateLabel(
            @PathVariable UUID id,
            @RequestBody LabelPatch body,
            Authentication auth,
            @RequestHeader(value = "X-Caller-Source", required = false) String sourceHeader) {
        return singleDto(service.updateLabel(id, body == null ? null : body.label,
                actorOf(auth), parseSource(sourceHeader)));
    }

    @PatchMapping("/{id}/metadata")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public SubaccountDto updateMetadata(
            @PathVariable UUID id,
            @RequestBody SubaccountService.MetadataPatch body,
            Authentication auth,
            @RequestHeader(value = "X-Caller-Source", required = false) String sourceHeader) {
        return singleDto(service.updateMetadata(id, body, actorOf(auth), parseSource(sourceHeader)));
    }

    /**
     * manual add no ck-viewer
     * @return
     */
    @PostMapping("/quick-add")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public ResponseEntity<SubaccountDto> quickAdd(
            @RequestBody SubaccountService.QuickAddRequest req,
            Authentication auth,
            @RequestHeader(value = "X-Caller-Source", required = false) String sourceHeader) {
        return ResponseEntity.status(HttpStatus.CREATED).body(
                singleDto(service.quickAdd(req, actorOf(auth), parseSource(sourceHeader))));
    }

    @PostMapping("/{id}/credentials")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public SubaccountDto attachCredential(
            @PathVariable UUID id,
            @RequestBody AttachCredential body,
            Authentication auth,
            @RequestHeader(value = "X-Caller-Source", required = false) String sourceHeader) {
        if (body == null || body.serviceKey == null || body.serviceKey.isBlank()) {
            throw new IllegalArgumentException("serviceKey is required");
        }
        return singleDto(service.attachCredential(id, body.serviceKey,
                actorOf(auth), parseSource(sourceHeader)));
    }

    @PatchMapping("/{id}/cf-org-id")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public SubaccountDto setCfOrgId(
            @PathVariable UUID id,
            @RequestBody SetCfOrgIdBody body,
            Authentication auth,
            @RequestHeader(value = "X-Caller-Source", required = false) String sourceHeader) {
        return singleDto(service.setCfOrgId(id, body.cfOrgId,
                actorOf(auth), parseSource(sourceHeader)));
    }

    public static class SetCfOrgIdBody { public UUID cfOrgId; }

    @PostMapping("/{id}/cf-technical-user")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public SubaccountDto attachCfTechnicalUser(
            @PathVariable UUID id,
            @RequestBody SubaccountService.CfTechnicalUserPayload body,
            Authentication auth,
            @RequestHeader(value = "X-Caller-Source", required = false) String sourceHeader) {
        return singleDto(service.attachCfTechnicalUser(id, body,
                actorOf(auth), parseSource(sourceHeader)));
    }

    @PostMapping("/{id}/cf-technical-user/copy-from/{sourceId}")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public SubaccountDto copyCfTechnicalUser(
            @PathVariable UUID id,
            @PathVariable UUID sourceId,
            @RequestBody CopyCfTechUserBody body,
            Authentication auth,
            @RequestHeader(value = "X-Caller-Source", required = false) String sourceHeader) {
        return singleDto(service.copyCfTechnicalUserFrom(id, sourceId,
                body.cfApiUrl, body.cfUaaUrl,
                actorOf(auth), parseSource(sourceHeader)));
    }

    public static class CopyCfTechUserBody {
        public String cfApiUrl;
        public String cfUaaUrl;
    }

    @PostMapping("/{id}/provision-xsuaa-apiaccess")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public SubaccountDto provisionXsuaa(
            @PathVariable UUID id,
            Authentication auth,
            @RequestHeader(value = "X-Caller-Source", required = false) String sourceHeader) {
        return singleDto(service.provisionXsuaaApiAccess(id,
                actorOf(auth), parseSource(sourceHeader)));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(
            @PathVariable UUID id,
            Authentication auth,
            @RequestHeader(value = "X-Caller-Source", required = false) String sourceHeader) {
        service.unenroll(id, actorOf(auth), parseSource(sourceHeader));
    }

    private SubaccountDto singleDto(Subaccount s) {
        return SubaccountDto.from(s,
                service.capabilities().getOrDefault(s.id(), java.util.EnumSet.noneOf(ninja.gruber.btpc.domain.CredentialKind.class)),
                service.contactCounts().getOrDefault(s.id(), 0));
    }

    private static String actorOf(Authentication auth) {
        return auth != null && auth.getName() != null ? auth.getName() : "unknown";
    }

    private static ActorSource parseSource(String header) {
        if (header == null || header.isBlank()) return ActorSource.UI;
        return switch (header.toLowerCase()) {
            case "soar", "soar-api" -> ActorSource.SOAR_API;
            case "system" -> ActorSource.SYSTEM;
            default -> ActorSource.UI;
        };
    }

    public static class LabelPatch {
        public String label;
    }

    public static class AttachCredential {
        public String serviceKey;
    }
}
