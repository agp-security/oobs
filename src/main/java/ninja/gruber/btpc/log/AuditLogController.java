// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.log;

import ninja.gruber.btpc.config.MethodSecurityConfig;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/logs")
public class AuditLogController {

    /**mainly for the UI**/

    private static final DateTimeFormatter STAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");

    private final AuditLogService service;

    public AuditLogController(AuditLogService service) {
        this.service = service;
    }

    @GetMapping
    @PreAuthorize(MethodSecurityConfig.VIEWER)
    public List<Map<String, Object>> list(
            @RequestParam(required = false) String action,
            @RequestParam(required = false) String outcome,
            @RequestParam(required = false) String actor,
            @RequestParam(required = false) String targetEmail,
            @RequestParam(required = false) String fromDate,
            @RequestParam(required = false) String toDate,
            @RequestParam(required = false) UUID   subaccountId,
            @RequestParam(required = false) String systemType,
            @RequestParam(required = false) UUID   iasTenantId,
            @RequestParam(defaultValue = "100") int limit) {
        int safe = Math.clamp(limit, 1, 1000);
        return service.list(criteria(action, outcome, actor, targetEmail,
                fromDate, toDate, subaccountId, systemType, iasTenantId), safe);
    }

    @GetMapping("/export")
    @PreAuthorize(MethodSecurityConfig.VIEWER)
    public ResponseEntity<StreamingResponseBody> export(
            @RequestParam(defaultValue = "csv") String format,
            @RequestParam(required = false) String action,
            @RequestParam(required = false) String outcome,
            @RequestParam(required = false) String actor,
            @RequestParam(required = false) String targetEmail,
            @RequestParam(required = false) String fromDate,
            @RequestParam(required = false) String toDate,
            @RequestParam(required = false) UUID   subaccountId,
            @RequestParam(required = false) String systemType,
            @RequestParam(required = false) UUID   iasTenantId,
            @RequestParam(defaultValue = "10000") int limit) {
        int safe = Math.clamp(limit, 1, 100_000);
        AuditLogService.FilterCriteria c = criteria(action, outcome, actor, targetEmail,
                fromDate, toDate, subaccountId, systemType, iasTenantId);
        String stamp = STAMP.format(OffsetDateTime.now());
        boolean json = "json".equalsIgnoreCase(format);

        StreamingResponseBody body = json
                ? out -> service.streamJson(c, safe, out)
                : out -> service.streamCsv(c, safe, out);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"audit-events-" + stamp + (json ? ".json" : ".csv") + "\"")
                .contentType(json
                        ? MediaType.APPLICATION_JSON
                        : MediaType.parseMediaType("text/csv; charset=utf-8"))
                .body(body);
    }

    private static AuditLogService.FilterCriteria criteria(String action, String outcome, String actor,
                                                           String targetEmail, String fromDate, String toDate,
                                                           UUID subaccountId, String systemType, UUID iasTenantId) {
        return new AuditLogService.FilterCriteria(action, outcome, actor, targetEmail,
                fromDate, toDate, subaccountId, systemType, iasTenantId);
    }
}
