// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.appconfig;

import ninja.gruber.btpc.config.MethodSecurityConfig;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/app-config")
public class AppConfigController {

    private final AppConfigService service;

    public AppConfigController(AppConfigService service) {
        this.service = service;
    }

    /**
     * return config values as key:val map
     */
    @GetMapping
    @PreAuthorize(MethodSecurityConfig.VIEWER)
    public Map<String, KeyState> list() {
        Map<String, KeyState> out = new LinkedHashMap<>();
        String emailCsv = service.getExternalEmailDomainsCsv();
        Long healthConfigInterval = service.getHealthAutoIntervalSeconds();
        out.put(AppConfigService.KEY_EXTERNAL_EMAIL_DOMAINS,
                new KeyState(emailCsv, !emailCsv.isEmpty()));
        out.put(AppConfigService.KEY_HEALTH_AUTO_INTERVAL_SECONDS,
                new KeyState(String.valueOf(healthConfigInterval), healthConfigInterval!=0));
        return out;
    }

    /**
     * update the whitelisted keys
     */
    @PutMapping("/{key}")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public KeyState put(
            @PathVariable String key,
            @RequestBody UpdateBody body,
            Authentication auth) {
        service.putWhitelisted(key, body.value, auth.getName());
        return new KeyState(currentValue(key), true);
    }

    private String currentValue(String key) {
        if (AppConfigService.KEY_EXTERNAL_EMAIL_DOMAINS.equals(key)) {
            return service.getExternalEmailDomainsCsv();
        }else if(AppConfigService.KEY_HEALTH_AUTO_INTERVAL_SECONDS.equals(key)){
            return String.valueOf(service.getHealthAutoIntervalSeconds());
        }
        throw new IllegalArgumentException("wrong key for global acc config supplied");
    }

    public record KeyState(String value, boolean overridden) {}

    public static class UpdateBody {
        public String value;
    }
}
