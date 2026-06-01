// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.web;

import org.jooq.DSLContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.jooq.impl.DSL.inline;

@RestController
@RequestMapping("/api/v1")
public class HealthController {

    private final DSLContext dsl;
    private final String appVersion;
    private final Environment environment;
    private final boolean devAuthEnabled;

    public HealthController(DSLContext dsl,
                            @Value("${btpc.version:dev}") String appVersion,
                            @Value("${btpc.dev-auth.enabled:false}") boolean devAuthEnabled,
                            Environment environment) {
        this.dsl = dsl;
        this.appVersion = appVersion;
        this.environment = environment;
        this.devAuthEnabled = devAuthEnabled;
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "ok");
        out.put("version", appVersion);
        List<String> profiles = Arrays.asList(environment.getActiveProfiles());
        out.put("profiles", profiles.isEmpty() ? List.of("default") : profiles);
        out.put("devAuthEnabled", devAuthEnabled);
        Integer one = dsl.select(inline(1)).fetchOne(0, Integer.class); //SELECT 1
        if (one == null || one != 1) throw new RuntimeException("db check failed");
        return out;
    }
}
