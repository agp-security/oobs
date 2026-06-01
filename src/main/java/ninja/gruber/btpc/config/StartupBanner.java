// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.Arrays;

@Component
public class StartupBanner {

    private static final Logger log = LoggerFactory.getLogger(StartupBanner.class);

    private final Environment env;
    private final boolean devAuthEnabled;

    public StartupBanner(Environment env,
                         @Value("${btpc.dev-auth.enabled:false}") boolean devAuthEnabled) {
        this.env = env;
        this.devAuthEnabled = devAuthEnabled;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onReady() {
        String[] profiles = env.getActiveProfiles();
        String profileStr = profiles.length == 0 ? "default" : String.join(",", profiles);
        log.info("==== ossb ====");
        log.info("  active profiles : {}", profileStr);
        if(devAuthEnabled)
            log.info("  UI              : http://localhost:{}/ui/", env.getProperty("server.port", "8080"));
        log.info("===============================");
    }
}
