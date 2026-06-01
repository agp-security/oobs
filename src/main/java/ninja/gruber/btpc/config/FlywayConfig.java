// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.flyway.FlywayMigrationStrategy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FlywayConfig {

    private static final Logger log = LoggerFactory.getLogger(FlywayConfig.class);

    /**
     * Default strategy is a plain {@code migrate()} (which validates first) - so schema drift stays a
     * hard startup failure, per the project's "drift must not sneak past" doctrine.
     *
     * <p>Set {@code btpc.flyway.repair-on-start=true} (env {@code BTPC_FLYWAY_REPAIR_ON_START=true})
     * for a SINGLE deploy to run {@code repair()} before {@code migrate()}. This realigns the
     * {@code flyway_schema_history} checksums to the migration files on disk - the correct fix when an
     * already-applied migration was edited in a way that doesn't change its semantics (e.g. comments
     * removed). Unset the flag and redeploy once the app is healthy, otherwise genuine drift would be
     * silently repaired away on every boot.
     */
    @Bean
    FlywayMigrationStrategy flywayMigrationStrategy(
            @Value("${btpc.flyway.repair-on-start:false}") boolean repairOnStart) {
        return flyway -> {
            if (repairOnStart) {
                log.warn("btpc.flyway.repair-on-start=true -> running Flyway repair() before migrate() "
                        + "to realign schema-history checksums. UNSET this flag and redeploy once the "
                        + "app is healthy to restore strict drift validation.");
                flyway.repair();
            }
            flyway.migrate();
        };
    }
}
