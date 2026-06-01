// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.flyway;

import ninja.gruber.btpc.support.TestcontainersConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@Import(TestcontainersConfiguration.class)
class FlywayMigrationsTest {

    @Autowired
    JdbcTemplate jdbc;

    @Test
    void allTablesExistAfterMigrate() {
        List<String> expected = List.of(
                "subaccounts",
                "subaccount_credentials",
                "containment_events",
                "action_snapshots",
                "conflict_sets",
                "protected_users",
                "subaccount_contacts",
                "central_viewer_keys",
                "discovered_subaccounts",
                "app_config",
                "ias_tenants",
                "audit_sinks",
                "origin_profiles"
        );
        for (String t : expected) {
            Integer count = jdbc.queryForObject(
                    "SELECT count(*)::int FROM information_schema.tables " +
                            "WHERE table_schema = 'public' AND table_name = ?",
                    Integer.class, t);
            assertThat(count)
                    .withFailMessage("expected table %s to exist after Flyway migrate", t)
                    .isEqualTo(1);
        }
    }

    @Test
    void flywayRecordedAllMigrations() {
        Integer migrations = jdbc.queryForObject(
                "SELECT count(*)::int FROM flyway_schema_history WHERE success = true",
                Integer.class);
        // V1__schema.sql is the baseline; V2__drop_protected_user_ias_id.sql and
        // V3__action_snapshots_system_id.sql were added on top. Bump this count
        // whenever a new V*.sql is committed to db/migration/.
        assertThat(migrations).isEqualTo(3);
    }
}
