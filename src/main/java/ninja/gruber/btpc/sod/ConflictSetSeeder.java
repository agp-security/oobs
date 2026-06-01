// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.sod;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

@Component
public class ConflictSetSeeder {

    private static final Logger log = LoggerFactory.getLogger(ConflictSetSeeder.class);
    private static final String RESOURCE_PATH = "rules/builtin-rules.json";

    private final ConflictSetRepo repo;
    private final ObjectMapper mapper;

    public ConflictSetSeeder(ConflictSetRepo repo, ObjectMapper mapper) {
        this.repo = repo;
        this.mapper = mapper;
    }

    @PostConstruct
    @Transactional
    public void seedIfEmpty() {
        int existing = repo.countAll();
        if (existing > 0) {
            log.debug("ConflictSetSeeder: {} rule(s) already present, skipping seed", existing);
            return;
        }
        JsonNode root = readCatalog();
        JsonNode rules = root.path("rules");
        if (!rules.isArray()) {
            log.warn("ConflictSetSeeder: '{}' has no 'rules' array - nothing to seed", RESOURCE_PATH);
            return;
        }
        int loaded = 0;
        for (JsonNode rule : rules) {
            try {
                repo.insert(
                        rule.path("name").asText(),
                        textOrNull(rule, "description"),
                        rule.path("severity").asText("medium"),
                        rule.path("kind").asText("sod"),
                        readStringList(rule.path("roleCollections")),
                        rule.has("thresholdCount") && !rule.get("thresholdCount").isNull()
                                ? rule.get("thresholdCount").asInt()
                                : null,
                        rule.path("scopeLevel").asText("subaccount"),
                        "system:seeder"
                );
                loaded++;
            } catch (Exception e) {
                log.warn("ConflictSetSeeder: failed to insert '{}': {}",
                        rule.path("name").asText("?"), e.getMessage());
            }
        }
        log.info("ConflictSetSeeder: seeded {} of {} bundled risk rules", loaded, rules.size());
    }

    private JsonNode readCatalog() {
        try (InputStream in = new ClassPathResource(RESOURCE_PATH).getInputStream()) {
            return mapper.readTree(in);
        } catch (Exception e) {
            throw new IllegalStateException("ConflictSetSeeder: failed to read " + RESOURCE_PATH, e);
        }
    }

    private static List<String> readStringList(JsonNode n) {
        List<String> out = new ArrayList<>();
        if (n != null && n.isArray()) {
            for (JsonNode el : n) if (el.isTextual()) out.add(el.asText());
        }
        return out;
    }

    private static String textOrNull(JsonNode parent, String field) {
        JsonNode v = parent.path(field);
        return v.isTextual() ? v.asText() : null;
    }
}
