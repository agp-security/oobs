// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.sod;

import ninja.gruber.btpc.domain.ConflictSet;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class SodEngineEvaluateTest {

    private static final Set<String> NO_DOMAINS = Set.of();

    @Test
    void sod_firesOnTwoOrMoreMatches() {
        ConflictSet rule = rule("sod", List.of("RC_A", "RC_B", "RC_C"), null);
        assertThat(SodEngine.evaluate(rule, "u@x", Set.of("RC_A", "RC_X"), NO_DOMAINS)).isNull();
        assertThat(SodEngine.evaluate(rule, "u@x", Set.of("RC_A", "RC_B"), NO_DOMAINS))
                .containsExactlyInAnyOrder("RC_A", "RC_B");
        assertThat(SodEngine.evaluate(rule, "u@x", Set.of("RC_A", "RC_B", "RC_C"), NO_DOMAINS))
                .containsExactlyInAnyOrder("RC_A", "RC_B", "RC_C");
    }

    @Test
    void critical_firesOnAnySingleMatch() {
        ConflictSet rule = rule("critical", List.of("RC_DANGER", "RC_DANGER2"), null);
        assertThat(SodEngine.evaluate(rule, "u@x", Set.of("RC_SAFE"), NO_DOMAINS)).isNull();
        assertThat(SodEngine.evaluate(rule, "u@x", Set.of("RC_DANGER"), NO_DOMAINS))
                .containsExactly("RC_DANGER");
    }

    @Test
    void threshold_countsAllRcsWhenFilterEmpty() {
        ConflictSet rule = rule("threshold", List.of(), 3);
        assertThat(SodEngine.evaluate(rule, "u@x", Set.of("RC_1", "RC_2"), NO_DOMAINS)).isNull();
        assertThat(SodEngine.evaluate(rule, "u@x", Set.of("RC_1", "RC_2", "RC_3"), NO_DOMAINS))
                .containsExactlyInAnyOrder("RC_1", "RC_2", "RC_3");
    }

    @Test
    void threshold_countsOnlyFilteredRcsWhenFilterSet() {
        ConflictSet rule = rule("threshold", List.of("RC_ADMIN_A", "RC_ADMIN_B", "RC_ADMIN_C"), 2);
        assertThat(SodEngine.evaluate(rule, "u@x",
                Set.of("RC_ADMIN_A", "RC_OTHER1", "RC_OTHER2"), NO_DOMAINS)).isNull();
        assertThat(SodEngine.evaluate(rule, "u@x",
                Set.of("RC_ADMIN_A", "RC_ADMIN_B", "RC_OTHER1"), NO_DOMAINS))
                .containsExactlyInAnyOrder("RC_ADMIN_A", "RC_ADMIN_B");
    }

    // external_email kind
    @Test
    void externalEmail_perRuleAllowList_flagsExternal() {
        ConflictSet rule = rule("external_email", List.of("contoso.com", "agp-security.com"), null);
        assertThat(SodEngine.evaluate(rule, "alice@contoso.com", Set.of(), NO_DOMAINS)).isNull();
        assertThat(SodEngine.evaluate(rule, "bob@external.example", Set.of(), NO_DOMAINS))
                .containsExactly("external: @external.example");
    }

    @Test
    void externalEmail_globalFallbackUsedWhenRuleListEmpty() {
        ConflictSet rule = rule("external_email", List.of(), null);
        Set<String> global = Set.of("contoso.com");
        assertThat(SodEngine.evaluate(rule, "alice@contoso.com", Set.of(), global)).isNull();
        assertThat(SodEngine.evaluate(rule, "bob@evil.example", Set.of(), global))
                .containsExactly("external: @evil.example");
    }

    @Test
    void externalEmail_skippedWhenNoAllowListAnywhere() {
        ConflictSet rule = rule("external_email", List.of(), null);
        // No per-rule list, no global config - engine has no basis to classify.
        assertThat(SodEngine.evaluate(rule, "anyone@anywhere", Set.of(), NO_DOMAINS)).isNull();
    }

    @Test
    void externalEmail_caseInsensitiveDomainCompare() {
        ConflictSet rule = rule("external_email", List.of("Contoso.Com"), null);
        assertThat(SodEngine.evaluate(rule, "Alice@CONTOSO.COM", Set.of(), NO_DOMAINS)).isNull();
    }

    @Test
    void externalEmail_invalidEmailFlagged() {
        ConflictSet rule = rule("external_email", List.of("contoso.com"), null);
        // No '@' at all
        assertThat(SodEngine.evaluate(rule, "not-an-email", Set.of(), NO_DOMAINS))
                .containsExactly("invalid-email: not-an-email");
        // Empty after '@'
        assertThat(SodEngine.evaluate(rule, "alice@", Set.of(), NO_DOMAINS))
                .containsExactly("invalid-email: alice@");
    }

    @Test
    void externalEmail_leadingAtInAllowListIsStripped() {
        ConflictSet rule = rule("external_email", List.of("@contoso.com"), null);
        assertThat(SodEngine.evaluate(rule, "alice@contoso.com", Set.of(), NO_DOMAINS)).isNull();
    }

    @Test
    void unknownKind_doesNotFire() {
        ConflictSet rule = rule("nope", List.of("RC_A"), null);
        assertThat(SodEngine.evaluate(rule, "u@x", Set.of("RC_A", "RC_B"), NO_DOMAINS)).isNull();
    }

    @Test
    void nullKind_defaultsToSod() {
        ConflictSet rule = new ConflictSet(
                UUID.randomUUID(), "legacy", null, "high", null,
                List.of("RC_A", "RC_B"), null, true, "subaccount",
                "test", null, null);
        assertThat(SodEngine.evaluate(rule, "u@x", Set.of("RC_A", "RC_B"), NO_DOMAINS))
                .containsExactlyInAnyOrder("RC_A", "RC_B");
    }

    // ---- CSV parsing ----

    @Test
    void parseDomainsCsv_normalisesEntries() {
        assertThat(SodEngine.parseDomainsCsv("Contoso.Com, @AGP-Security.com ,, "))
                .containsExactlyInAnyOrder("contoso.com", "agp-security.com");
        assertThat(SodEngine.parseDomainsCsv("")).isEmpty();
        assertThat(SodEngine.parseDomainsCsv(null)).isEmpty();
    }

    private static ConflictSet rule(String kind, List<String> rcs, Integer threshold) {
        return new ConflictSet(
                UUID.randomUUID(), "test", "test", "high", kind,
                rcs, threshold, true, "subaccount",
                "test", null, null);
    }
}
