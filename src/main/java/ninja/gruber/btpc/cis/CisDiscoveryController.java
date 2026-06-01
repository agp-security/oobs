// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.cis;
import ninja.gruber.btpc.cis.domain.SubaccountCandidate;

import ninja.gruber.btpc.config.MethodSecurityConfig;
import ninja.gruber.btpc.domain.CredentialKind;
import ninja.gruber.btpc.domain.ParsedServiceKey;
import ninja.gruber.btpc.enroll.ServiceKeyClassifier;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/cis")
public class CisDiscoveryController {

    private final CisClient cis;
    private final ServiceKeyClassifier classifier;

    public CisDiscoveryController(CisClient cis, ServiceKeyClassifier classifier) {
        this.cis = cis;
        this.classifier = classifier;
    }

    /**
     * Ad-hoc discover...
     */
    @PostMapping("/discover")
    @PreAuthorize(MethodSecurityConfig.ADMIN)
    public DiscoverResponse discover(@RequestBody DiscoverRequest req) {
        if (req == null || req.serviceKey == null || req.serviceKey.isBlank()) {
            throw new IllegalArgumentException("serviceKey is required");
        }
        ParsedServiceKey parsed = classifier.classify(req.serviceKey);
        if (parsed.kind() != CredentialKind.CIS) {
            throw new IllegalArgumentException(
                    "Discovery requires a CIS central-viewer service key; got "
                            + parsed.kind().dbValue());
        }
        List<SubaccountCandidate> candidates = cis.listSubaccounts(req.serviceKey);
        return new DiscoverResponse(candidates.size(), candidates);
    }

    public static class DiscoverRequest {
        public String serviceKey;
    }

    public record DiscoverResponse(int count, List<SubaccountCandidate> subaccounts) {}
}
