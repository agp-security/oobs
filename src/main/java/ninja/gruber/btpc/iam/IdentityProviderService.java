// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.iam;

import ninja.gruber.btpc.domain.CredentialKind;
import ninja.gruber.btpc.domain.Subaccount;
import ninja.gruber.btpc.enroll.SubaccountService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;

@Service
public class IdentityProviderService {

    private static final Logger log = LoggerFactory.getLogger(IdentityProviderService.class);

    public static final Set<String> RESERVED_ORIGINS =
            Set.of("sap.default", "sap.custom", "ldap", "uaa");

    private final SubaccountService subaccounts;
    private final XsuaaScimClient xsuaa;

    public IdentityProviderService(SubaccountService subaccounts, XsuaaScimClient xsuaa) {
        this.subaccounts = subaccounts;
        this.xsuaa = xsuaa;
    }

    public DiscoverResult discover(List<UUID> subaccountIds) {
        List<Subaccount> selected = (subaccountIds == null || subaccountIds.isEmpty())
                ? subaccounts.list()
                : subaccountIds.stream().map(subaccounts::get).toList();

        Map<String, IdpAggregate> byOrigin = new LinkedHashMap<>();
        List<DiscoverError> errors = new ArrayList<>();
        for (Subaccount sa : selected) {
            String credJson;
            try {
                credJson = new String(
                        subaccounts.decryptCredential(sa.id(), CredentialKind.XSUAA_APIACCESS),
                        StandardCharsets.UTF_8);
            } catch (NoSuchElementException e) {
                errors.add(new DiscoverError(sa.id(), sa.cisDisplayName(),
                        "no XSUAA api-access credential attached"));
                continue;
            }
            try {
                for (XsuaaScimClient.IdentityProvider ip : xsuaa.listIdentityProviders(credJson)) {
                    if (ip.originKey() == null) continue;
                    IdpAggregate agg = byOrigin.computeIfAbsent(ip.originKey(),
                            k -> new IdpAggregate(k, ip.name(), ip.type(), ip.active(), new ArrayList<>()));
                    agg.seenIn().add(sa.cisDisplayName());
                }
            } catch (Exception e) {
                log.warn("identity-providers discovery failed for subaccount {}", sa.id(), e);
                errors.add(new DiscoverError(sa.id(), sa.cisDisplayName(), e.getMessage()));
            }
        }
        return new DiscoverResult(new ArrayList<>(byOrigin.values()), errors);
    }

    public OriginValidation validateOrigins(List<String> originKeys, List<UUID> subaccountIds) {
        DiscoverResult d = discover(subaccountIds);
        Set<String> known = new HashSet<>(RESERVED_ORIGINS);
        for (IdpAggregate a : d.origins()) known.add(a.originKey());
        List<String> unknown = new ArrayList<>();
        for (String k : originKeys) {
            if (k != null && !known.contains(k) && !unknown.contains(k)) unknown.add(k);
        }
        return new OriginValidation(unknown, d.errors().isEmpty(), d.errors());
    }

    public record DiscoverResult(List<IdpAggregate> origins, List<DiscoverError> errors) {}
    public record IdpAggregate(String originKey, String name, String type,
                               Boolean active, List<String> seenIn) {}
    public record DiscoverError(UUID subaccountId, String subaccountDisplayName, String error) {}
    public record OriginValidation(List<String> unknownOrigins, boolean conclusive,
                                   List<DiscoverError> errors) {}
}
