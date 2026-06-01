// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.iam;

import ninja.gruber.btpc.domain.CredentialKind;
import ninja.gruber.btpc.domain.Subaccount;
import ninja.gruber.btpc.enroll.SubaccountService;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IdentityProviderServiceTest {

    private final SubaccountService subaccounts = mock(SubaccountService.class);
    private final XsuaaScimClient xsuaa = mock(XsuaaScimClient.class);
    private final IdentityProviderService svc = new IdentityProviderService(subaccounts, xsuaa);

    private static Subaccount sa(UUID id) {
        return new Subaccount(id, UUID.randomUUID(), "Acme Prod", null, "prod", "us10",
                UUID.randomUUID(), "Acme GA", "production", "tester", null, null, null,
                "active", UUID.randomUUID());
    }

    private void discoveryReturns(UUID saId, String... originKeys) {
        when(subaccounts.list()).thenReturn(List.of(sa(saId)));
        when(subaccounts.decryptCredential(eq(saId), eq(CredentialKind.XSUAA_APIACCESS)))
                .thenReturn("{}".getBytes(StandardCharsets.UTF_8));
        List<XsuaaScimClient.IdentityProvider> idps = new java.util.ArrayList<>();
        for (String k : originKeys) {
            idps.add(new XsuaaScimClient.IdentityProvider(k, k + " IdP", "saml", true));
        }
        when(xsuaa.listIdentityProviders(any())).thenReturn(idps);
    }

    @Test
    void discoveredAndReservedOrigins_areKnown_garbageIsFlagged() {
        UUID saId = UUID.randomUUID();
        discoveryReturns(saId, "corp-saml", "azuread");

        IdentityProviderService.OriginValidation v = svc.validateOrigins(
                List.of("corp-saml", "sap.default", "uaa", "ldap", "totally-bogus"), null);

        assertThat(v.conclusive()).isTrue();
        // discovered (corp-saml) + reserved built-ins (sap.default/uaa/ldap) all pass;
        // only the garbage key is reported.
        assertThat(v.unknownOrigins()).containsExactly("totally-bogus");
    }

    @Test
    void inactiveIdp_isStillKnown() {
        UUID saId = UUID.randomUUID();
        when(subaccounts.list()).thenReturn(List.of(sa(saId)));
        when(subaccounts.decryptCredential(eq(saId), eq(CredentialKind.XSUAA_APIACCESS)))
                .thenReturn("{}".getBytes(StandardCharsets.UTF_8));
        when(xsuaa.listIdentityProviders(any())).thenReturn(List.of(
                new XsuaaScimClient.IdentityProvider("legacy-idp", "Legacy", "oidc", false)));

        IdentityProviderService.OriginValidation v =
                svc.validateOrigins(List.of("legacy-idp"), null);

        assertThat(v.unknownOrigins()).isEmpty();
    }

    @Test
    void discoveryError_isInconclusive_soCallerCanFailOpen() {
        UUID saId = UUID.randomUUID();
        when(subaccounts.list()).thenReturn(List.of(sa(saId)));
        when(subaccounts.decryptCredential(eq(saId), eq(CredentialKind.XSUAA_APIACCESS)))
                .thenThrow(new NoSuchElementException("no XSUAA credential"));

        IdentityProviderService.OriginValidation v =
                svc.validateOrigins(List.of("anything"), null);

        assertThat(v.conclusive()).isFalse();
        assertThat(v.errors()).hasSize(1);
        assertThat(v.unknownOrigins()).containsExactly("anything");
    }

    @Test
    void duplicateUnknownKeys_areReportedOnce() {
        discoveryReturns(UUID.randomUUID(), "corp-saml");

        IdentityProviderService.OriginValidation v =
                svc.validateOrigins(List.of("bogus", "bogus", "corp-saml"), null);

        assertThat(v.unknownOrigins()).containsExactly("bogus");
    }
}
