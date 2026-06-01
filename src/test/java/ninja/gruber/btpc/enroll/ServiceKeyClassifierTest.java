// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.enroll;

import com.fasterxml.jackson.databind.ObjectMapper;
import ninja.gruber.btpc.domain.CredentialKind;
import ninja.gruber.btpc.domain.ParsedServiceKey;
import ninja.gruber.btpc.config.UrlAllowlist;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ServiceKeyClassifierTest {

    private final ServiceKeyClassifier classifier = new ServiceKeyClassifier(
            new ObjectMapper(),
            // Allow real BTP hosts so the unit fixtures (which use realistic
            // URLs like *.authentication.eu10.hana.ondemand.com) pass through.
            new UrlAllowlist(".hana.ondemand.com,.cloud.sap,.accounts.ondemand.com,.trial-accounts.ondemand.com"));

    @Test
    void classifiesCisCentralPlan() {
        String json = """
                {
                  "sap.cloud.service": "com.sap.core.commercial.service.central",
                  "endpoints": { "accounts_service_url": "https://accounts-service.cfapps.eu10.hana.ondemand.com" },
                  "uaa": {
                    "subaccountid": "00000000-0000-4000-8000-000000000002",
                    "url": "https://73e9ab73trial-ga.authentication.eu10.hana.ondemand.com",
                    "xsmasterappname": "cis-central!b14",
                    "identityzone": "73e9ab73trial-ga"
                  }
                }
                """;
        ParsedServiceKey p = classifier.classify(json);
        assertThat(p.kind()).isEqualTo(CredentialKind.CIS);
        assertThat(p.subaccountGuid()).isNull();   // central plan: subaccountid is the hosting one, not a target
        assertThat(p.region()).isEqualTo("eu10");
        assertThat(p.identityZone()).isEqualTo("73e9ab73trial-ga");
    }

    @Test
    void rejectsCisLocalPlan() {
        // Local-plan CIS keys are no longer supported - the classifier should
        // identify them as CIS but reject the local plan explicitly.
        String json = """
                {
                  "sap.cloud.service": "com.sap.core.commercial.service.local",
                  "endpoints": { "accounts_service_url": "https://accounts-service.cfapps.eu10.hana.ondemand.com" },
                  "uaa": {
                    "subaccountid": "00000000-0000-4000-8000-000000000001",
                    "url": "https://73e9ab73trial.authentication.us10.hana.ondemand.com",
                    "xsmasterappname": "cis-local!b4"
                  }
                }
                """;
        assertThatThrownBy(() -> classifier.classify(json))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("CIS local-plan keys are no longer supported");
    }

    @Test
    void classifiesIas() {
        String json = """
                {
                  "btp-tenant-api": "https://api.authentication.us10.hana.ondemand.com",
                  "app_tid": "00000000-0000-4000-8000-000000000001",
                  "clientid": "x",
                  "clientsecret": "y",
                  "url": "https://aym2kpzp4.trial-accounts.ondemand.com",
                  "domain": "accounts.ondemand.com"
                }
                """;
        ParsedServiceKey p = classifier.classify(json);
        assertThat(p.kind()).isEqualTo(CredentialKind.IAS);
        assertThat(p.subaccountGuid()).hasToString("00000000-0000-4000-8000-000000000001");
        assertThat(p.region()).isEqualTo("us10");
    }

    @Test
    void classifiesXsuaaApiaccess_nestedUnderUaa() {
        // Legacy binding shape: credentials inside a uaa{} block.
        String json = """
                {
                  "uaa": {
                    "clientid": "x",
                    "clientsecret": "y",
                    "url": "https://73e9ab73trial.authentication.us10.hana.ondemand.com",
                    "apiurl": "https://api.authentication.us10.hana.ondemand.com",
                    "identityzone": "73e9ab73trial",
                    "subaccountid": "00000000-0000-4000-8000-000000000001"
                  }
                }
                """;
        ParsedServiceKey p = classifier.classify(json);
        assertThat(p.kind()).isEqualTo(CredentialKind.XSUAA_APIACCESS);
        assertThat(p.region()).isEqualTo("us10");
        assertThat(p.subaccountGuid()).hasToString("00000000-0000-4000-8000-000000000001");
    }

    @Test
    void classifiesXsuaaApiaccess_flatRoot() {
        // Modern binding shape - fields at the root of the JSON, no uaa{} wrapper.
        // This is what BTP currently issues for the api-access plan.
        String json = """
                {
                  "clientid": "xyz",
                  "clientsecret": "zzzz",
                  "url": "https://73e9ab73trial.authentication.us10.hana.ondemand.com",
                  "identityzone": "73e9ab73trial",
                  "identityzoneid": "00000000-0000-4000-8000-000000000001",
                  "tenantid": "00000000-0000-4000-8000-000000000001",
                  "tenantmode": "dedicated",
                  "sburl": "https://internal-xsuaa.authentication.us10.hana.ondemand.com",
                  "apiurl": "https://api.authentication.us10.hana.ondemand.com",
                  "xsappname": "na-00000000-0000-4000-8000-000000000003!a000001",
                  "subaccountid": "00000000-0000-4000-8000-000000000001",
                  "uaadomain": "authentication.us10.hana.ondemand.com",
                  "zoneid": "00000000-0000-4000-8000-000000000001"
                }
                """;
        ParsedServiceKey p = classifier.classify(json);
        assertThat(p.kind()).isEqualTo(CredentialKind.XSUAA_APIACCESS);
        assertThat(p.region()).isEqualTo("us10");
        assertThat(p.subaccountGuid()).hasToString("00000000-0000-4000-8000-000000000001");
        assertThat(p.identityZone()).isEqualTo("73e9ab73trial");
    }

    @Test
    void rejectsUnknownShape() {
        assertThatThrownBy(() -> classifier.classify("{\"hello\": \"world\"}"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unrecognised service key shape");
    }

    @Test
    void rejectsInvalidJson() {
        assertThatThrownBy(() -> classifier.classify("not json"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not valid JSON");
    }
}
