// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.certinventory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ninja.gruber.btpc.domain.CredentialKind;
import ninja.gruber.btpc.domain.Subaccount;
import ninja.gruber.btpc.enroll.SubaccountService;
import ninja.gruber.btpc.iastenant.domain.IasTenant;
import ninja.gruber.btpc.iastenant.IasTenantService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;
import java.util.NoSuchElementException;

@Service
public class CertificateInventoryService {

    private static final Logger log = LoggerFactory.getLogger(CertificateInventoryService.class);
    private static final int EXPIRING_SOON_DAYS = 30; //notification threshold

    private final IasTenantService iasTenants;
    private final SubaccountService subaccounts;
    private final ObjectMapper mapper;

    public CertificateInventoryService(IasTenantService iasTenants,
                                       SubaccountService subaccounts,
                                       ObjectMapper mapper) {
        this.iasTenants = iasTenants;
        this.subaccounts = subaccounts;
        this.mapper = mapper;
    }

    public List<CertEntry> list() {
        List<CertEntry> out = new ArrayList<>();
        for (IasTenant t : iasTenants.list()) {
            out.add(loadIasCert(t));
        }
        for (Subaccount sa : subaccounts.list()) {
            out.add(loadCfCert(sa));
        }
        return out;
    }

    private CertEntry loadCert(byte[] credsJson, String source, String systemId, String displayName, String host) throws Exception {
        JsonNode root = mapper.readTree(credsJson);
        String p12Base64 = optString(root, "p12Base64");
        if (p12Base64.isEmpty()) {
            return new CertEntry(source, systemId, displayName, host, null, null, null, null,
                    "failed",
                    "no 'p12Base64' field in stored creds (legacy clientsecret/PEM binding?)");
        }
        String p12Password = optString(root, "p12Password");
        X509Certificate cert = firstCertFromP12(p12Base64, p12Password);
        return toCertEntry(source, systemId, displayName, host, cert);
    }

    private CertEntry loadIasCert(IasTenant t) {
        try {
            byte[] credsJson = iasTenants.decryptCreds(t.id());
            return loadCert(credsJson, "ias", t.id().toString(), t.displayName(), t.iasHost());
        } catch (Exception e) {
            log.warn("Cert inventory: IAS tenant {} unparseable: {}", t.id(), e.getMessage());
            return new CertEntry("ias", t.id().toString(), t.displayName(), t.iasHost(), null, null, null, null,
                    "failed", e.getMessage());
        }
    }

    private CertEntry loadCfCert(Subaccount sa) {
        try {
            byte[] credsJson = subaccounts.decryptCredential(sa.id(), CredentialKind.CF_TECHNICAL_USER);
            return loadCert(credsJson, "cf", sa.id().toString(), sa.cisDisplayName(), "");
        } catch (Exception e) {
            log.warn("Cert inventory: CF cred decrypt failed for {}: {}", sa.id(), e.getMessage());
            return new CertEntry("cf", sa.id().toString(), sa.cisDisplayName(), null, null, null, null, null, "failed",
                    "decrypt  (is a cf user attached to the subaccount): " + e.getMessage());
        }
    }

    private static X509Certificate firstCertFromP12(String p12Base64, String p12Password) throws Exception {
        byte[] p12 = Base64.getDecoder().decode(p12Base64);
        char[] pw = p12Password == null ? new char[0] : p12Password.toCharArray();
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new ByteArrayInputStream(p12), pw);
        for (Enumeration<String> a = ks.aliases(); a.hasMoreElements(); ) {
            java.security.cert.Certificate c = ks.getCertificate(a.nextElement());
            if (c instanceof X509Certificate x) return x;
        }
        throw new IllegalStateException("P12 contains no X.509 certificate");
    }

    private CertEntry toCertEntry(String source, String id, String label, String sublabel,
                              X509Certificate cert) {
        OffsetDateTime notAfter = cert.getNotAfter().toInstant().atOffset(ZoneOffset.UTC);
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        long days = ChronoUnit.DAYS.between(now, notAfter);
        String status;
        if (days < 0) status = "expired";
        else if (days <= EXPIRING_SOON_DAYS) status = "expiring";
        else status = "ok";
        return new CertEntry(source, id, label, sublabel,
                cert.getSubjectX500Principal().getName(),
                cert.getNotBefore().toInstant().atOffset(ZoneOffset.UTC).toString(),
                notAfter.toString(),
                days, status, null);
    }

    private static String optString(JsonNode node, String field) {
        JsonNode v = node.path(field);
        return v.isTextual() ? v.asText() : "";
    }

    public record CertEntry(
            String source,
            String system_id,
            String label,
            String sublabel,
            String subject,
            String notBefore,
            String notAfter,
            Long daysUntilExpiry,
            String status,
            String error
    ) {}
}
