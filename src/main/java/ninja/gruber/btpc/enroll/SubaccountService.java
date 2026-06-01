// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.enroll;

import ninja.gruber.btpc.enroll.domain.SubaccountDto;

import ninja.gruber.btpc.audit.IAuditForward;
import ninja.gruber.btpc.audit.IAuditForward.ActorSource;
import ninja.gruber.btpc.audit.IAuditForward.AuditEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import ninja.gruber.btpc.audit.IAuditForward.Outcome;
import ninja.gruber.btpc.cf.CfApiClient;
import ninja.gruber.btpc.crypto.AesGcmBox;
import ninja.gruber.btpc.domain.CredentialKind;
import ninja.gruber.btpc.domain.ParsedServiceKey;
import ninja.gruber.btpc.domain.Subaccount;
import ninja.gruber.btpc.config.UrlAllowlist;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;

@Service
public class SubaccountService {

    private static final Logger log = LoggerFactory.getLogger(SubaccountService.class);

    private final SubaccountRepo repo;
    private final ServiceKeyClassifier classifier;
    private final AesGcmBox crypto;
    private final IAuditForward audit;
    private final UrlAllowlist urlAllowlist;
    private final ObjectMapper mapper;
    private final CfApiClient cf;

    public SubaccountService(SubaccountRepo repo, ServiceKeyClassifier classifier,
                             AesGcmBox crypto, IAuditForward audit,
                             UrlAllowlist urlAllowlist, ObjectMapper mapper,
                             CfApiClient cf) {
        this.repo = repo;
        this.classifier = classifier;
        this.crypto = crypto;
        this.audit = audit;
        this.urlAllowlist = urlAllowlist;
        this.mapper = mapper;
        this.cf = cf;
    }

    @Transactional
    public Subaccount enroll(EnrollRequest req, String actor, ActorSource source) {
        if (req.subaccountGuid == null) {
            throw new IllegalArgumentException(
                    "subaccountGuid is required (pick it from the Discover picker or type it manually).");
        }

        List<ParsedServiceKey> parsed = req.serviceKeys == null ? List.of()
                : req.serviceKeys.stream().map(classifier::classify).toList();

        ParsedServiceKey cisKey = parsed.stream()
                .filter(ParsedServiceKey::isCis)
                .findFirst()
                .orElse(null);

        UUID resolvedGuid = req.subaccountGuid;

        Optional<Subaccount> existing = repo.findByGuid(resolvedGuid);
        if (existing.isPresent()) {
            throw new IllegalStateException(
                    "Subaccount " + resolvedGuid + " is already enrolled (id=" + existing.get().id() + ")");
        }

        String region = blankToNull(req.region);
        if (region == null && cisKey != null) region = cisKey.region();
        if (region == null) region = "unknown";

        String cisDisplayName = blankToNull(req.cisDisplayName);
        if (cisDisplayName == null && cisKey != null) cisDisplayName = cisKey.identityZone();
        if (cisDisplayName == null) cisDisplayName = "Subaccount " + resolvedGuid;

        String label = blankToNull(req.label);
        String stage = validatedStage(req.stage);
        String globalAccountName = blankToNull(req.globalAccountName);
        UUID globalAccountId = req.globalAccountId;

        UUID id = repo.insertSubaccount(
                resolvedGuid, cisDisplayName, label, region,
                globalAccountId, globalAccountName, stage, actor);

        for (ParsedServiceKey p : parsed) {
            if (p.kind() == CredentialKind.IAS) {
                log.info("Enroll {}: ignoring pasted IAS service key - create an IAS tenant " +
                        "and link this subaccount via /api/v1/ias-tenants instead.", id);
                continue;
            }
            wrapAndStore(id, p);
        }

        audit.record(new AuditEvent(
                UUID.randomUUID(), id.toString(), IAuditForward.SystemType.SUBACCOUNT, "", null,
                "enroll", actor, source, Outcome.OK, null,
                Map.of(
                        "cisDisplayName", cisDisplayName,
                        "label", String.valueOf(label),
                        "subaccountGuid", resolvedGuid.toString(),
                        "region", region,
                        "credentialKinds", parsed.stream().map(p -> p.kind().dbValue()).toList(),
                        "discoveredId", String.valueOf(req.discoveredId)
                )));

        return repo.findById(id).orElseThrow();
    }

    @Transactional
    public Subaccount updateLabel(UUID id, String label, String actor, ActorSource source) {
        Subaccount s = get(id);
        String trimmed = blankToNull(label);
        repo.updateLabel(id, trimmed);
        audit.record(new AuditEvent(
                UUID.randomUUID(), id.toString(), IAuditForward.SystemType.SUBACCOUNT, "", null,
                "enroll", actor, source, Outcome.OK, null,
                Map.of("op", "update_label", "label", String.valueOf(trimmed),
                        "previous", String.valueOf(s.label()))));
        return repo.findById(id).orElseThrow();
    }

    @Transactional
    public Subaccount updateMetadata(UUID id, MetadataPatch patch, String actor, ActorSource source) {
        get(id);
        String label = blankToNull(patch.label);
        String gaName = blankToNull(patch.globalAccountName);
        String stage = validatedStage(patch.stage);
        repo.updateMetadata(id, label, patch.globalAccountId, gaName, stage);
        audit.record(new AuditEvent(
                UUID.randomUUID(), id.toString(), IAuditForward.SystemType.SUBACCOUNT, "", null,
                "enroll", actor, source, Outcome.OK, null,
                Map.of("op", "update_metadata",
                        "label", String.valueOf(label),
                        "globalAccountId", String.valueOf(patch.globalAccountId),
                        "globalAccountName", String.valueOf(gaName),
                        "stage", String.valueOf(stage))));
        return repo.findById(id).orElseThrow();
    }

    @Transactional
    public Subaccount quickAdd(QuickAddRequest req, String actor, ActorSource source) {
        if (req.subaccountGuid == null) {
            throw new IllegalArgumentException("subaccountGuid is required for quick-add");
        }
        if (req.cisDisplayName == null || req.cisDisplayName.isBlank()) {
            throw new IllegalArgumentException("name (cisDisplayName) is required for quick-add");
        }
        if (req.region == null || req.region.isBlank()) {
            throw new IllegalArgumentException("region is required for quick-add");
        }
        if (repo.findByGuid(req.subaccountGuid).isPresent()) {
            throw new IllegalStateException(
                    "Subaccount " + req.subaccountGuid + " is already enrolled");
        }
        UUID id = repo.insertSubaccount(
                req.subaccountGuid,
                req.cisDisplayName.trim(),
                blankToNull(req.label),
                req.region.trim(),
                req.globalAccountId,
                blankToNull(req.globalAccountName),
                validatedStage(req.stage),
                actor);
        audit.record(new AuditEvent(
                UUID.randomUUID(), id.toString(), IAuditForward.SystemType.SUBACCOUNT, "", null,
                "enroll", actor, source, Outcome.OK, null,
                Map.of("op", "quick_add", "subaccountGuid", req.subaccountGuid.toString(),
                        "cisDisplayName", req.cisDisplayName,
                        "region", req.region,
                        "noCredential", true)));
        return repo.findById(id).orElseThrow();
    }

    private static String blankToNull(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static final java.util.Set<String> ALLOWED_STAGES =
            java.util.Set.of("prod", "dev", "qa", "test");

    private static String validatedStage(String raw) {
        String v = blankToNull(raw);
        if (v == null) return null;
        String lower = v.toLowerCase(java.util.Locale.ROOT);
        if (!ALLOWED_STAGES.contains(lower)) {
            throw new IllegalArgumentException(
                    "stage must be one of " + ALLOWED_STAGES + " (case-insensitive); got '" + raw + "'");
        }
        return lower;
    }

    @Transactional
    public Subaccount attachCredential(UUID id, String serviceKeyJson,
                                       String actor, ActorSource source) {
        get(id);
        ParsedServiceKey p = classifier.classify(serviceKeyJson);
        if (p.kind() == CredentialKind.CIS) {
            throw new IllegalArgumentException(
                    "CIS is captured at enroll time. Use the XSUAA api-access "
                            + "plan service key here, or the CF technical-user "
                            + "structured dialog. For IAS, use the IAS Tenants section.");
        }
        if (p.kind() == CredentialKind.IAS) {
            throw new IllegalArgumentException(
                    "IAS service keys are managed at the tenant level. Create the IAS tenant in the IAS Tenants tab, "
                            + "then link this subaccount to it.");
        }
        wrapAndStore(id, p);
        audit.record(new AuditEvent(
                UUID.randomUUID(), id.toString(), IAuditForward.SystemType.SUBACCOUNT, "", null,
                "enroll", actor, source, Outcome.OK, null,
                Map.of("op", "attach_credential", "kind", p.kind().dbValue())));
        return repo.findById(id).orElseThrow();
    }

    @Transactional
    public Subaccount setCfOrgId(UUID id, UUID cfOrgId, String actor, ActorSource source) {
        get(id);
        repo.setCfOrgId(id, cfOrgId);
        Map<String, Object> details = new java.util.LinkedHashMap<>();
        details.put("op", "set_cf_org_id");
        details.put("cfOrgId", cfOrgId == null ? null : cfOrgId.toString());
        audit.record(new AuditEvent(
                UUID.randomUUID(), id.toString(), IAuditForward.SystemType.SUBACCOUNT, "", null,
                "enroll", actor, source, Outcome.OK, null, details));
        return repo.findById(id).orElseThrow();
    }

    @Transactional
    public Subaccount attachCfTechnicalUser(UUID id, CfTechnicalUserPayload p,
                                            String actor, ActorSource source) {
        get(id);
        validateCfTechnicalUser(p);
        String json = serialiseCfTechnicalUserJson(p);

        int orgCount;
        try {
            orgCount = cf.listOrganizations(json).size();
        } catch (Exception e) {
            throw new IllegalArgumentException(
                    "CF technical-user smoke test failed: " + e.getMessage()
                            + ". Check cfUaaUrl, cfApiUrl, credentials, "
                            + "and origin (passcode flow). Credential NOT saved.", e);
        }
        if (orgCount == 0) {
            log.warn("CF tech user for subaccount {} saved but /v3/organizations is empty - "
                    + "technical user has no org-level visibility; containment will fail at "
                    + "lookup time. Grant OrgAuditor or OrgManager on the subaccount's CF org.",
                    id);
        }

        wrapAndStore(id, CredentialKind.CF_TECHNICAL_USER, json);
        audit.record(new AuditEvent(
                UUID.randomUUID(), id.toString(), IAuditForward.SystemType.SUBACCOUNT, "", null,
                "enroll", actor, source, Outcome.OK, null,
                Map.of("op", "attach_credential",
                        "kind", CredentialKind.CF_TECHNICAL_USER.dbValue(),
                        "username", String.valueOf(p.username),
                        "smokeTest", "ok",
                        "orgsVisible", orgCount)));
        return repo.findById(id).orElseThrow();
    }

    @Transactional
    public Subaccount copyCfTechnicalUserFrom(UUID targetId, UUID sourceId,
                                              String cfApiUrl, String cfUaaUrl,
                                              String actor, ActorSource source) {
        if (targetId.equals(sourceId)) {
            throw new IllegalArgumentException("target and source must differ");
        }
        get(targetId);
        get(sourceId);
        if (cfApiUrl == null || cfApiUrl.isBlank())
            throw new IllegalArgumentException("cfApiUrl is required");
        if (cfUaaUrl == null || cfUaaUrl.isBlank())
            throw new IllegalArgumentException("cfUaaUrl is required");
        urlAllowlist.requireAllowed(cfApiUrl, "cfApiUrl");
        urlAllowlist.requireAllowed(cfUaaUrl, "cfUaaUrl");

        String srcJson;
        try {
            srcJson = new String(
                    decryptCredential(sourceId, CredentialKind.CF_TECHNICAL_USER),
                    java.nio.charset.StandardCharsets.UTF_8);
        } catch (NoSuchElementException e) {
            throw new IllegalArgumentException(
                    "source subaccount has no CF technical-user credential to copy");
        }

        com.fasterxml.jackson.databind.JsonNode src;
        try { src = mapper.readTree(srcJson); }
        catch (Exception e) { throw new IllegalStateException("source credential is not valid JSON", e); }

        CfTechnicalUserPayload p = new CfTechnicalUserPayload();
        p.cfApiUrl = cfApiUrl.trim();
        p.cfUaaUrl = cfUaaUrl.trim();
        p.username = textOrBlank(src, "username");
        p.origin = textOrBlank(src, "origin");
        p.iasPasscodeUrl = textOrBlank(src, "iasPasscodeUrl");
        p.p12Base64 = textOrBlank(src, "p12Base64");
        p.p12Password = textOrBlank(src, "p12Password");
        validateCfTechnicalUser(p);
        String json = serialiseCfTechnicalUserJson(p);

        int orgCount;
        try {
            orgCount = cf.listOrganizations(json).size();
        } catch (Exception e) {
            throw new IllegalArgumentException(
                    "CF technical-user smoke test failed after copy: " + e.getMessage()
                            + ". Check the new cfApiUrl / cfUaaUrl are valid for this region. "
                            + "Credential NOT saved.", e);
        }

        wrapAndStore(targetId, CredentialKind.CF_TECHNICAL_USER, json);
        audit.record(new AuditEvent(
                UUID.randomUUID(), targetId.toString(), IAuditForward.SystemType.SUBACCOUNT, "", null,
                "enroll", actor, source, Outcome.OK, null,
                Map.of("op", "attach_credential",
                        "kind", CredentialKind.CF_TECHNICAL_USER.dbValue(),
                        "copyFromSubaccountId", sourceId.toString(),
                        "username", String.valueOf(p.username),
                        "smokeTest", "ok",
                        "orgsVisible", orgCount)));
        return repo.findById(targetId).orElseThrow();
    }

    private static String textOrBlank(com.fasterxml.jackson.databind.JsonNode n, String field) {
        com.fasterxml.jackson.databind.JsonNode v = n.path(field);
        return v.isTextual() ? v.asText() : "";
    }

    private void validateCfTechnicalUser(CfTechnicalUserPayload p) {
        if (p == null) throw new IllegalArgumentException("body is required");
        if (p.username == null || p.username.isBlank())
            throw new IllegalArgumentException("username is required");
        if (p.cfApiUrl == null || p.cfApiUrl.isBlank())
            throw new IllegalArgumentException("cfApiUrl is required");
        if (p.cfUaaUrl == null || p.cfUaaUrl.isBlank())
            throw new IllegalArgumentException("cfUaaUrl is required");
        urlAllowlist.requireAllowed(p.cfApiUrl, "cfApiUrl");
        urlAllowlist.requireAllowed(p.cfUaaUrl, "cfUaaUrl");
        if (p.iasPasscodeUrl == null || p.iasPasscodeUrl.isBlank())
            throw new IllegalArgumentException("iasPasscodeUrl is required");
        if (p.p12Base64 == null || p.p12Base64.isBlank())
            throw new IllegalArgumentException("p12Base64 is required");
        if (p.p12Password == null)
            throw new IllegalArgumentException("p12Password is required");
        if (p.origin == null || p.origin.isBlank())
            throw new IllegalArgumentException("origin is required " +
                    "(IAS origin key - what `cf login --origin <key>` would use)");
        urlAllowlist.requireAllowed(p.iasPasscodeUrl, "iasPasscodeUrl");
    }

    private String serialiseCfTechnicalUserJson(CfTechnicalUserPayload p) {
        java.util.LinkedHashMap<String, Object> m = new java.util.LinkedHashMap<>();
        m.put("cfApiUrl", p.cfApiUrl);
        m.put("cfUaaUrl", p.cfUaaUrl);
        m.put("username", p.username);
        m.put("origin", p.origin);
        m.put("iasPasscodeUrl", p.iasPasscodeUrl);
        m.put("p12Base64", p.p12Base64);
        m.put("p12Password", p.p12Password);
        try { return mapper.writeValueAsString(m); }
        catch (Exception e) { throw new IllegalStateException("failed to serialise cf creds", e); }
    }

    public static class CfTechnicalUserPayload {
        public String cfApiUrl;
        public String cfUaaUrl;
        public String username;
        public String origin;  //Trust Config -> *-platform
        public String iasPasscodeUrl;
        public String p12Base64;
        public String p12Password;
    }

    private void wrapAndStore(UUID id, ParsedServiceKey p) {
        wrapAndStore(id, p.kind(), p.rawJson());
    }

    private void wrapAndStore(UUID id, CredentialKind kind, String rawJson) {
        String aad = id + ":" + kind.dbValue();
        AesGcmBox.Wrapped w = crypto.wrap(rawJson.getBytes(StandardCharsets.UTF_8), aad);
        repo.upsertCredential(id, kind, w);
    }

    public List<Subaccount> list() {
        return repo.list();
    }

    public Subaccount get(UUID id) {
        return repo.findById(id)
                .orElseThrow(() -> new NoSuchElementException("subaccount not found: " + id));
    }

    @Transactional
    public void unenroll(UUID id, String actor, ActorSource source) {
        Subaccount s = get(id);
        audit.record(new AuditEvent(
                UUID.randomUUID(), id.toString(), IAuditForward.SystemType.SUBACCOUNT, "", null,
                "unenroll", actor, source, Outcome.OK, null,
                Map.of(
                        "cisDisplayName", String.valueOf(s.cisDisplayName()),
                        "label", String.valueOf(s.label()),
                        "subaccountGuid", s.subaccountGuid().toString()
                )));
        int rows = repo.delete(id);
        if (rows == 0) {
            throw new NoSuchElementException("subaccount not found: " + id);
        }
        log.info("Subaccount {} unenrolled by {}", id, actor);
    }

    @Transactional
    public Subaccount provisionXsuaaApiAccess(UUID subaccountId, String actor, ActorSource source) {
        Subaccount sa = get(subaccountId);
        if (sa.cfOrgId() == null) {
            throw new IllegalStateException(
                    "Cannot import XSUAA key: subaccount has no cf_org_id pinned. "
                            + "Set it in the Edit dialog first.");
        }
        String cfJson;
        try {
            cfJson = new String(decryptCredential(subaccountId, CredentialKind.CF_TECHNICAL_USER),
                    StandardCharsets.UTF_8);
        } catch (NoSuchElementException e) {
            throw new IllegalStateException(
                    "Cannot import XSUAA key: subaccount has no CF technical user attached. "
                            + "Attach one (Edit -> Add CF Technical User) first.");
        }
        String orgGuid = sa.cfOrgId().toString();
        log.info("Import XSUAA: subaccount={} cisDisplay='{}' org={}",
                subaccountId, sa.cisDisplayName(), orgGuid);

        String offeringGuid = cf.findServiceOfferingGuid(cfJson, "xsuaa")
                .orElseThrow(() -> new IllegalStateException(
                        "xsuaa service offering not visible to the technical user. "
                                + "Confirm Service Manager / Cloud Controller permissions."));
        log.info("Import XSUAA: found xsuaa offering guid={}", offeringGuid);
        String planGuid = cf.findServicePlanGuid(cfJson, offeringGuid, "apiaccess")
                .orElseThrow(() -> new IllegalStateException(
                        "xsuaa apiaccess plan not visible to the technical user."));
        log.info("Import XSUAA: found apiaccess plan guid={}", planGuid);

        List<CfApiClient.ServiceInstance> instances =
                cf.findInstancesByPlanInOrg(cfJson, orgGuid, planGuid);
        log.info("Import XSUAA: instances found in org {} = {}", orgGuid,
                instances.stream().map(CfApiClient.ServiceInstance::name).toList());

        String instanceGuid;
        String instanceName;
        boolean createdInstance = false;
        if (!instances.isEmpty()) {
            if (instances.size() > 1) {
                log.warn("Import XSUAA: multiple instances found ({}), picking the first: {}",
                        instances.size(), instances.get(0).name());
            }
            instanceGuid = instances.get(0).guid();
            instanceName = instances.get(0).name();
        } else {
            List<CfApiClient.Space> spaces = cf.listSpaces(cfJson, orgGuid);
            if (spaces.isEmpty()) {
                throw new IllegalStateException(
                        "Cannot create xsuaa:apiaccess: CF org " + orgGuid + " has no spaces. "
                                + "Create one in the BTP cockpit first.");
            }
            spaces.sort((a, b) -> String.valueOf(a.name()).compareTo(String.valueOf(b.name())));
            CfApiClient.Space space = spaces.get(0);
            instanceName = "btpc-xsuaa-apiaccess";
            log.info("Import XSUAA: no instance found, creating '{}' in space '{}' ({})",
                    instanceName, space.name(), space.guid());
            CfApiClient.ProvisionedJob job = cf.createManagedServiceInstance(
                    cfJson, space.guid(), planGuid, instanceName);
            if (!cf.waitForJob(cfJson, job.jobUrl(), 120)) {
                throw new IllegalStateException(
                        "CF did not finish provisioning the service instance within 120s. "
                                + "Check the BTP cockpit for the long-running job.");
            }
            instanceGuid = job.guid() != null ? job.guid()
                    : cf.findManagedServiceInstance(cfJson, space.guid(), instanceName)
                        .orElseThrow(() -> new IllegalStateException(
                                "Service instance created but not findable by name post-job"))
                        .guid();
            createdInstance = true;
            log.info("Import XSUAA: created instance {} ({})", instanceName, instanceGuid);
        }

        List<CfApiClient.ServiceKey> keys = cf.listServiceKeys(cfJson, instanceGuid);
        log.info("Import XSUAA: existing keys on instance '{}' = {}",
                instanceName, keys.stream().map(CfApiClient.ServiceKey::name).toList());

        String keyGuid;
        String keyName;
        boolean createdKey = false;
        if (!keys.isEmpty()) {
            keyGuid = keys.get(0).guid();
            keyName = keys.get(0).name();
            log.info("Import XSUAA: using existing key '{}' (guid={})", keyName, keyGuid);
        } else {
            keyName = "btpc-xsuaa-apiaccess-key";
            log.info("Import XSUAA: no key found on instance, creating '{}'", keyName);
            CfApiClient.ProvisionedJob job = cf.createServiceKey(cfJson, instanceGuid, keyName);
            if (!cf.waitForJob(cfJson, job.jobUrl(), 60)) {
                throw new IllegalStateException(
                        "CF did not finish creating the service key within 60s.");
            }
            keyGuid = job.guid() != null ? job.guid()
                    : cf.findServiceKey(cfJson, instanceGuid, keyName)
                        .orElseThrow(() -> new IllegalStateException(
                                "Service key created but cannot be found by name post-job"))
                        .guid();
            createdKey = true;
            log.info("Import XSUAA: created key {} ({})", keyName, keyGuid);
        }
        CfApiClient.ServiceKey key = new CfApiClient.ServiceKey(keyGuid, keyName);
        CfApiClient.ServiceInstance instance =
                new CfApiClient.ServiceInstance(instanceGuid, instanceName, null);

        String credsJson = cf.getServiceKeyDetails(cfJson, key.guid());
        ParsedServiceKey parsed;
        try {
            parsed = classifier.classify(credsJson);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Fetched service-key credentials don't classify as XSUAA api-access: "
                            + e.getMessage());
        }
        if (parsed.kind() != CredentialKind.XSUAA_APIACCESS) {
            throw new IllegalStateException(
                    "Imported key classifies as " + parsed.kind()
                            + ", not XSUAA_APIACCESS - aborting before overwriting the slot.");
        }
        wrapAndStore(subaccountId, parsed);
        java.util.LinkedHashMap<String, Object> details = new java.util.LinkedHashMap<>();
        details.put("op", "import_xsuaa_apiaccess");
        details.put("kind", CredentialKind.XSUAA_APIACCESS.dbValue());
        details.put("cfOrgId", orgGuid);
        details.put("instanceGuid", instance.guid());
        details.put("instanceName", instance.name());
        details.put("keyGuid", key.guid());
        details.put("keyName", key.name());
        details.put("createdInstance", createdInstance);
        details.put("createdKey", createdKey);
        audit.record(new AuditEvent(
                UUID.randomUUID(), subaccountId.toString(), IAuditForward.SystemType.SUBACCOUNT, "", null,
                "enroll", actor, source, Outcome.OK, null, details));
        log.info("Imported XSUAA api-access credentials for subaccount {}: instance={}, key={}",
                subaccountId, instance.guid(), key.guid());
        return repo.findById(subaccountId).orElseThrow();
    }

    public byte[] decryptCredential(UUID subaccountId, CredentialKind kind) {
        SubaccountRepo.EncryptedCredential c = repo.loadCredential(subaccountId, kind)
                .orElseThrow(() -> new NoSuchElementException(
                        "no " + kind.dbValue() + " credential for subaccount " + subaccountId));
        String aad = subaccountId + ":" + kind.dbValue();
        return crypto.unwrap(c.cipher(), c.nonce(), aad);
    }

    public Map<UUID, java.util.Set<CredentialKind>> capabilities() {
        return repo.capabilitiesByAccount();
    }

    public Map<UUID, Integer> contactCounts() {
        return repo.contactCountByAccount();
    }

    public static class EnrollRequest {
        public String cisDisplayName;
        public String region;
        public UUID subaccountGuid;
        public UUID globalAccountId;
        public String globalAccountName;
        public String stage;
        public String label;
        public List<String> serviceKeys;
        public UUID discoveredId;
    }

    public static class QuickAddRequest {
        public UUID subaccountGuid;
        public String cisDisplayName;
        public String region;
        public UUID globalAccountId;
        public String globalAccountName;
        public String stage;
        public String label;
    }

    public static class MetadataPatch {
        public String label;
        public UUID globalAccountId;
        public String globalAccountName;
        public String stage;
    }
}
