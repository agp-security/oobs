// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.health;

import ninja.gruber.btpc.audit.IAuditForward;
import ninja.gruber.btpc.audit.IAuditForward.ActorSource;
import ninja.gruber.btpc.audit.IAuditForward.AuditEvent;
import ninja.gruber.btpc.audit.IAuditForward.Outcome;
import ninja.gruber.btpc.audit.IAuditForward.SystemType;
import ninja.gruber.btpc.cf.CfApiClient;
import ninja.gruber.btpc.cis.CisClient;
import ninja.gruber.btpc.discovery.CentralKeyService;
import ninja.gruber.btpc.discovery.domain.CentralViewerKey;
import ninja.gruber.btpc.domain.CredentialKind;
import ninja.gruber.btpc.domain.Subaccount;
import ninja.gruber.btpc.enroll.SubaccountService;
import ninja.gruber.btpc.iam.IasClient;
import ninja.gruber.btpc.iam.XsuaaScimClient;
import ninja.gruber.btpc.iastenant.IasTenantService;
import ninja.gruber.btpc.iastenant.domain.IasTenant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;

// Token-acquisition probes for every credential the orchestrator can reach.
// One audit row per probe (action='health_check', outcome=OK|FAILED) so the
// existing Postgres + Splunk HEC + BTP Audit Log fan-out picks them up with
// no extra wiring. The scheduled job (ScheduledHealthCheckJob) calls
// runAll() on a cadence read from app_config; the UI Run-now button hits
// the same path through HealthCheckController.
@Service
public class HealthCheckService {

    private static final Logger log = LoggerFactory.getLogger(HealthCheckService.class);

    private final SubaccountService subaccounts;
    private final IasTenantService tenants;
    private final CentralKeyService centralKeys;
    private final CisClient cis;
    private final XsuaaScimClient xsuaa;
    private final CfApiClient cf;
    private final IasClient ias;
    private final IAuditForward audit;

    public HealthCheckService(SubaccountService subaccounts, IasTenantService tenants,
                              CentralKeyService centralKeys,
                              CisClient cis, XsuaaScimClient xsuaa, CfApiClient cf,
                              IasClient ias, IAuditForward audit) {
        this.subaccounts = subaccounts;
        this.tenants = tenants;
        this.centralKeys = centralKeys;
        this.cis = cis;
        this.xsuaa = xsuaa;
        this.cf = cf;
        this.ias = ias;
        this.audit = audit;
    }

    public Report runAll(String actor, ActorSource source) {
        UUID correlationId = UUID.randomUUID();
        OffsetDateTime startedAt = OffsetDateTime.now();
        List<SubaccountReport> saReports = new ArrayList<>();
        for (Subaccount sa : subaccounts.list()) {
            // CIS now lives only at the global-account level (CentralKeyService
            // manages central-viewer keys); the perCentralKey section probes
            // each central key once. Per-subaccount we probe the two credential
            // kinds that can be attached.
            List<ProbeResult> probes = new ArrayList<>();
            probes.add(probeSubaccount(sa, CredentialKind.XSUAA_APIACCESS, "xsuaa_apiaccess",
                    xsuaa::ping, correlationId, actor, source));
            probes.add(probeSubaccount(sa, CredentialKind.CF_TECHNICAL_USER, "cf_technical_user",
                    cf::obtainToken, correlationId, actor, source));
            saReports.add(new SubaccountReport(sa.id(), sa.cisDisplayName(), probes));
        }
        List<TenantReport> tenantReports = new ArrayList<>();
        for (IasTenant t : tenants.list()) {
            ProbeResult p = probeTenant(t, correlationId, actor, source);
            tenantReports.add(new TenantReport(t.id(), t.displayName(), t.iasHost(), p));
        }
        List<CentralKeyReport> centralReports = new ArrayList<>();
        for (CentralViewerKey k : centralKeys.list()) {
            ProbeResult p = probeCentralKey(k, correlationId, actor, source);
            centralReports.add(new CentralKeyReport(k.id(), k.label(),
                    k.globalAccountName(), p));
        }
        int totalProbes = saReports.stream().mapToInt(r -> r.probes().size()).sum()
                + tenantReports.size() + centralReports.size();
        int okProbes = (int) (saReports.stream().flatMap(r -> r.probes().stream())
                .filter(p -> "ok".equals(p.outcome())).count()
                + tenantReports.stream().filter(t -> "ok".equals(t.probe().outcome())).count()
                + centralReports.stream().filter(c -> "ok".equals(c.probe().outcome())).count());
        log.info("health-check correlation={} probes={} ok={} failed={}",
                correlationId, totalProbes, okProbes, totalProbes - okProbes);
        return new Report(correlationId, startedAt, OffsetDateTime.now(),
                saReports, tenantReports, centralReports, totalProbes, okProbes);
    }

    private ProbeResult probeCentralKey(CentralViewerKey k, UUID correlationId,
                                        String actor, ActorSource source) {
        String credJson;
        try {
            credJson = new String(centralKeys.decrypt(k.id()), StandardCharsets.UTF_8);
        } catch (NoSuchElementException e) {
            audit.record(new AuditEvent(correlationId, k.id().toString(), SystemType.INTERNAL,
                    null, null, "health_check", actor, source, Outcome.SKIPPED, null,
                    Map.of("kind", "cis_central", "centralKeyId", k.id().toString(),
                            "reason", "key disappeared mid-run")));
            return new ProbeResult("cis_central", "skipped", "key disappeared mid-run", 0L);
        }
        long start = System.nanoTime();
        try {
            cis.ping(credJson);
            long ms = (System.nanoTime() - start) / 1_000_000L;
            audit.record(new AuditEvent(correlationId, k.id().toString(), SystemType.INTERNAL,
                    null, null, "health_check", actor, source, Outcome.OK, null,
                    Map.of("kind", "cis_central",
                            "centralKeyId", k.id().toString(),
                            "label", String.valueOf(k.label()),
                            "latencyMs", ms)));
            return new ProbeResult("cis_central", "ok", "token round-trip succeeded", ms);
        } catch (Exception e) {
            long ms = (System.nanoTime() - start) / 1_000_000L;
            String msg = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("kind", "cis_central");
            details.put("centralKeyId", k.id().toString());
            details.put("latencyMs", ms);
            details.put("error", msg);
            audit.record(new AuditEvent(correlationId, k.id().toString(), SystemType.INTERNAL,
                    null, null, "health_check", actor, source, Outcome.FAILED, msg, details));
            return new ProbeResult("cis_central", "failed", msg, ms);
        }
    }

    private ProbeResult probeSubaccount(Subaccount sa, CredentialKind kind, String kindLabel,
                                        ProbeFn fn, UUID correlationId,
                                        String actor, ActorSource source) {
        String credJson;
        try {
            credJson = new String(subaccounts.decryptCredential(sa.id(), kind),
                    StandardCharsets.UTF_8);
        } catch (NoSuchElementException e) {
            // No credential attached for this kind. Not a failure - just
            // record an audit row with outcome=SKIPPED so the operator can
            // tell "never tried" from "tried and failed".
            audit.record(new AuditEvent(correlationId, sa.id().toString(), SystemType.SUBACCOUNT,
                    null, null, "health_check", actor, source, Outcome.SKIPPED, null,
                    Map.of("kind", kindLabel, "reason", "no credential attached")));
            return new ProbeResult(kindLabel, "skipped", "no credential attached", 0L);
        }
        long start = System.nanoTime();
        try {
            fn.run(credJson);
            long ms = (System.nanoTime() - start) / 1_000_000L;
            audit.record(new AuditEvent(correlationId, sa.id().toString(), SystemType.SUBACCOUNT,
                    null, null, "health_check", actor, source, Outcome.OK, null,
                    Map.of("kind", kindLabel, "latencyMs", ms)));
            return new ProbeResult(kindLabel, "ok", "token round-trip succeeded", ms);
        } catch (Exception e) {
            long ms = (System.nanoTime() - start) / 1_000_000L;
            String msg = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("kind", kindLabel);
            details.put("latencyMs", ms);
            details.put("error", msg);
            audit.record(new AuditEvent(correlationId, sa.id().toString(), SystemType.SUBACCOUNT,
                    null, null, "health_check", actor, source, Outcome.FAILED, msg, details));
            return new ProbeResult(kindLabel, "failed", msg, ms);
        }
    }

    private ProbeResult probeTenant(IasTenant t, UUID correlationId,
                                    String actor, ActorSource source) {
        String credJson;
        try {
            credJson = new String(tenants.decryptCreds(t.id()), StandardCharsets.UTF_8);
        } catch (NoSuchElementException e) {
            audit.record(new AuditEvent(correlationId, t.id().toString(), SystemType.IAS,
                    null, null, "health_check", actor, source, Outcome.SKIPPED, null,
                    Map.of("kind", "ias", "iasTenantId", t.id().toString(),
                            "reason", "tenant disappeared mid-run")));
            return new ProbeResult("ias", "skipped", "tenant disappeared mid-run", 0L);
        }
        long start = System.nanoTime();
        try {
            ias.ping(credJson);
            long ms = (System.nanoTime() - start) / 1_000_000L;
            audit.record(new AuditEvent(correlationId, t.id().toString(), SystemType.IAS,
                    null, null, "health_check", actor, source, Outcome.OK, null,
                    Map.of("kind", "ias",
                            "iasTenantId", t.id().toString(),
                            "iasHost", t.iasHost(),
                            "latencyMs", ms)));
            return new ProbeResult("ias", "ok", "SCIM probe succeeded", ms);
        } catch (Exception e) {
            long ms = (System.nanoTime() - start) / 1_000_000L;
            String msg = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("kind", "ias");
            details.put("iasTenantId", t.id().toString());
            details.put("iasHost", t.iasHost());
            details.put("latencyMs", ms);
            details.put("error", msg);
            audit.record(new AuditEvent(correlationId, t.id().toString(), SystemType.IAS,
                    null, null, "health_check", actor, source, Outcome.FAILED, msg, details));
            return new ProbeResult("ias", "failed", msg, ms);
        }
    }

    @FunctionalInterface
    private interface ProbeFn { void run(String credJson); }

    public record Report(UUID correlationId, OffsetDateTime startedAt, OffsetDateTime finishedAt,
                         List<SubaccountReport> perSubaccount, List<TenantReport> perTenant,
                         List<CentralKeyReport> perCentralKey,
                         int totalProbes, int okProbes) {}

    public record SubaccountReport(UUID subaccountId, String displayName,
                                   List<ProbeResult> probes) {}

    public record TenantReport(UUID tenantId, String displayName, String iasHost,
                               ProbeResult probe) {}

    public record CentralKeyReport(UUID centralKeyId, String label, String globalAccountName,
                                   ProbeResult probe) {}

    public record ProbeResult(String kind, String outcome, String message, long latencyMs) {}
}
