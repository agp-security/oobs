// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.discovery;

import ninja.gruber.btpc.audit.IAuditForward;
import ninja.gruber.btpc.audit.IAuditForward.ActorSource;
import ninja.gruber.btpc.audit.IAuditForward.AuditEvent;
import ninja.gruber.btpc.audit.IAuditForward.Outcome;
import ninja.gruber.btpc.cis.CisClient;
import ninja.gruber.btpc.cis.domain.SubaccountCandidate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;

@Service
public class DiscoveryService {

    private static final Logger log = LoggerFactory.getLogger(DiscoveryService.class);

    private final CentralKeyService keys;
    private final DiscoveredSubaccountRepo candidates;
    private final CisClient cis;
    private final IAuditForward audit;

    public DiscoveryService(CentralKeyService keys, DiscoveredSubaccountRepo candidates,
                            CisClient cis, IAuditForward audit) {
        this.keys = keys;
        this.candidates = candidates;
        this.cis = cis;
        this.audit = audit;
    }

    public SyncResult syncOne(UUID centralKeyId, String actor, ActorSource source) {
        keys.get(centralKeyId);
        try {
            byte[] raw = keys.decrypt(centralKeyId);
            List<SubaccountCandidate> remote = cis.listSubaccounts(new String(raw, StandardCharsets.UTF_8));
            int upserts = 0;
            UUID inferredGa = null;
            String inferredGaName = null;
            for (SubaccountCandidate c : remote) {
                UUID guid = safeUuid(c.guid());
                if (guid == null) continue;
                UUID parentGuid = safeUuid(c.parentGuid());
                UUID gaGuid = safeUuid(c.globalAccountGuid());
                if (gaGuid != null && inferredGa == null) inferredGa = gaGuid;
                candidates.upsert(
                        centralKeyId, guid, c.displayName(), c.subdomain(), c.region(),
                        c.parentType(), parentGuid, gaGuid,
                        c.state(), c.stateMessage(),
                        c.betaEnabled(), c.usedForProduction(), c.description());
                upserts++;
            }
            keys.recordSyncSuccess(centralKeyId, upserts, inferredGa, inferredGaName);
            audit.record(new AuditEvent(
                    UUID.randomUUID(), null, IAuditForward.SystemType.INTERNAL, "", null,
                    "enroll", actor, source, Outcome.OK, null,
                    Map.of("op", "discovery_sync",
                            "centralKeyId", centralKeyId.toString(),
                            "upserts", upserts)));
            log.info("Sync OK key={} upserts={}", centralKeyId, upserts);
            return new SyncResult(centralKeyId, true, upserts, null);
        } catch (NoSuchElementException e) {
            throw e;
        } catch (RuntimeException e) {
            log.warn("Sync FAILED key={}: {}", centralKeyId, e.getMessage());
            keys.recordSyncFailure(centralKeyId, e.getMessage());
            audit.record(new AuditEvent(
                    UUID.randomUUID(), null, IAuditForward.SystemType.INTERNAL, "", null,
                    "enroll", actor, source, Outcome.FAILED, e.getMessage(),
                    Map.of("op", "discovery_sync", "centralKeyId", centralKeyId.toString())));
            return new SyncResult(centralKeyId, false, 0, e.getMessage());
        }
    }

    private static UUID safeUuid(String s) {
        if (s == null || s.isBlank()) return null;
        try { return UUID.fromString(s); }
        catch (Exception e) { return null; }
    }

    public record SyncResult(UUID centralKeyId, boolean ok, int upserts, String error) {}
}
