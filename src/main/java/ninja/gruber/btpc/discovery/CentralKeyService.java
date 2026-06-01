// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.discovery;

import ninja.gruber.btpc.discovery.domain.CentralViewerKey;

import ninja.gruber.btpc.cis.CisClient;
import ninja.gruber.btpc.cis.domain.SubaccountCandidate;
import ninja.gruber.btpc.crypto.AesGcmBox;
import ninja.gruber.btpc.domain.CredentialKind;
import ninja.gruber.btpc.domain.ParsedServiceKey;
import ninja.gruber.btpc.enroll.ServiceKeyClassifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;

@Service
public class CentralKeyService {

    private static final Logger log = LoggerFactory.getLogger(CentralKeyService.class);

    private final CentralKeyRepo repo;
    private final ServiceKeyClassifier classifier;
    private final AesGcmBox crypto;
    private final CisClient cis;

    public CentralKeyService(CentralKeyRepo repo, ServiceKeyClassifier classifier,
                             AesGcmBox crypto, CisClient cis) {
        this.repo = repo;
        this.classifier = classifier;
        this.crypto = crypto;
        this.cis = cis;
    }

    @Transactional
    public CentralViewerKey save(SaveRequest req, String actor) {
        if (req == null || req.serviceKey == null || req.serviceKey.isBlank()) {
            throw new IllegalArgumentException("serviceKey is required");
        }
        ParsedServiceKey parsed = classifier.classify(req.serviceKey);
        if (parsed.kind() != CredentialKind.CIS) {
            throw new IllegalArgumentException(
                    "Only CIS central-viewer service keys can be saved for discovery; got "
                            + parsed.kind().dbValue());
        }
        List<SubaccountCandidate> probe;
        try {
            probe = cis.listSubaccounts(parsed.rawJson());
        } catch (RuntimeException e) {
            throw new IllegalArgumentException(
                    "CIS rejected this key: " + e.getMessage(), e);
        }
        UUID gaGuid = probe.stream()
                .map(SubaccountCandidate::globalAccountGuid)
                .filter(s -> s != null && !s.isBlank())
                .findFirst()
                .map(s -> {
                    try { return UUID.fromString(s); }
                    catch (Exception e) { return null; }
                })
                .orElse(null);
        if (gaGuid != null) {
            Optional<CentralViewerKey> dup = repo.findByGlobalAccountId(gaGuid);
            if (dup.isPresent()) {
                throw new IllegalStateException( // as this is a central plan
                        "Global account " + gaGuid + " already has a saved central-viewer key " +
                                "(id=" + dup.get().id() + "). Update or delete it first.");
            }
        }
        UUID id = UUID.randomUUID();
        String aad = "central-viewer-key:" + id;
        AesGcmBox.Wrapped w = crypto.wrap(parsed.rawJson().getBytes(StandardCharsets.UTF_8), aad);

        int interval = req.syncIntervalMinutes != null ? req.syncIntervalMinutes : 60;
        boolean enabled = req.syncEnabled == null || req.syncEnabled;

        repo.insert(id, gaGuid, blankToNull(req.globalAccountName),
                blankToNull(req.label),
                w.cipher(), w.nonce(),
                interval, enabled, actor);
        log.info("Saved central-viewer key {} (global_account_id={}, interval={}m, enabled={}); " +
                "probe returned {} subaccount(s)", id, gaGuid, interval, enabled, probe.size());
        return repo.findById(id).orElseThrow();
    }

    public List<CentralViewerKey> list() {
        return repo.list();
    }

    public CentralViewerKey get(UUID id) {
        return repo.findById(id)
                .orElseThrow(() -> new NoSuchElementException("central-viewer key not found: " + id));
    }

    public byte[] decrypt(UUID id) {
        CentralKeyRepo.EncryptedKey raw = repo.loadCipher(id)
                .orElseThrow(() -> new NoSuchElementException("central-viewer key not found: " + id));
        return crypto.unwrap(raw.cipher(), raw.nonce(), "central-viewer-key:" + id);
    }

    @Transactional
    public CentralViewerKey updateSettings(UUID id, UpdateRequest req) {
        get(id);  // existence check
        repo.updateSyncSettings(id, req.syncEnabled, req.syncIntervalMinutes,
                req.label == null ? null : req.label.trim());
        return repo.findById(id).orElseThrow();
    }

    @Transactional
    public void delete(UUID id) {
        int rows = repo.delete(id);
        if (rows == 0) throw new NoSuchElementException("central-viewer key not found: " + id);
        log.info("Deleted central-viewer key {}", id);
    }

    public List<CentralViewerKey> findDueForSync() {
        return repo.findDueForSync();
    }

    public void recordSyncSuccess(UUID id, int count, UUID inferredGlobalAccountId,
                                  String inferredGlobalAccountName) {
        repo.recordSyncSuccess(id, count, inferredGlobalAccountId, inferredGlobalAccountName);
    }

    public void recordSyncFailure(UUID id, String errorMessage) {
        repo.recordSyncFailure(id, errorMessage);
    }

    private static String blankToNull(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    public static class SaveRequest {
        public String serviceKey;
        public String label;
        public String globalAccountName;
        public Integer syncIntervalMinutes;
        public Boolean syncEnabled;
    }

    public static class UpdateRequest {
        public Boolean syncEnabled;
        public Integer syncIntervalMinutes;
        public String label;
    }
}
