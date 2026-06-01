// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.audit.custom;

import ninja.gruber.btpc.audit.custom.domain.AuditSinkConfig;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ninja.gruber.btpc.crypto.AesGcmBox;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;

@Service
public class AuditSinkService {

    private final AuditSinkConfigRepo repo;
    private final AesGcmBox crypto;
    private final ObjectMapper mapper;

    public AuditSinkService(AuditSinkConfigRepo repo, AesGcmBox crypto, ObjectMapper mapper) {
        this.repo = repo;
        this.crypto = crypto;
        this.mapper = mapper;
    }

    public List<AuditSinkConfig> list() { return repo.list(); }

    public Optional<AuditSinkConfig> find(AuditSinkConfig.Kind kind) {
        return repo.findByKind(kind);
    }

    @Transactional
    public AuditSinkConfig upsert(AuditSinkConfig.Kind kind, boolean enabled,
                                  JsonNode config, String secret, String actor) {
        AesGcmBox.Wrapped wrapped = null;
        if (secret != null && !secret.isBlank()) { //only if new secret input -> also possible to toggle with existing secret
            wrapped = crypto.wrap(secret.getBytes(StandardCharsets.UTF_8), aadFor(kind));
        }
        repo.upsert(kind, enabled, config == null ? mapper.createObjectNode() : config,
                wrapped, actor);
        return repo.findByKind(kind).orElseThrow();
    }

    @Transactional
    public void delete(AuditSinkConfig.Kind kind) {
        repo.delete(kind);
    }

    public Optional<String> decryptSecret(AuditSinkConfig.Kind kind) {
        return repo.loadSecret(kind).map(s ->
                new String(crypto.unwrap(s.cipher(), s.nonce(), aadFor(kind)),
                        StandardCharsets.UTF_8));
    }

    public void recordTestResult(AuditSinkConfig.Kind kind, boolean ok, String message) {
        repo.recordTestResult(kind, ok ? "ok" : "failed", message);
    }

    public AuditSinkConfig getOrThrow(AuditSinkConfig.Kind kind) {
        return repo.findByKind(kind).orElseThrow(() ->
                new NoSuchElementException("audit sink " + kind.dbValue() + " not configured"));
    }

    private static String aadFor(AuditSinkConfig.Kind kind) {
        return "audit_sink:" + kind.dbValue();
    }
}
