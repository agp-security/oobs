// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.iastenant;

import ninja.gruber.btpc.iastenant.domain.IasTenant;

import com.fasterxml.jackson.databind.ObjectMapper;
import ninja.gruber.btpc.crypto.AesGcmBox;
import ninja.gruber.btpc.config.UrlAllowlist;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;

@Service
public class IasTenantService {

    private final IasTenantRepo repo;
    private final AesGcmBox crypto;
    private final ObjectMapper mapper;
    private final UrlAllowlist urlAllowlist;

    public IasTenantService(IasTenantRepo repo, AesGcmBox crypto, ObjectMapper mapper,
                            UrlAllowlist urlAllowlist) {
        this.repo = repo;
        this.crypto = crypto;
        this.mapper = mapper;
        this.urlAllowlist = urlAllowlist;
    }

    @Transactional
    public IasTenant create(CreatePayload p, String actor) {
        validate(p);
        String host = hostOf(p.url);
        if (repo.findByHost(host).isPresent()) {
            throw new IllegalArgumentException(
                    "IAS tenant already exists for host " + host
                            + " - edit it instead of creating a duplicate.");
        }
        String json = serialise(p);
        AesGcmBox.Wrapped wrapped = crypto.wrap(json.getBytes(StandardCharsets.UTF_8),
                aadFor(host));
        UUID id = repo.insert(p.displayName.trim(), host, wrapped, actor);
        return repo.findById(id).orElseThrow();
    }

    @Transactional
    public IasTenant updateMeta(UUID id, String displayName, String actor) {
        if (displayName == null || displayName.isBlank()) {
            throw new IllegalArgumentException("displayName is required");
        }
        if (repo.updateMeta(id, displayName.trim(), actor) == 0) {
            throw new NoSuchElementException("IAS tenant " + id + " not found");
        }
        return repo.findById(id).orElseThrow();
    }

    @Transactional
    public IasTenant updateCreds(UUID id, CreatePayload p, String actor) {
        validate(p);
        IasTenant existing = repo.findById(id)
                .orElseThrow(() -> new NoSuchElementException("IAS tenant " + id + " not found"));
        String host = hostOf(p.url);
        if (!existing.iasHost().equals(host)) {
            throw new IllegalArgumentException(
                    "credential URL host (" + host + ") doesn't match tenant host ("
                            + existing.iasHost() + "). Create a new tenant instead.");
        }
        String json = serialise(p);
        AesGcmBox.Wrapped wrapped = crypto.wrap(json.getBytes(StandardCharsets.UTF_8),
                aadFor(host));
        repo.updateCreds(id, wrapped, actor);
        return repo.findById(id).orElseThrow();
    }

    public List<IasTenant> list() { return repo.list(); }

    public IasTenant get(UUID id) {
        return repo.findById(id)
                .orElseThrow(() -> new NoSuchElementException("IAS tenant " + id + " not found"));
    }

    @Transactional
    public void delete(UUID id, String actor) {
        if (repo.delete(id) == 0) {
            throw new NoSuchElementException("IAS tenant " + id + " not found");
        }
    }
    
    public byte[] decryptCreds(UUID id) {
        IasTenant t = get(id);
        IasTenantRepo.EncryptedCreds c = repo.loadCreds(id)
                .orElseThrow(() -> new IllegalStateException(
                        "missing encrypted_creds row for IAS tenant: " + id));
        return crypto.unwrap(c.cipher(), c.nonce(), aadFor(t.iasHost()));
    }

    private String serialise(CreatePayload p) {
        LinkedHashMap<String, Object> m = new LinkedHashMap<>();
        m.put("url", p.url.trim());
        m.put("p12Base64", p.p12Base64);
        m.put("p12Password", p.p12Password == null ? "" : p.p12Password);
        try { return mapper.writeValueAsString(m); }
        catch (Exception e) { throw new IllegalStateException("failed to serialise IAS creds", e); }
    }

    private void validate(CreatePayload p) {
        if (p == null) throw new IllegalArgumentException("body is required");
        if (p.displayName == null || p.displayName.isBlank())
            throw new IllegalArgumentException("displayName is required");
        if (p.url == null || p.url.isBlank())
            throw new IllegalArgumentException("url is required");
        if (p.p12Base64 == null || p.p12Base64.isBlank())
            throw new IllegalArgumentException("p12Base64 is required "
                    + "(upload the .p12 from the X509_GENERATED IAS Application binding)");
        if (!p.p12Base64.matches("^[A-Za-z0-9+/=\\s]+$"))
            throw new IllegalArgumentException(
                    "p12Base64 must be a base64-encoded PKCS#12 blob "
                            + "(the dialog handles the file -> base64 conversion)");
        urlAllowlist.requireAllowed(p.url, "url");
    }

    private static String aadFor(String host) {
        return "ias_tenant:" + host;
    }

    static String hostOf(String url) {
        try {
            String host = URI.create(url.trim()).getHost();
            if (host == null || host.isBlank()) {
                throw new IllegalArgumentException("url has no host: " + url);
            }
            return host.toLowerCase();
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid url: " + url, e);
        }
    }

    public static class CreatePayload {
        public String displayName;
        public String url;
        public String p12Base64;
        public String p12Password;
    }
}
