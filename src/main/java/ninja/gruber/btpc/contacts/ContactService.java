// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.contacts;

import ninja.gruber.btpc.domain.SubaccountContact;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;

@Service
public class ContactService {

    private static final Set<String> VALID_ROLES =
            Set.of("security", "ops", "business", "technical", "other");

    private final ContactRepo repo;

    public ContactService(ContactRepo repo) {
        this.repo = repo;
    }

    public SubaccountContact add(UUID subaccountId, ContactPayload p, String actor) {
        validate(p);
        UUID id;
        try {
            id = repo.insert(subaccountId, p.name.trim(), p.email.trim(),
                    p.role, blankToNull(p.notes), actor);
        } catch (DuplicateKeyException e) {
            throw new IllegalStateException(
                    "A contact with email " + p.email + " and role " + p.role +
                            " already exists for this subaccount");
        }
        return repo.findById(id).orElseThrow();
    }

    public SubaccountContact update(UUID id, ContactPayload p) {
        validate(p);//no client concept so everyone entitled through the scopes can change all contacts.
        get(id);
        try {
            repo.update(id, p.name.trim(), p.email.trim(), p.role, blankToNull(p.notes));
        } catch (DuplicateKeyException e) {
            throw new IllegalStateException(
                    "Another contact already exists with email " + p.email +
                            " and role " + p.role + " for this subaccount");
        }
        return repo.findById(id).orElseThrow();
    }

    public void delete(UUID id) {
        get(id);
        repo.delete(id);
    }

    public SubaccountContact get(UUID id) {
        return repo.findById(id)
                .orElseThrow(() -> new NoSuchElementException("contact not found: " + id));
    }

    public List<SubaccountContact> list(UUID subaccountId) {
        return repo.listForSubaccount(subaccountId);
    }

    private void validate(ContactPayload p) {
        if (p == null) throw new IllegalArgumentException("contact payload is required");
        if (p.name == null || p.name.isBlank()) throw new IllegalArgumentException("name is required");
        if (p.email == null || p.email.isBlank()) throw new IllegalArgumentException("email is required");
        if (p.role == null || !VALID_ROLES.contains(p.role)) {
            throw new IllegalArgumentException(
                    "role must be one of " + VALID_ROLES);
        }
    }

    private static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s.trim();
    }

    public static class ContactPayload {
        public String name;
        public String email;
        public String role;
        public String notes;
    }
}
