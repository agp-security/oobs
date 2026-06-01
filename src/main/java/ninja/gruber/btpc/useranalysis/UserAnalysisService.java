// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.useranalysis;

import ninja.gruber.btpc.cf.CfApiClient;
import ninja.gruber.btpc.domain.CredentialKind;
import ninja.gruber.btpc.domain.Subaccount;
import ninja.gruber.btpc.enroll.SubaccountService;
import ninja.gruber.btpc.iam.IasClient;
import ninja.gruber.btpc.iam.XsuaaScimClient;
import ninja.gruber.btpc.iastenant.domain.IasTenant;
import ninja.gruber.btpc.iastenant.IasTenantService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Service
public class UserAnalysisService {

    private static final Logger log = LoggerFactory.getLogger(UserAnalysisService.class);

    private final SubaccountService subaccounts;
    private final IasTenantService iasTenants;
    private final IasClient ias;
    private final XsuaaScimClient xsuaa;
    private final CfApiClient cf;

    public UserAnalysisService(SubaccountService subaccounts, IasTenantService iasTenants,
                               IasClient ias, XsuaaScimClient xsuaa, CfApiClient cf) {
        this.subaccounts = subaccounts;
        this.iasTenants = iasTenants;
        this.ias = ias;
        this.xsuaa = xsuaa;
        this.cf = cf;
    }

    public AnalysisReport analyze(String email) {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("email is required");
        }
        String e = email.trim();
        log.info("User analysis: starting walk for {}", e);

        List<TenantSection> tenantSections = new ArrayList<>();
        Map<UUID, String> iasUserIdByTenant = new HashMap<>();
        Map<UUID, Set<String>> iasGroupNamesByTenant = new HashMap<>();

        for (IasTenant t : iasTenants.list()) {
            TenantSection.Builder tb = new TenantSection.Builder(t.id(), t.displayName(), t.iasHost());
            try {
                String iasJson = new String(iasTenants.decryptCreds(t.id()), StandardCharsets.UTF_8);
                Optional<IasClient.IasUser> u = ias.findUserByEmail(iasJson, e);
                if (u.isEmpty()) {
                    tb.userFound = false;
                    tenantSections.add(tb.build());
                    continue;
                }
                tb.userFound = true;
                tb.iasUserId = u.get().id();
                tb.iasUserActive = u.get().active();
                tb.givenName = u.get().givenName();
                tb.familyName = u.get().familyName();
                iasUserIdByTenant.put(t.id(), tb.iasUserId);

                List<IasClient.IasGroupRef> groups = ias.listUserGroups(iasJson, tb.iasUserId);
                Set<String> names = new HashSet<>();
                for (IasClient.IasGroupRef g : groups) {
                    tb.iasGroups.add(new IasGroupRow(g.id(), g.displayName()));
                    if (g.displayName() != null) names.add(g.displayName());
                }
                iasGroupNamesByTenant.put(t.id(), names);
            } catch (Exception ex) {
                log.warn("User analysis: IAS tenant {} lookup failed: {}", t.id(), ex.getMessage());
                tb.error = ex.getMessage();
            }
            tenantSections.add(tb.build());
        }

        List<SubaccountSection> saSections = new ArrayList<>();
        for (Subaccount sa : subaccounts.list()) {
            SubaccountSection.Builder sb = new SubaccountSection.Builder(sa.id(),
                    sa.cisDisplayName(), sa.region());
            String xsuaaJson = tryDecrypt(sa.id(), CredentialKind.XSUAA_APIACCESS);
            if (xsuaaJson != null) {
                walkXsuaa(sa, xsuaaJson, e, iasUserIdByTenant, iasGroupNamesByTenant, sb);
            } else {
                sb.errors.add("no XSUAA api-access credential attached");
            }
            String cfJson = tryDecrypt(sa.id(), CredentialKind.CF_TECHNICAL_USER);
            if (cfJson != null && sa.cfOrgId() != null) {
                walkCf(sa, cfJson, e, sb);
            } else if (cfJson != null) {
                sb.errors.add("CF tech user attached but cf_org_id not pinned");
            }
            saSections.add(sb.build());
        }

        log.info("User analysis: done for {} ({} tenants, {} subaccounts)",
                e, tenantSections.size(), saSections.size());
        return new AnalysisReport(e, tenantSections, saSections);
    }

    private String tryDecrypt(UUID subaccountId, CredentialKind kind) {
        try {
            return new String(subaccounts.decryptCredential(subaccountId, kind),
                    StandardCharsets.UTF_8);
        } catch (NoSuchElementException ex) {
            return null;
        }
    }

    private void walkXsuaa(Subaccount sa, String xsuaaJson, String email,
                           Map<UUID, String> iasUserIdByTenant,
                           Map<UUID, Set<String>> iasGroupNamesByTenant,
                           SubaccountSection.Builder sb) {
        List<XsuaaScimClient.ShadowUser> shadows;
        try {
            shadows = xsuaa.findShadowUsersByEmail(xsuaaJson, email);
        } catch (Exception ex) {
            sb.errors.add("XSUAA SCIM lookup failed: " + ex.getMessage());
            return;
        }
        if (shadows.isEmpty()) return;
        for (XsuaaScimClient.ShadowUser s : shadows) {
            sb.shadowUsers.add(new ShadowUserRow(s.id(), s.origin()));
        }
        Set<String> shadowIds = new HashSet<>();
        for (XsuaaScimClient.ShadowUser s : shadows) {
            if (s.id() != null) shadowIds.add(s.id());
        }

        try {
            for (XsuaaScimClient.Group g : xsuaa.listGroups(xsuaaJson)) {
                if (g.displayName() == null) continue;
                for (XsuaaScimClient.Member m : g.members()) {
                    if (m.userId() != null && shadowIds.contains(m.userId())) {
                        sb.directRcs.add(new DirectRcRow(g.displayName(), m.origin()));
                        break;
                    }
                }
            }
        } catch (Exception ex) {
            sb.errors.add("XSUAA /Groups walk failed: " + ex.getMessage());
        }

        Set<String> userGroupNames = new HashSet<>();
        for (Set<String> names : iasGroupNamesByTenant.values()) {
            userGroupNames.addAll(names);
        }
        log.info("Mapping walk[{}]: user IAS groups (union across {} tenant(s)) = {}",
                sa.cisDisplayName(), iasGroupNamesByTenant.size(), userGroupNames);
        if (userGroupNames.isEmpty()) {
            sb.errors.add("Mapping walk skipped: user has no IAS groups in any enrolled "
                    + "IAS tenant. Check the IAS tenant section above.");
            return;
        }
        Set<String> originsSeen = new java.util.LinkedHashSet<>();
        for (XsuaaScimClient.ShadowUser s : shadows) {
            if (s.origin() != null) originsSeen.add(s.origin());
        }
        log.info("Mapping walk[{}]: origins to query = {}", sa.cisDisplayName(), originsSeen);
        boolean anyMatched = false;
        for (String origin : originsSeen) {
            try {
                List<XsuaaScimClient.IdpRcMapping> rules =
                        xsuaa.listIdpRoleCollectionMappings(xsuaaJson, origin);
                log.info("Mapping walk[{} / origin={}]: XSUAA returned {} mapping rule(s)",
                        sa.cisDisplayName(), origin, rules.size());
                int gateName = 0, gateOp = 0, gateValue = 0, gateGroupSet = 0, matched = 0;
                for (XsuaaScimClient.IdpRcMapping r : rules) {
                    if (!"Groups".equalsIgnoreCase(r.attributeName())) { gateName++; continue; }
                    if (!"equals".equalsIgnoreCase(r.comparisonOperator())) { gateOp++; continue; }
                    if (r.attributeValue() == null || r.roleCollectionName() == null) { gateValue++; continue; }
                    if (!userGroupNames.contains(r.attributeValue())) { gateGroupSet++; continue; }
                    sb.mappedRcs.add(new MappedRcRow(
                            r.roleCollectionName(), origin, r.attributeValue()));
                    log.info("Mapping walk[{} / origin={}]: MATCH rc='{}' via group='{}'",
                            sa.cisDisplayName(), origin,
                            r.roleCollectionName(), r.attributeValue());
                    matched++;
                    anyMatched = true;
                }
                log.info("Mapping walk[{} / origin={}]: matched={} dropped: attrName!=Groups={}, "
                                + "op!=equals={}, null-value-or-rc={}, group-not-in-user-set={}",
                        sa.cisDisplayName(), origin,
                        matched, gateName, gateOp, gateValue, gateGroupSet);
            } catch (Exception ex) {
                log.warn("Mapping walk[{} / origin={}]: lookup failed: {}",
                        sa.cisDisplayName(), origin, ex.getMessage());
                sb.errors.add("XSUAA IDP-mapping lookup for origin '" + origin
                        + "' failed: " + ex.getMessage()
                        + ". Common cause: the api-access binding lacks the 'xs_authorization.read' "
                        + "scope required to read identity-provider mappings.");
            }
        }
        if (!anyMatched && !originsSeen.isEmpty()) {
            log.info("Mapping walk[{}]: no rules matched across {} origin(s) - check the per-origin "
                    + "drop counts above to see why",
                    sa.cisDisplayName(), originsSeen.size());
        }
    }

    private void walkCf(Subaccount sa, String cfJson, String email, SubaccountSection.Builder sb) {
        CfApiClient.CfUser cfUser;
        try {
            List<CfApiClient.CfUser> direct = cf.findUserByUsername(cfJson, email, null);
            if (direct.isEmpty()) {
                CfApiClient.OrgWalkDiagnostic walk = cf.walkOrgs(cfJson, email);
                if (walk.matches().isEmpty()) return;
                cfUser = walk.matches().get(0);
            } else {
                cfUser = direct.get(0);
            }
        } catch (Exception ex) {
            sb.errors.add("CF user lookup failed: " + ex.getMessage());
            return;
        }
        sb.cfUserGuid = cfUser.guid();
        sb.cfUserOrigin = cfUser.origin();
        String orgGuid = sa.cfOrgId().toString();

        try {
            for (CfApiClient.RoleEntry r : cf.listRolesForUser(cfJson, cfUser.guid(), orgGuid, null)) {
                sb.cfRoles.add(new CfRoleRow(r.type(), orgGuid, null, null));
            }
        } catch (Exception ex) {
            sb.errors.add("CF org-roles lookup failed: " + ex.getMessage());
        }
        try {
            for (CfApiClient.Space sp : cf.listSpaces(cfJson, orgGuid)) {
                for (CfApiClient.RoleEntry r : cf.listRolesForUser(cfJson, cfUser.guid(), null, sp.guid())) {
                    sb.cfRoles.add(new CfRoleRow(r.type(), orgGuid, sp.guid(), String.valueOf(sp.name())));
                }
            }
        } catch (Exception ex) {
            sb.errors.add("CF space-roles lookup failed: " + ex.getMessage());
        }
    }

    public record AnalysisReport(String email,
                                 List<TenantSection> iasTenants,
                                 List<SubaccountSection> subaccounts) {}

    public record TenantSection(UUID iasTenantId, String displayName, String iasHost,
                                boolean userFound, String iasUserId,
                                Boolean iasUserActive,
                                String givenName, String familyName,
                                List<IasGroupRow> iasGroups,
                                String error) {
        static class Builder {
            final UUID iasTenantId; final String displayName; final String iasHost;
            boolean userFound; String iasUserId; Boolean iasUserActive;
            String givenName; String familyName;
            final List<IasGroupRow> iasGroups = new ArrayList<>();
            String error;
            Builder(UUID id, String dn, String host) { this.iasTenantId = id; this.displayName = dn; this.iasHost = host; }
            TenantSection build() {
                return new TenantSection(iasTenantId, displayName, iasHost, userFound, iasUserId,
                        iasUserActive, givenName, familyName, iasGroups, error);
            }
        }
    }

    public record IasGroupRow(String id, String displayName) {}

    public record SubaccountSection(UUID subaccountId, String displayName, String region,
                                    List<ShadowUserRow> shadowUsers,
                                    List<DirectRcRow> directRcs,
                                    List<MappedRcRow> mappedRcs,
                                    String cfUserGuid, String cfUserOrigin,
                                    List<CfRoleRow> cfRoles,
                                    List<String> errors) {
        static class Builder {
            final UUID subaccountId; final String displayName; final String region;
            final List<ShadowUserRow> shadowUsers = new ArrayList<>();
            final List<DirectRcRow> directRcs = new ArrayList<>();
            final List<MappedRcRow> mappedRcs = new ArrayList<>();
            String cfUserGuid; String cfUserOrigin;
            final List<CfRoleRow> cfRoles = new ArrayList<>();
            final List<String> errors = new ArrayList<>();
            Builder(UUID id, String dn, String region) { this.subaccountId = id; this.displayName = dn; this.region = region; }
            SubaccountSection build() {
                return new SubaccountSection(subaccountId, displayName, region,
                        new ArrayList<>(new LinkedHashMap<String, ShadowUserRow>() {{
                            for (ShadowUserRow r : shadowUsers) putIfAbsent(r.id() + "@" + r.origin(), r);
                        }}.values()),
                        directRcs, mappedRcs, cfUserGuid, cfUserOrigin, cfRoles, errors);
            }
        }
    }

    public record ShadowUserRow(String id, String origin) {}
    public record DirectRcRow(String roleCollection, String origin) {}
    public record MappedRcRow(String roleCollection, String origin, String viaIasGroup) {}
    public record CfRoleRow(String type, String orgGuid, String spaceGuid, String spaceName) {}
}
