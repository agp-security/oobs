// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.cis.domain;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record SubaccountCandidate(
        String guid,
        String displayName,
        String subdomain,
        String region,
        String parentType,
        String parentGuid,
        String globalAccountGuid,
        Boolean betaEnabled,
        String description,
        String state,
        String stateMessage,
        String usedForProduction
) {}
