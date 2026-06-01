// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.containment;

import ninja.gruber.btpc.containment.domain.ContainmentDtos.ContainRequest;

import java.util.LinkedHashSet;
import java.util.Set;

record OriginFilter(String mode, Set<String> origins) {

    static OriginFilter of(ContainRequest req) {
        String mode = req.originMode == null || req.originMode.isBlank()
                ? "all" : req.originMode.toLowerCase();
        if ("all".equals(mode)) return new OriginFilter("all", Set.of());
        if (req.origins == null || req.origins.isEmpty()) {
            throw new IllegalArgumentException(
                    "originMode='" + req.originMode + "' requires a non-empty `origins` list");
        }
        return new OriginFilter(mode, new LinkedHashSet<>(req.origins));
    }

    static OriginFilter all() {
        return new OriginFilter("all", Set.of());
    }

    boolean allOrigins() {
        return "all".equals(mode);
    }
}
