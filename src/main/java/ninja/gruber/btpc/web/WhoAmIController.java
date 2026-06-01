// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.web;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1")
public class WhoAmIController {

    @GetMapping("/whoami")
    public Map<String, Object> whoami() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Map<String, Object> out = new LinkedHashMap<>();
        if (auth == null) {
            out.put("authenticated", false);
            return out;
        }
        out.put("authenticated", auth.isAuthenticated());
        out.put("user", auth.getName());
        List<String> scopes = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .map(a -> a.startsWith("SCOPE_") ? a.substring(6) : a) //btpc_
                .collect(Collectors.toList());
        out.put("scopes", scopes);
        return out;
    }
}
