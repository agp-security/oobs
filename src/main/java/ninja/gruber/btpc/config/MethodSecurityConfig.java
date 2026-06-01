// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class MethodSecurityConfig {

    public static final String ADMIN      = "hasAuthority('SCOPE_btpc.admin')";
    public static final String RESPONDER  = "hasAnyAuthority('SCOPE_btpc.admin','SCOPE_btpc.responder')";
    public static final String SOD_VIEWER = "hasAnyAuthority('SCOPE_btpc.admin','SCOPE_btpc.sod_viewer')";
    public static final String VIEWER     = "hasAnyAuthority('SCOPE_btpc.admin','SCOPE_btpc.responder','SCOPE_btpc.sod_viewer','SCOPE_btpc.viewer')";
}
