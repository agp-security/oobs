// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.web.domain;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ErrorResponse(
        String error,
        String message,
        OffsetDateTime timestamp
) {
    public static ErrorResponse of(String error, String message) {
        return new ErrorResponse(error, message, OffsetDateTime.now(ZoneOffset.UTC));
    }
}
