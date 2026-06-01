// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.cis;

// Typed wrapper for CIS / UAA failures. The HTTP status is the upstream BTP
// response code; controllers map this to 502 (Bad Gateway) for the caller.
public class CisException extends RuntimeException {

    private final int upstreamStatus;
    private final String upstreamBody;

    public CisException(String message, int upstreamStatus, String upstreamBody) {
        super(message);
        this.upstreamStatus = upstreamStatus;
        this.upstreamBody = upstreamBody;
    }

    public CisException(String message, Throwable cause) {
        super(message, cause);
        this.upstreamStatus = 0;
        this.upstreamBody = null;
    }

    public int upstreamStatus() { return upstreamStatus; }
    public String upstreamBody() { return upstreamBody; }
}
