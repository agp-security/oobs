// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jan-Luca Gruber

package ninja.gruber.btpc.containment;

class CfUserNotFoundException extends RuntimeException {
    CfUserNotFoundException(String message) { super(message); }
}
