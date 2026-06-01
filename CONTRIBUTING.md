<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Jan-Luca Gruber
-->

# Contributing to OOBS

Thank you for your interest in contributing to OOBS! This document explains how to contribute and the legal requirements for doing so.

## How to contribute

1. Fork the repo and create a feature branch.
2. Keep changes focused; one logical change per pull request.
3. Add or update tests (`./gradlew test`) - the build must stay green.
4. Every new source file must carry the standard header:

   ```
   SPDX-License-Identifier: AGPL-3.0-only
   Copyright (C) <year> <your name>
   ```

5. Open a pull request describing **what** changed and **why**.

## Why this project uses AGPL-3.0

OOBS is a security service that people self-host. AGPL ensures that
if someone modifies it and runs the modified version as a service for others,
those modifications must also be made available under the AGPL. You remain
free to **use, run, self-host, and modify** the software for yourself or your
organisation; the copyleft obligation only applies when you distribute it or
expose a *modified* version to third parties over a network.

## Reporting (security) bugs

see https://agp-security.com/.well-known/security.txt