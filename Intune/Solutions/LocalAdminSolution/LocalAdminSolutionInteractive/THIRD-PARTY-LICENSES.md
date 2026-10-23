# Third-party dependency and licence inventory

Reviewed 21 October 2026 from the committed npm lockfiles. Versions and declared SPDX licence identifiers below are taken from each lockfile; the inventory includes direct and transitive packages, development dependencies, and platform-optional entries.

## Review summary

- Backend lockfile: 112 package entries.
- HTML lockfile: 2 package entries.
- Every lockfile entry declares a licence. Declared licences are MIT, Apache-2.0, BSD-3-Clause, ISC, and 0BSD; no copyleft or source-available licence was found.
- `HTML/vendor/LICENSE-msal-browser.txt` carries the MIT notice for the redistributed MSAL browser bundle.
- The BFF deployment archive retains upstream package licence/notice files under `node_modules` and now includes `Backend/THIRD-PARTY-NOTICES.txt` for `@nodable/entities`, whose published package omits a separate licence file.

## Package inventory

| Project | Package | Version | Scope | Declared licence |
|---|---|---:|---|---|
| Backend | `@azure/abort-controller` | 2.2.0 | transitive runtime | MIT |
| Backend | `@azure/core-auth` | 1.11.0 | transitive runtime | MIT |
| Backend | `@azure/core-client` | 1.11.1 | transitive runtime | MIT |
| Backend | `@azure/core-paging` | 1.7.0 | transitive runtime | MIT |
| Backend | `@azure/core-process` | 1.0.0 | transitive runtime | MIT |
| Backend | `@azure/core-rest-pipeline` | 1.25.0 | transitive runtime | MIT |
| Backend | `@azure/core-tracing` | 1.4.0 | transitive runtime | MIT |
| Backend | `@azure/core-util` | 1.14.0 | transitive runtime | MIT |
| Backend | `@azure/core-xml` | 1.6.0 | transitive runtime | MIT |
| Backend | `@azure/data-tables` | 13.3.2 | direct runtime | MIT |
| Backend | `@azure/functions` | 4.16.5 | direct runtime | MIT |
| Backend | `@azure/functions-extensions-base` | 0.3.0 | transitive runtime | MIT |
| Backend | `@azure/identity` | 4.13.3 | direct runtime | MIT |
| Backend | `@azure/logger` | 1.4.0 | transitive runtime | MIT |
| Backend | `@azure/msal-browser` | 5.23.0 | transitive runtime | MIT |
| Backend | `@azure/msal-common` | 16.14.1 | transitive runtime | MIT |
| Backend | `@azure/msal-node` | 6.0.1 | transitive runtime | MIT |
| Backend | `@esbuild/aix-ppc64` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@esbuild/android-arm` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@esbuild/android-arm64` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@esbuild/android-x64` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@esbuild/darwin-arm64` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@esbuild/darwin-x64` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@esbuild/freebsd-arm64` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@esbuild/freebsd-x64` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@esbuild/linux-arm` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@esbuild/linux-arm64` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@esbuild/linux-ia32` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@esbuild/linux-loong64` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@esbuild/linux-mips64el` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@esbuild/linux-ppc64` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@esbuild/linux-riscv64` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@esbuild/linux-s390x` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@esbuild/linux-x64` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@esbuild/netbsd-arm64` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@esbuild/netbsd-x64` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@esbuild/openbsd-arm64` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@esbuild/openbsd-x64` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@esbuild/openharmony-arm64` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@esbuild/sunos-x64` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@esbuild/win32-arm64` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@esbuild/win32-ia32` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@esbuild/win32-x64` | 0.25.12 | transitive development / optional | MIT |
| Backend | `@nodable/entities` | 3.1.0 | transitive runtime | MIT |
| Backend | `@types/node` | 24.7.0 | direct development | MIT |
| Backend | `@typescript/typescript-aix-ppc64` | 7.0.2 | transitive development / optional | Apache-2.0 |
| Backend | `@typescript/typescript-darwin-arm64` | 7.0.2 | transitive development / optional | Apache-2.0 |
| Backend | `@typescript/typescript-darwin-x64` | 7.0.2 | transitive development / optional | Apache-2.0 |
| Backend | `@typescript/typescript-freebsd-arm64` | 7.0.2 | transitive development / optional | Apache-2.0 |
| Backend | `@typescript/typescript-freebsd-x64` | 7.0.2 | transitive development / optional | Apache-2.0 |
| Backend | `@typescript/typescript-linux-arm` | 7.0.2 | transitive development / optional | Apache-2.0 |
| Backend | `@typescript/typescript-linux-arm64` | 7.0.2 | transitive development / optional | Apache-2.0 |
| Backend | `@typescript/typescript-linux-loong64` | 7.0.2 | transitive development / optional | Apache-2.0 |
| Backend | `@typescript/typescript-linux-mips64el` | 7.0.2 | transitive development / optional | Apache-2.0 |
| Backend | `@typescript/typescript-linux-ppc64` | 7.0.2 | transitive development / optional | Apache-2.0 |
| Backend | `@typescript/typescript-linux-riscv64` | 7.0.2 | transitive development / optional | Apache-2.0 |
| Backend | `@typescript/typescript-linux-s390x` | 7.0.2 | transitive development / optional | Apache-2.0 |
| Backend | `@typescript/typescript-linux-x64` | 7.0.2 | transitive development / optional | Apache-2.0 |
| Backend | `@typescript/typescript-netbsd-arm64` | 7.0.2 | transitive development / optional | Apache-2.0 |
| Backend | `@typescript/typescript-netbsd-x64` | 7.0.2 | transitive development / optional | Apache-2.0 |
| Backend | `@typescript/typescript-openbsd-arm64` | 7.0.2 | transitive development / optional | Apache-2.0 |
| Backend | `@typescript/typescript-openbsd-x64` | 7.0.2 | transitive development / optional | Apache-2.0 |
| Backend | `@typescript/typescript-sunos-x64` | 7.0.2 | transitive development / optional | Apache-2.0 |
| Backend | `@typescript/typescript-win32-arm64` | 7.0.2 | transitive development / optional | Apache-2.0 |
| Backend | `@typescript/typescript-win32-x64` | 7.0.2 | transitive development / optional | Apache-2.0 |
| Backend | `@typespec/ts-http-runtime` | 0.3.9 | transitive runtime | MIT |
| Backend | `agent-base` | 7.1.4 | transitive runtime | MIT |
| Backend | `anynum` | 1.0.1 | transitive runtime | MIT |
| Backend | `buffer-equal-constant-time` | 1.0.1 | transitive runtime | BSD-3-Clause |
| Backend | `bundle-name` | 4.1.1 | transitive runtime | MIT |
| Backend | `cookie` | 0.7.2 | transitive runtime | MIT |
| Backend | `debug` | 4.4.3 | transitive runtime | MIT |
| Backend | `default-browser` | 5.5.1 | transitive runtime | MIT |
| Backend | `default-browser-id` | 5.0.1 | transitive runtime | MIT |
| Backend | `define-lazy-prop` | 3.0.0 | transitive runtime | MIT |
| Backend | `ecdsa-sig-formatter` | 1.0.11 | transitive runtime | Apache-2.0 |
| Backend | `esbuild` | 0.25.12 | transitive development | MIT |
| Backend | `fast-xml-builder` | 1.3.1 | transitive runtime | MIT |
| Backend | `fast-xml-parser` | 5.11.2 | transitive runtime | MIT |
| Backend | `fsevents` | 2.3.3 | transitive development / optional | MIT |
| Backend | `get-tsconfig` | 4.14.3 | transitive development | MIT |
| Backend | `http-proxy-agent` | 7.0.2 | transitive runtime | MIT |
| Backend | `https-proxy-agent` | 7.0.6 | transitive runtime | MIT |
| Backend | `is-docker` | 3.0.0 | transitive runtime | MIT |
| Backend | `is-inside-container` | 1.0.0 | transitive runtime | MIT |
| Backend | `is-unsafe` | 2.0.2 | transitive runtime | MIT |
| Backend | `is-wsl` | 3.1.1 | transitive runtime | MIT |
| Backend | `jose` | 6.2.12 | direct runtime | MIT |
| Backend | `jsonwebtoken` | 9.0.3 | transitive runtime | MIT |
| Backend | `jwa` | 2.0.1 | transitive runtime | MIT |
| Backend | `jws` | 4.0.1 | transitive runtime | MIT |
| Backend | `lodash.includes` | 4.3.0 | transitive runtime | MIT |
| Backend | `lodash.isboolean` | 3.0.3 | transitive runtime | MIT |
| Backend | `lodash.isinteger` | 4.0.4 | transitive runtime | MIT |
| Backend | `lodash.isnumber` | 3.0.3 | transitive runtime | MIT |
| Backend | `lodash.isplainobject` | 4.0.6 | transitive runtime | MIT |
| Backend | `lodash.isstring` | 4.0.1 | transitive runtime | MIT |
| Backend | `lodash.once` | 4.1.1 | transitive runtime | MIT |
| Backend | `ms` | 2.1.3 | transitive runtime | MIT |
| Backend | `open` | 10.2.0 | transitive runtime | MIT |
| Backend | `path-expression-matcher` | 1.6.2 | transitive runtime | MIT |
| Backend | `resolve-pkg-maps` | 1.0.0 | transitive development | MIT |
| Backend | `run-applescript` | 7.1.0 | transitive runtime | MIT |
| Backend | `safe-buffer` | 5.2.1 | transitive runtime | MIT |
| Backend | `semver` | 7.8.5 | transitive runtime | ISC |
| Backend | `strnum` | 2.4.2 | transitive runtime | MIT |
| Backend | `tslib` | 2.8.1 | transitive runtime | 0BSD |
| Backend | `tsx` | 4.20.6 | direct development | MIT |
| Backend | `typescript` | 7.0.2 | direct development | Apache-2.0 |
| Backend | `undici-types` | 7.14.0 | transitive development | MIT |
| Backend | `wsl-utils` | 0.1.0 | transitive runtime | MIT |
| Backend | `xml-naming` | 0.3.0 | transitive runtime | MIT |
| HTML | `@azure/msal-browser` | 5.23.0 | direct runtime | MIT |
| HTML | `@azure/msal-common` | 16.14.1 | transitive runtime | MIT |
