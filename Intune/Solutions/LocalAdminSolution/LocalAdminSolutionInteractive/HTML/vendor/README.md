# Vendored browser dependency

This directory contains the browser files required to host the LiveHTML report without a runtime
dependency on a public CDN:

- `msal-browser.min.js`
- `msal-redirect-bridge.min.js`

Both files are generated from the pinned npm dependency `@azure/msal-browser` version `5.23.0`.
They are Microsoft open-source software distributed under the MIT License. The required copyright
and permission notice is retained in `LICENSE-msal-browser.txt`.

Do not edit the generated JavaScript files manually. Recreate them from the pinned lockfile:

```powershell
Set-Location .\HTML
npm ci
```

The `postinstall` script runs `scripts\copy-msal.mjs` and copies only the two runtime bundles and
their license into this directory. `node_modules` is a local restore cache and must not be committed.
