# Changes

## 2026

### 1st of September

* New: Analyze-CSP-Header.ps1 - analyzes enforced and report-only Content-Security-Policy headers for supplied HTTPS sites and creates a self-contained interactive HTML report. Includes a public-domain demo report.
* Change: Analyze-CSP-Header.ps1 - follows up to five HTTP 301 or 302 redirects, displays redirect chains and limit errors in the report, and sends a Microsoft Edge user-agent.
* Change: Analyze-CSP-Header.ps1 - adds HTTP 307 and 308 to the redirect statuses followed by the analyzer.
* Change: Analyze-CSP-Header.ps1 - uses a self-cleaning Microsoft Edge NetLog fallback when native HTTP requests fail, logs fallback warnings and errors, and continues processing remaining URLs.
* Docs: README.md - documents CSP analysis, redirect handling, parameters, examples, report statuses, and the public demo. Adds an acknowledgement for httpbin.org.
