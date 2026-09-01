# Other tools

This folder contains general-purpose tools that are not tied to a specific Microsoft service.

## Analyze CSP Header

`Analyze-CSP-Header.ps1` checks one or more HTTPS sites for Content Security Policy response
headers and creates a self-contained interactive HTML report.

### Capabilities

- Checks enforced `Content-Security-Policy` headers.
- Identifies `Content-Security-Policy-Report-Only` separately from enforced policies.
- Parses multiple policies and their directives without requiring external modules.
- Highlights broad sources, wildcards, scheme-wide sources, `unsafe-inline`, `unsafe-eval`, and
  executable `data:` or `blob:` sources.
- Reviews fallback coverage and defensive directives such as `object-src`, `base-uri`,
  `frame-ancestors`, `form-action`, and `upgrade-insecure-requests`.
- Sends HEAD requests first and uses GET when HEAD is unsupported or does not return a CSP header.
- Follows HTTP 301, 302, 307, and 308 redirects up to five hops and records the redirect chain.
- Displays a report error when a request exceeds the five-redirect limit.
- Uses a Microsoft Edge User-Agent string for HTTP requests.
- Uses installed Microsoft Edge in headless mode when the native Windows HTTP client cannot
  establish a connection.
- Writes a warning to the log whenever the Edge fallback is used.
- Removes the temporary Edge profile, DOM output, error output, and NetLog immediately after
  extracting the response information.
- Records a per-site error and continues with remaining URLs when Edge is unavailable or its
  capture fails.
- Keeps failures isolated so one unavailable site does not stop the remaining checks.
- Records status, final URL, request method, elapsed time, findings, parsed directives, and raw
  response headers.
- Produces one HTML file with embedded CSS, JavaScript, and report data. The report has no external
  runtime dependencies.
- Supports search, status filtering, expandable site details, and responsive layouts.
- Writes a CMTrace-compatible timestamped log file.

The assessment is a practical review aid. Application requirements and intended source access
must be considered before changing a CSP.

### Requirements

- PowerShell 7
- HTTPS access to each supplied target

No PowerShell modules or external web libraries are required. Microsoft Edge is optional and is
used automatically as a fallback for sites that the native Windows HTTP client cannot reach. Edge
is normally present on modern Windows desktop installations; environments such as Windows Server
Core or customized images may not include it.

### Usage

Analyze one site:

```powershell
.\Analyze-CSP-Header.ps1 -Url 'https://www.microsoft.com'
```

Analyze multiple sites:

```powershell
.\Analyze-CSP-Header.ps1 -Url @(
    'https://intune.best'
    'https://www.microsoft.com'
    'https://www.google.com'
)
```

Create a report at a specific path without opening the browser:

```powershell
.\Analyze-CSP-Header.ps1 `
    -Url 'https://www.microsoft.com' `
    -OutputPath '.\CSP-Report.html' `
    -OpenReport:$false
```

Set the request timeout and log folder:

```powershell
.\Analyze-CSP-Header.ps1 `
    -Url 'https://www.google.com' `
    -TimeoutSeconds 60 `
    -LogPath '.\Logs'
```

### Parameters

| Parameter | Description |
| --- | --- |
| `Url` | One or more absolute HTTPS URLs. This parameter is required and has no default targets. |
| `OutputPath` | HTML report path. A timestamped filename in the current folder is used when omitted. |
| `TimeoutSeconds` | Timeout for each HEAD or GET request. The default is 30 seconds. |
| `OpenReport` | Opens the completed report in the default browser. The default is `$true`. |
| `LogPath` | Log directory. The current folder is used by default. |
| `LogFile` | Log filename. A timestamped filename is generated when omitted. |

### Report statuses

| Status | Meaning |
| --- | --- |
| `Good` | An enforced CSP was found and the automated checks found none of the tested concerns. |
| `Review` | An enforced CSP was found with directives or sources that warrant review. |
| `Missing` | No enforced CSP was returned. A report-only policy may still be present. |
| `Request failed` | The target could not be analyzed due to connectivity, protocol, timeout, validation, or redirect-limit errors. |

### Demo

Open [Analyze-CSP-Header-Demo.html](Analyze-CSP-Header-Demo.html) to view a generated report that
uses public example domains.

### Acknowledgement

Thanks to [httpbin.org](https://httpbin.org) for providing public HTTP request and redirect
endpoints used to validate redirect handling and the five-redirect boundary.
