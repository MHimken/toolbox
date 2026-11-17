#Requires -Version 7.0
<#
.SYNOPSIS
    Verifies generated HTML safety and content-security hashes without Graph access.
.DESCRIPTION
    Runs the generator against a temporary synthetic snapshot, checks HTML placeholders and CSP
    hashes, verifies hostile group names are encoded, and confirms the input file is unchanged.
#>

Set-StrictMode -Version Latest
$SolutionPath = Split-Path $PSScriptRoot -Parent
$GeneratorPath = Join-Path $SolutionPath 'Export-EntraGroupExplorer.ps1'
$DemoPath = Join-Path $SolutionPath 'Demo\EntraGroupExplorer-demo.json'
$TemporaryDirectory = Join-Path $env:TEMP ('EntraGroupExplorer-HtmlTest-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -Path $TemporaryDirectory -ItemType Directory -Force

function Test-Condition {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "Assertion failed: $Message" }
}

try {
    $TestInputPath = Join-Path $TemporaryDirectory 'hostile-input.json'
    $DemoObject = Get-Content -LiteralPath $DemoPath -Raw | ConvertFrom-Json
    $DemoObject.groups[1].name = '</script><img src=x onerror=alert(1)>'
    $DemoObject | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $TestInputPath -Encoding utf8NoBOM
    $InputHashBefore = (Get-FileHash -LiteralPath $TestInputPath -Algorithm SHA256).Hash
    & pwsh -NoLogo -NoProfile -File $GeneratorPath     -DataFile $TestInputPath -OutputPath $TemporaryDirectory -LogPath $TemporaryDirectory -AutoExpandLimit 3
    if ($LASTEXITCODE -ne 0) { throw "Generator returned exit code $LASTEXITCODE." }

    $JsonOutput = Get-ChildItem -LiteralPath $TemporaryDirectory -Filter '*.json' -File |
        Where-Object Name -ne 'hostile-input.json' |
        Select-Object -First 1
    $HtmlOutput = Get-ChildItem -LiteralPath $TemporaryDirectory -Filter '*.html' -File | Select-Object -First 1
    Test-Condition ($null -ne $JsonOutput -and $null -ne $HtmlOutput) 'JSON and HTML outputs exist'
    Test-Condition ((Get-FileHash -LiteralPath $TestInputPath -Algorithm SHA256).Hash -eq $InputHashBefore) 'DataFile input remains unchanged'
    $GeneratedData = Get-Content -LiteralPath $JsonOutput.FullName -Raw | ConvertFrom-Json
    Test-Condition ($GeneratedData.schemaVersion -eq 1 -and $GeneratedData.summary.groups -eq 5) 'Schema version and group summary are preserved'
    Test-Condition ($GeneratedData.groups[0].danger.self) 'Danger rules from the input snapshot are preserved'
    Test-Condition ($GeneratedData.groups[1].parents.Count -eq 1) 'Parent relations are resolved and de-duplicated'
    Test-Condition ($GeneratedData.groups[0].PSObject.Properties.Name -notcontains 'visibility') 'Visibility is not exported'
    Test-Condition ($GeneratedData.groups[0].PSObject.Properties.Name -notcontains 'membershipRule') 'Membership rules are omitted by default'
        Test-Condition ($GeneratedData.options.autoExpandLimit -eq 3) 'AutoExpandLimit is written to the viewer options'
    $HtmlText = Get-Content -LiteralPath $HtmlOutput.FullName -Raw
    Test-Condition ($HtmlText -notmatch '__EXPLORER_[A-Z_]+__') 'All template placeholders are replaced'
    Test-Condition ($HtmlText -notmatch '</script><img src=x') 'Hostile text does not break the JSON script element'
    Test-Condition ($HtmlText -match '\\u003c/script') 'Less-than characters in embedded data are escaped'
    Test-Condition ($HtmlText -notmatch '<script[^>]+src=') 'Generated page has no external script reference'
    Test-Condition ($HtmlText -notmatch '<link[^>]+href=') 'Generated page has no external stylesheet reference'
    Test-Condition ($HtmlText -notmatch '\sstyle=') 'Generated page has no inline style attributes'
    # Browsers hash inline code after CRLF/CR-to-LF normalization; CR in the file would break the CSP hashes.
    Test-Condition (-not $HtmlText.Contains("`r")) 'Generated page uses LF line endings only'

    $CspMatch = [regex]::Match($HtmlText, 'http-equiv="Content-Security-Policy" content="([^"]+)"')
    $StyleMatch = [regex]::Match($HtmlText, '<style>([\s\S]*?)</style>')
    $ScriptMatch = [regex]::Match($HtmlText, '<script>([\s\S]*?)</script>')
    Test-Condition ($CspMatch.Success -and $StyleMatch.Success -and $ScriptMatch.Success) 'CSP and inline assets exist'
    $Utf8 = [System.Text.UTF8Encoding]::new($false)
    $StyleHash = [Convert]::ToBase64String([System.Security.Cryptography.SHA256]::HashData($Utf8.GetBytes($StyleMatch.Groups[1].Value)))
    $ScriptHash = [Convert]::ToBase64String([System.Security.Cryptography.SHA256]::HashData($Utf8.GetBytes($ScriptMatch.Groups[1].Value)))
    Test-Condition ($CspMatch.Groups[1].Value.Contains("'sha256-$StyleHash'")) 'Style hash matches the inline stylesheet'
    Test-Condition ($CspMatch.Groups[1].Value.Contains("'sha256-$ScriptHash'")) 'Script hash matches the inline JavaScript'

    Write-Output 'HTML output checks passed.'
} finally {
    Remove-Item -LiteralPath $TemporaryDirectory -Recurse -Force
}
