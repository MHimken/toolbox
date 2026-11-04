# Changes

## 2026

### 4th of November

* Change: LDAPSigningAnalyzer.ps1 - `ComputerName` accepts multiple domain controllers as an array or comma-separated list. When no domain controller is specified, all domain controllers of the current domain are autodetected through Active Directory, with the DNS SRV record `_ldap._tcp.dc._msdcs.<domain>` as fallback, and each one is queried.
* Change: LDAPSigningAnalyzer.ps1 - findings include the reporting `DomainController`. Domain controllers that cannot be queried are logged and the remaining domain controllers are still processed. The script exits with code 1 when no domain controller could be read, and domain controllers without matching events are logged as informational.

### 30th of August

* Add: LDAPSigningAnalyzer.ps1 - added analysis of LDAP signing and channel-binding events for local or remote domain controllers.
* Add: NTLMAuditAnalyse.ps1 - added parallel NTLM audit-event collection from domain controllers with CSV export.
* Add: Set-WindowsProductKey.ps1 - added Windows product-key installation and activation verification for Defender Live Response.
