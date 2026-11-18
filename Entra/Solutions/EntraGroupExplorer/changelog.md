# Changes

## 2026

### 13th of November

* Change: Parent and nested groups spread across the full browser width in aligned columns of equally wide cards (four per row at 1920 px). The card width follows `MaxNameLength`.
* Change: The upper tree grows upward, so a parent's own parents appear above it, further away from the selected group.
* Change: Tree cards show one badge (the most severe); all warning reasons stay in the tooltip and the accessible label.
* Fix: Long labels no longer overflow their card and cover its right border.
* New: Selecting a group adds its id to the URL fragment; opening a link restores the selection, and browser Back/Forward restores earlier selections. Query-string links are also accepted.

### 12th of November

* New: Add the EntraGroupExplorer PowerShell generator, JSON schema, self-contained interactive viewer, synthetic demo, and offline tests.
* Fix: Exports without dangerous-group rules no longer fail with "Cannot bind argument to parameter 'Rules' because it is an empty array".
* Fix: `created` is written as culture-invariant ISO 8601 UTC.
* Fix: Existing Graph contexts with `Group.Read.All` or `Directory.Read.All` are accepted.
* Fix: Inline CSS/JS are normalized to LF before CSP hashing; browsers blocked them when templates were checked out with CRLF, leaving an unstyled, non-functional page.
* Fix: Warning symbols render as solid triangles (red for dangerous, amber for related), the center-card warning label is readable, and tree connectors no longer cross headings.
* Fix: Delegated tokens with `Directory.AccessAsUser.All` are accepted.
* Change: Progress output shows batch totals and percentages for both the membership and transitive count phases. Validated against a tenant with 24,778 groups.
* Change: Search uses a cached, pre-sorted index; with 25,000 groups a keystroke takes about 7 ms instead of up to 137 ms.
* Change: Direct relations are sorted by name and wrap into rows instead of one long column.
* New: `-AutoExpandLimit` (default 10) starts branches with more nested groups collapsed; `0` disables it.
