# Changes

## 2026

### 7th of September

* Added daily collection: `Runbooks/Collect-PrimaryUserSignInData.ps1` streams one completed UTC day of successful Windows sign-ins into retry-safe Azure Table aggregates.
* Added weekly repair: `Runbooks/Repair-PrimaryUserAssignments.ps1` validates 28 complete days, calculates deterministic primary users, supports preview, submits Graph batches, and audits outcomes.
* Added automated deployment: `Deployment/main.bicep` creates Storage, three Azure Tables, an Automation Account managed identity, and table-scoped role assignments.
* Added deployment bootstrap: `Deployment/Deploy-RepairPrimaryUser.ps1` imports and publishes both runbooks, creates daily and weekly UTC schedules, and grants the required Graph application permissions.
* Added implementation and operations documentation in `README.md`.
