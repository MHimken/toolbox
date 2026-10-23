import { loadRuntimeConfig, runtimeConfigDefaults, validateSasConnection } from './connection.js';
import { EntraAuthClient, hasCompleteEntraConfig } from './auth.js';
import { AdminClient, AdminModeController, adminIdleTimeoutMinutes, isAdminSessionError, normalizeSidInput, previewRuleFromProposal, previewRuleMatches, proposalFromReviewRow, validateProposalDraft } from './adminMode.js';
import { buildCsv, calculateReportingState, getAzureTableEntities, resolveAzureData, resolveReviewData, text } from './dataService.js';
import { ProfileApiError, ProfileClient } from './profileClient.js';
import { identityUsage, LocalFirstIdentityLookup, searchLocalIdentities } from './identityLookup.js';
import {
  createDefaultColumnLayout,
  defaultColumnWidth,
  maximumColumnWidth,
  minimumColumnWidth,
  normalizeColumnLayout as normalizeSavedColumnLayout,
  normalizeColumnWidth,
  normalizeTableLayouts as normalizeSavedTableLayouts
} from './tableLayout.js';
import {
  generateRecoveryProfile,
  importRecoveryProfile,
  loadConnection,
  loadLastSuccessfulRun,
  loadPreferences,
  loadRecoveryProfile,
  removeConnection,
  removeRecoveryProfile,
  saveConnection,
  saveLastSuccessfulRun,
  savePreferences,
  saveRecoveryProfile
} from './storage.js';

    const embeddedPayload = document.getElementById('reportData').textContent.trim();
    const hasEmbeddedData = embeddedPayload !== ('__REPORT_' + 'DATA__');
    const preferences = loadPreferences();
    const embeddedReport = hasEmbeddedData ? JSON.parse(embeddedPayload) : null;
    let REPORT = embeddedReport?.raw
      ? resolveAzureData(
          embeddedReport.raw.main || [],
          embeddedReport.raw.users || [],
          embeddedReport.raw.groups || [],
          embeddedReport.raw.devices || [],
          embeddedReport.raw.rules || [],
          embeddedReport.raw.actions || [],
          preferences.staleThresholdDays,
          preferences.reviewWindowDays
        )
      : (embeddedReport || {
      generatedAt: null, summary: [], users: [], groups: [], devices: [], review: [], governance: [], actions: []
    });
    if (embeddedReport?.generatedAt) REPORT.generatedAt = embeddedReport.generatedAt;
    for (const collection of ['summary', 'users', 'groups', 'devices', 'review', 'governance', 'actions']) {
      if (!Array.isArray(REPORT[collection])) REPORT[collection] = [];
    }
    const views = {
      summary: {
        rows: REPORT.summary,
        columns: [
          ['ComputerName', 'Computer name'], ['SID', 'SID'], ['RowKey', 'Entry'],
          ['JoinState', 'Join state'], ['EntraState', 'Entra state'], ['IntuneState', 'Intune state'],
          ['LastReportUtc', 'Last report'], ['ReportingState', 'Collector reporting'],
          ['LocalAdminGroupName', 'Administrators group'], ['Removed', 'Status'],
          ['UserName', 'User name'], ['GroupName', 'Group name'],
          ['MembershipType', 'Membership type'], ['AddedThroughGroupName', 'Added through group'],
          ['LocalAccountLastPasswordChange', 'Password changed'], ['Timestamp', 'Azure timestamp']
        ]
      },
      users: { rows: REPORT.users, columns: [['UserID', 'User ID'], ['SamAccountName', 'SAM account name'], ['UserPrincipalName', 'User principal name'], ['LocalOrEntraOrAD', 'Source'], ['ObservedAt', 'Observed'], ['ResolutionState', 'Resolution state'], ['Timestamp', 'Azure timestamp']] },
      groups: { rows: REPORT.groups, columns: [['GroupID', 'Group ID'], ['GroupName', 'Group name'], ['LocalOrEntraOrAD', 'Source'], ['ObservedAt', 'Observed'], ['ResolutionState', 'Resolution state'], ['Timestamp', 'Azure timestamp']] },
      devices: { rows: REPORT.devices, columns: [['ComputerName', 'Computer name'], ['EntraDisplayName', 'Entra display name'], ['EntraDeviceId', 'Entra device ID'], ['EntraState', 'Entra state'], ['AccountEnabled', 'Entra enabled'], ['IntuneState', 'Intune state'], ['IntuneManagedDeviceId', 'Intune managed-device ID'], ['IntuneLastSyncUtc', 'Intune last sync'], ['ComplianceState', 'Compliance'], ['IntuneRecordCount', 'Intune records'], ['OperatingSystem', 'Operating system'], ['ComputerSid', 'Computer SID'], ['LastReportUtc', 'Collector last report'], ['DaysSinceLastReport', 'Days since report'], ['ReportingState', 'Collector reporting'], ['JoinState', 'Join state'], ['ActiveAdminEntries', 'Active entries'], ['RemovedEntries', 'Removed entries'], ['ReviewStatus', 'Review status']] },
      review: { rows: REPORT.review, columns: [['ComputerName', 'Computer name'], ['PrincipalID', 'Principal SID'], ['PrincipalType', 'Principal type'], ['PrincipalName', 'Principal name'], ['PrincipalSource', 'Principal source'], ['MembershipType', 'Membership type'], ['AddedThroughGroupName', 'Added through group'], ['JoinState', 'Join state'], ['EntraState', 'Entra state'], ['IntuneState', 'Intune state'], ['LastReportUtc', 'Last report'], ['PolicyStatus', 'Policy status'], ['ReviewStatus', 'Review status'], ['MatchingRuleIds', 'Matching rule IDs'], ['DecisiveRuleIds', 'Decisive rule IDs'], ['CorrelationId', 'Correlation ID']] },
      governance: { rows: REPORT.governance, columns: [['PartitionKey', 'Owner / scope'], ['RowKey', 'Rule ID'], ['RuleScope', 'Rule scope'], ['Effect', 'Effect'], ['PrincipalType', 'Principal type'], ['MatchType', 'Match type'], ['PrincipalValue', 'Principal value'], ['PrincipalDisplayName', 'Principal name (informational)'], ['PrincipalUserPrincipalName', 'Principal UPN (informational)'], ['PrincipalSource', 'Principal source'], ['MembershipScope', 'Membership scope'], ['DeviceScopeType', 'Device scope'], ['DeviceScopeValue', 'Device value'], ['ValidFromUtc', 'Valid from'], ['ValidUntilUtc', 'Valid until'], ['Status', 'Status'], ['Owner', 'Owner'], ['Reason', 'Reason'], ['TicketReference', 'Ticket'], ['SchemaVersion', 'Schema version']] }
    };
    function defaultColumnLayoutForView(view) {
      return createDefaultColumnLayout(views[view]?.columns);
    }
    function normalizeColumnLayout(view, layout) {
      return normalizeSavedColumnLayout(views[view]?.columns, layout);
    }
    function normalizeTableLayouts(layouts) {
      return normalizeSavedTableLayouts(views, layouts);
    }
    const state = { view: preferences.defaultView, defaultView: preferences.defaultView, query: '', join: '', removed: '', grouped: preferences.groupByComputer, expandedComputers: [], expandedGroups: [], sortRules: [{ key: 'ComputerName', direction: 1 }], page: 1, size: preferences.pageSize, linked: false, staleThresholdDays: preferences.staleThresholdDays, reviewWindowDays: preferences.reviewWindowDays, timeDisplay: preferences.timeDisplay, csvFilenamePrefix: preferences.csvFilenamePrefix, tableLayouts: normalizeTableLayouts(preferences.tableLayouts || {}) };
    const elements = Object.fromEntries(['generatedAt','headerCount','visibleCount','totalMain','totalRemoved','totalComputers','totalUsers','totalGroups','adminModeButton','adminModeStatus','adminIdleCountdown','adminIdleRemaining','adminTotalRemaining','connectionPanel','storageAccountName','sasToken','governanceStorageAccountName','governanceSasToken','rememberConnection','forgetConnection','refreshButton','refreshWarning','hostConfigStatus','refreshStatus','governanceTab','backButton','search','joinField','joinFilter','removedField','removedFilter','groupField','groupToggle','staleField','staleThreshold','pageSize','resetButton','resetTableLayoutButton','exportButton','tableHead','tableBody','emptyState','pageInfo','firstPage','previousPage','nextPage','lastPage','settingsPanel','guidancePanel','defaultViewSetting','pageSizeSetting','timeDisplaySetting','staleThresholdSetting','reviewWindowSetting','csvPrefixSetting','groupByComputerSetting','saveSettingsButton','settingsStatus','cloudProfileStatus','signInButton','syncProfileButton','signOutButton','profileStatus','recoveryCodeInput','rememberRecoveryProfile','generateRecoveryButton','importRecoveryButton','forgetRecoveryButton',    'recoveryResult','recoveryCodeOutput','proposeRuleButton','ruleDialog','ruleForm','ruleEffect','rulePrincipalType','rulePrincipalSid','rulePrincipalSource','ruleMembershipScope','ruleAssignedThroughGroupSid','ruleDeviceScopeType','ruleDeviceScopeValue','ruleAllowedEntraJoined','ruleAllowedHybridJoined','ruleAllowedDomainJoined','ruleMaxDeviceAgeDays','ruleValidFrom','ruleValidUntil','ruleTicketReference','ruleReason','rulePreview','ruleFormStatus','ruleCancelButton','ruleSubmitButton','reasonDialog','reasonForm','reasonDialogTitle','reasonDialogSummary','reasonInput','reasonFormStatus','reasonCancelButton','reasonSubmitButton'].map(id => [id, document.getElementById(id)]));
    const formatter = new Intl.NumberFormat();
    for (const id of ['reasonRulePreview', 'ruleMatchesDialog', 'ruleMatchesSummary', 'ruleMatchesHead', 'ruleMatchesBody', 'ruleMatchesEmpty', 'ruleMatchesCloseButton']) {
      elements[id] = document.getElementById(id);
    }
    for (const id of ['ruleIdentityQuery', 'ruleIdentityResults', 'ruleIdentityStatus', 'ruleIdentitySummary', 'ruleGroupQuery', 'ruleGroupResults', 'ruleGroupStatus', 'identityUsageDialog', 'identityUsageSummary', 'identityUsageHead', 'identityUsageBody', 'identityRulesHead', 'identityRulesBody', 'identityUsageCloseButton']) {
      elements[id] = document.getElementById(id);
    }
    let selectedPrincipal = null;
    const identityPickers = [];
    let pendingAdminStatusError = false;
    function setSignInStatus(message, isError = false) {
      const status = document.getElementById('signInStatus');
      status.textContent = message;
      status.dataset.error = String(isError);
      if (isError) expandAuthStatus();
    }
    function setAdminModeStatus(message) {
      const isError = pendingAdminStatusError;
      pendingAdminStatusError = false;
      const status = document.getElementById('adminModeStatus');
      if (status.textContent !== message) status.dataset.error = 'false';
      status.textContent = message;
      if (isError) {
        status.dataset.error = 'true';
        expandAuthStatus();
      }
    }
    function markAdminStatusError() {
      pendingAdminStatusError = true;
    }
    function expandAuthStatus() {
      document.getElementById('authStatusBox').open = true;
    }
            let adminController = null;
        let adminBusy = false;
        let adminStatusMessage = '';
        let pendingProposalKey = '';
        let pendingProposalFingerprint = '';
        let pendingReasonAction = null;
    function normalizeConfigValue(value, fallback = '') {
      return typeof value === 'string' ? value.trim() : fallback;
    }
    let runtimeConfig = { ...runtimeConfigDefaults };
    let entraAuthClient = null;
    let profileClient = null;
    let profileSession = null;
    let tableLayoutSaveTimer = null;
    let tableLayoutCloudSave = Promise.resolve();
    async function applyRuntimeConfig(config) {
      const resolved = { ...runtimeConfigDefaults, ...config };
      runtimeConfig = resolved;
      const storageName = normalizeConfigValue(resolved.storageAccountName).toLowerCase();
      const governanceName = normalizeConfigValue(resolved.governanceStorageAccountName).toLowerCase();
      if (storageName && (!elements.storageAccountName.value || resolved.lockStorageAccountName)) {
        if (resolved.lockStorageAccountName &&
            elements.storageAccountName.value &&
            elements.storageAccountName.value.toLowerCase() !== storageName) {
          elements.sasToken.value = '';
        }
        elements.storageAccountName.value = storageName;
        elements.storageAccountName.disabled = resolved.lockStorageAccountName;
        elements.storageAccountName.title = resolved.lockStorageAccountName
          ? 'The storage account is configured by the hosting environment and is locked in this browser.'
          : 'A host-configured default is available for this field.';
      }
      if (governanceName && (!elements.governanceStorageAccountName.value || resolved.lockGovernanceStorageAccountName)) {
        if (resolved.lockGovernanceStorageAccountName &&
            elements.governanceStorageAccountName.value &&
            elements.governanceStorageAccountName.value.toLowerCase() !== governanceName) {
          elements.governanceSasToken.value = '';
        }
        elements.governanceStorageAccountName.value = governanceName;
        elements.governanceStorageAccountName.disabled = resolved.lockGovernanceStorageAccountName;
        elements.governanceStorageAccountName.title = resolved.lockGovernanceStorageAccountName
          ? 'The governance storage account is configured by the hosting environment and is locked in this browser.'
          : 'A host-configured default is available for this field.';
      }
      if (resolved.defaultView && ['summary', 'devices', 'review', 'governance'].includes(resolved.defaultView)) {
        state.defaultView = resolved.defaultView;
      }
      if (resolved.bffBaseUrl) {
        elements.adminModeStatus.title = `Protected backend: ${resolved.bffBaseUrl}`;
      }
      const configuredValues = [
        storageName && 'inventory account',
        governanceName && 'governance account',
        resolved.bffBaseUrl && 'BFF URL',
        resolved.spaClientId && 'SPA identity',
        resolved.redirectUri && 'SPA redirect URI'
      ].filter(Boolean);
      elements.hostConfigStatus.textContent = configuredValues.length
        ? `Public host configuration loaded: ${configuredValues.join(', ')}. Credentials are never loaded from config.json.`
        : 'No public host defaults were loaded. Enter the required account names and credentials manually.';
      if (!hasEmbeddedData && resolved.bffBaseUrl) {
        profileClient = new ProfileClient(resolved.bffBaseUrl);
      }
      if (!hasEmbeddedData && profileClient && hasCompleteEntraConfig(resolved)) {
        try {
          entraAuthClient = new EntraAuthClient(resolved, globalThis.msal, {
            onPopupChange: pending => {
              document.getElementById('retryAuthButton').hidden = !pending;
              updateProfileControls();
              updateCapabilityState();
            }
          });
          await entraAuthClient.initialize();
          setSignInStatus('Microsoft Entra sign-in is available. No OAuth token is persisted.');
          elements.cloudProfileStatus.textContent = 'Sign in to synchronize your cloud profile.';
        } catch (error) {
          entraAuthClient = null;
          setSignInStatus(`Microsoft Entra sign-in could not initialize: ${error.message}`, true);
        }
        if (entraAuthClient) {
          adminController = new AdminModeController({
            client: new AdminClient(profileClient),
            auth: entraAuthClient,
            onChange: handleAdminModeChange,
            onCountdown: updateAdminCountdown
          });
        }
      } else if (!hasEmbeddedData && !profileClient) {
        elements.cloudProfileStatus.textContent = 'Cloud profile synchronization requires a configured protected BFF URL.';
      } else if (!hasEmbeddedData && !hasCompleteEntraConfig(resolved)) {
        elements.cloudProfileStatus.textContent = 'Recovery profile synchronization is available. Microsoft Entra sign-in requires tenant, SPA client, and API scope configuration.';
      }
      updateProfileControls();
      updateCapabilityState();
      const rememberedRecovery = !hasEmbeddedData && profileClient ? loadRecoveryProfile() : null;
      if (rememberedRecovery) {
        await activateRecoveryProfile(rememberedRecovery, true);
      }
    }
    function hasValidAccountName(value) {
      return /^[a-z0-9]{3,24}$/.test(normalizeConfigValue(value).toLowerCase());
    }
    function updateCapabilityState() {
      const governanceAccountConfigured = hasValidAccountName(elements.governanceStorageAccountName.value);
      elements.governanceSasToken.disabled = !governanceAccountConfigured;
      elements.governanceSasToken.title = governanceAccountConfigured
        ? 'Enter the read-only governance SAS token.'
        : 'Configure the governance Storage account before entering its SAS token.';
      const adminActive = Boolean(adminController?.active);
      const governanceReady = adminActive || REPORT.governance.length > 0 ||
        (governanceAccountConfigured && Boolean(elements.governanceSasToken.value.trim()));
      elements.governanceTab.disabled = !governanceReady;
      elements.governanceTab.title = governanceReady
        ? (adminActive ? 'Open governance rules loaded from the protected backend.' : 'Open governance data loaded with the configured account and credential.')
        : 'Governance requires a governance Storage account and read-only SAS token, or Admin mode.';
      if (!governanceReady && state.view === 'governance') activateView('summary');

      const bffConfigured = Boolean(runtimeConfig.bffBaseUrl);
      const entraConfigured = Boolean(runtimeConfig.entraTenantId && runtimeConfig.spaClientId && runtimeConfig.apiScope);
      const entraSignedIn = Boolean(entraAuthClient?.getAccount());
      const unavailableReason = hasEmbeddedData
        ? 'Admin mode is unavailable in generated snapshots.'
        : (!bffConfigured
            ? 'Admin mode requires a configured protected BFF URL.'
            : (!entraConfigured || !adminController
                ? 'Admin mode requires Entra tenant, SPA client, and API scope configuration.'
                : (!entraSignedIn ? 'Sign in with Microsoft Entra before entering Admin mode.' : '')));
      elements.adminModeButton.disabled = Boolean(unavailableReason) || adminBusy || Boolean(entraAuthClient?.popupPending);
      elements.adminModeButton.textContent = adminActive ? 'Exit Admin mode' : 'Enter Admin mode';
      elements.adminModeButton.setAttribute('aria-pressed', text(adminActive));
      elements.adminModeButton.classList.toggle('admin-active', adminActive);
      elements.adminModeButton.title = unavailableReason || (adminActive
        ? 'End Admin mode and discard the elevated token from browser memory.'
        : 'Confirm your identity with the Conditional Access authentication context to enable governance approvals and operator actions.');
      if (adminActive) {
        const session = adminController.session;
        const capabilities = Object.entries({ approveRules: 'approve rules', selfApprove: 'self-approve', operateActions: 'operate actions' })
          .filter(([key]) => session.capabilities?.[key]).map(([, label]) => label);
        setAdminModeStatus(`Admin mode active until ${displayValue('ExpiresAtUtc', session.expiresAtUtc)} (ends after ${adminIdleTimeoutMinutes} minutes without activity). Capabilities: ${capabilities.join(', ') || 'read only'}.${adminStatusMessage ? ` ${adminStatusMessage}` : ''}`);
      } else {
        setAdminModeStatus(unavailableReason
          ? `Admin mode unavailable: ${unavailableReason}`
          : (adminStatusMessage || 'Admin mode is available. Entering it requires a fresh Conditional Access confirmation.'));
      }
      elements.proposeRuleButton.hidden = !['review', 'governance'].includes(state.view);
      const canPropose = !hasEmbeddedData && Boolean(adminController) && entraSignedIn;
      elements.proposeRuleButton.disabled = !canPropose;
      elements.proposeRuleButton.title = canPropose
        ? 'Propose an organization-wide governance rule. An approver must activate it.'
        : 'Proposing governance rules requires the protected BFF and a Microsoft Entra sign-in.';
    }
    const layout = {
      summaryBand: document.querySelector('.summary-band'),
      toolbar: document.querySelector('.toolbar'),
      tableFrame: document.querySelector('.table-frame'),
      pagination: document.querySelector('.pagination')
    };
    const runtimeConfigPromise = loadRuntimeConfig(globalThis.fetch, hasEmbeddedData);

    function displayValue(key, value) {
      if (value === null || value === undefined || value === '') return '';
      if (key.includes('Timestamp') || key.includes('TimeStamp') || key.endsWith('Utc') || key.includes('PasswordChange')) {
        const date = new Date(value);
        if (!Number.isNaN(date.getTime())) return state.timeDisplay === 'utc' ? date.toISOString() : date.toLocaleString();
      }
      return text(value);
    }
    function searchable(row) { return Object.entries(row).filter(([key]) => !key.startsWith('_')).map(([, value]) => text(value).toLowerCase()).join(' '); }
    function restoreSavedConnection() {
      if (hasEmbeddedData) return;
      const saved = loadConnection();
      if (!saved) return;
      const accountName = text(saved?.accountName).trim().toLowerCase();
      const token = text(saved?.token).trim();
      const validationError = validateSasConnection(accountName, token);
      if (validationError) {
        removeConnection();
        elements.refreshStatus.textContent = `Saved connection was removed. ${validationError}`;
        return;
      }
      elements.storageAccountName.value = accountName;
      elements.sasToken.value = token;
      elements.governanceStorageAccountName.value = text(saved?.governanceAccountName);
      elements.governanceSasToken.value = text(saved?.governanceToken);
      elements.rememberConnection.checked = true;
      elements.refreshStatus.textContent = 'Saved connection loaded. Select Refresh from Azure to retrieve data.';
      updateCapabilityState();
    }
    function rememberCurrentConnection() {
      const accountName = elements.storageAccountName.value.trim().toLowerCase();
      const token = elements.sasToken.value.trim();
      const governanceAccountName = elements.governanceStorageAccountName.value.trim().toLowerCase();
      const governanceToken = elements.governanceSasToken.value.trim();
      const validationError = validateSasConnection(accountName, token);
      if (validationError) {
        return { saved: false, message: validationError };
      }
      if (governanceToken && !governanceAccountName) {
        return { saved: false, message: 'Provide the governance Storage account name for the entered governance SAS token.' };
      }
      if (governanceAccountName && governanceToken) {
        const governanceValidationError = validateSasConnection(governanceAccountName, governanceToken);
        if (governanceValidationError) {
          return { saved: false, message: `Governance connection: ${governanceValidationError}` };
        }
      }
      const saved = saveConnection(accountName, token, governanceAccountName, governanceToken);
      return {
        saved,
        message: saved
          ? 'Connection credentials were saved in this browser profile.'
          : 'The browser did not allow the connection credentials to be saved.'
      };
    }
    function updateReportSummary() {
      const lastRun = hasEmbeddedData ? null : loadLastSuccessfulRun();
      const formatDate = value => state.timeDisplay === 'utc' ? new Date(value).toISOString() : new Date(value).toLocaleString();
      const successfulRefresh = lastRun?.lastSuccessfulRefreshUtc ? ` Last successful refresh ${formatDate(lastRun.lastSuccessfulRefreshUtc)}.` : '';
      elements.generatedAt.textContent = REPORT.generatedAt ? `${hasEmbeddedData ? 'Snapshot generated' : 'Current data generated'} ${formatDate(REPORT.generatedAt)}.${successfulRefresh}` : `No Azure data loaded.${successfulRefresh}`;
      elements.totalMain.textContent = formatter.format(REPORT.summary.length);
      elements.totalRemoved.textContent = formatter.format(REPORT.summary.filter(row => Number(row.Removed) === 1).length);
      elements.totalComputers.textContent = formatter.format(REPORT.devices.length);
      elements.totalUsers.textContent = formatter.format(REPORT.users.length);
      elements.totalGroups.textContent = formatter.format(REPORT.groups.length);
      elements.joinFilter.querySelectorAll('option:not(:first-child)').forEach(option => option.remove());
      [...new Set(REPORT.summary.map(row => row.JoinState).filter(Boolean))].sort().forEach(value => { const option = document.createElement('option'); option.value = value; option.textContent = value; elements.joinFilter.appendChild(option); });
    }
    async function refreshFromAzure() {
      const accountName = elements.storageAccountName.value.trim().toLowerCase();
      const token = elements.sasToken.value.trim();
      const governanceAccountName = elements.governanceStorageAccountName.value.trim().toLowerCase();
      const governanceToken = elements.governanceSasToken.value.trim();
      const validationError = validateSasConnection(accountName, token);
      if (validationError) {
        elements.refreshStatus.textContent = validationError;
        return;
      }
      if (governanceToken && !governanceAccountName) {
        elements.refreshStatus.textContent = 'Provide the governance Storage account name for the entered governance SAS token.';
        return;
      }
      if (governanceAccountName && governanceToken) {
        const governanceValidationError = validateSasConnection(governanceAccountName, governanceToken);
        if (governanceValidationError) {
          elements.refreshStatus.textContent = `Governance connection: ${governanceValidationError}`;
          return;
        }
      }
      const accountUrl = `https://${accountName}.table.core.windows.net`;
      const governanceAccountUrl = governanceAccountName && governanceToken
        ? `https://${governanceAccountName}.table.core.windows.net`
        : '';
      elements.refreshButton.disabled = true;
      elements.refreshButton.textContent = 'Refreshing...';
      elements.refreshWarning.hidden = false;
      elements.refreshStatus.textContent = 'Reading Azure Table pages. Please wait patiently.';
      elements.connectionPanel.setAttribute('aria-busy', 'true');
      try {
        const [main, users, groups, devices, rules, actions] = await Promise.all([
          getAzureTableEntities('LocalAdminCollection', accountUrl, token),
          getAzureTableEntities('AdminUserNames', accountUrl, token),
          getAzureTableEntities('AdminGroups', accountUrl, token),
          getAzureTableEntities('LocalAdminDevices', accountUrl, token),
          governanceAccountUrl ? getAzureTableEntities('LocalAdminAllowRules', governanceAccountUrl, governanceToken) : Promise.resolve([]),
          governanceAccountUrl ? getAzureTableEntities('LocalAdminReviewActions', governanceAccountUrl, governanceToken) : Promise.resolve([])
        ]);
        REPORT = resolveAzureData(main, users, groups, devices, rules, actions, state.staleThresholdDays, state.reviewWindowDays);
        for (const view of ['summary', 'users', 'groups', 'devices', 'review', 'governance']) views[view].rows = REPORT[view];
        state.query = state.join = state.removed = ''; state.expandedComputers = []; state.expandedGroups = []; state.page = 1;
        elements.search.value = elements.joinFilter.value = elements.removedFilter.value = '';
        const persistenceMessage = elements.rememberConnection.checked
          ? (saveConnection(accountName, token, governanceAccountName, governanceToken) ? ' Connection saved on this device.' : ' Connection could not be saved by this browser.')
          : (removeConnection() ? '' : ' Previously saved connection could not be removed.');
        saveLastSuccessfulRun({
          storageAccountName: accountName,
          lastSuccessfulRefreshUtc: REPORT.generatedAt,
          summaryRows: REPORT.summary.length,
          userRows: REPORT.users.length,
          groupRows: REPORT.groups.length,
          deviceRows: REPORT.devices.length
        });
        updateReportSummary(); activateView('summary'); updateCapabilityState();
        elements.refreshWarning.textContent = 'Refresh complete. The report now shows the latest retrieved Azure Table data.';
        elements.refreshStatus.textContent = `Loaded ${formatter.format(REPORT.summary.length)} local administrator rows, ${formatter.format(REPORT.devices.length)} devices, ${formatter.format(REPORT.users.length)} users, ${formatter.format(REPORT.groups.length)} groups, and ${formatter.format(REPORT.governance.length)} allow rules.${persistenceMessage}`;
      } catch (error) {
        elements.refreshWarning.textContent = 'Refresh stopped. Review the error below before trying again.';
        elements.refreshStatus.textContent = `${error.message} Verify the SAS permissions and Azure Storage CORS configuration.`;
      } finally {
        elements.refreshButton.disabled = false;
        elements.refreshButton.textContent = 'Refresh from Azure';
        elements.connectionPanel.removeAttribute('aria-busy');
      }
    }
    function filteredRows() {
      const query = state.query.trim().toLowerCase();
      return views[state.view].rows.filter(row => (!query || searchable(row).includes(query)) && (state.view !== 'summary' || ((!state.join || text(row.JoinState) === state.join) && (!state.removed || text(row.Removed) === state.removed))));
    }
    function compareValues(left, right, direction = 1) {
      if (left === right) return 0;
      if (left === null || left === undefined || left === '') return 1;
      if (right === null || right === undefined || right === '') return -1;
      if (typeof left === 'number' && typeof right === 'number') return (left - right) * direction;
      return text(left).localeCompare(text(right), undefined, { numeric: true, sensitivity: 'base' }) * direction;
    }
    function sortedRows(rows) {
      const rules = state.sortRules;
      const effectiveRules = state.view === 'summary' && state.grouped
        ? [
            rules.find(rule => rule.key === 'ComputerName') || { key: 'ComputerName', direction: 1 },
            rules.find(rule => rule.key === 'SID') || { key: 'SID', direction: 1 },
            ...rules.filter(rule => rule.key !== 'ComputerName' && rule.key !== 'SID'),
          ]
        : rules;
      return [...rows].sort((left, right) => {
        for (const rule of effectiveRules) {
          const selectedOrder = compareValues(left[rule.key], right[rule.key], rule.direction);
          if (selectedOrder) return selectedOrder;
        }
        return 0;
      });
    }
    function groupComputerRows(rows) {
      const groups = [];
      rows.forEach(row => {
        const key = `${text(row.ComputerName)}|${text(row.SID)}`;
        const currentGroup = groups[groups.length - 1];
        if (!currentGroup || currentGroup.key !== key) groups.push({ key, rows: [row] });
        else currentGroup.rows.push(row);
      });
      return groups;
    }
    function groupAccessRows(rows, computerKey) {
      const directRows = [];
      const groups = [];
      const groupsBySid = new Map();
      rows.forEach(row => {
        const groupSid = row.MembershipType === 'Transitive' ? text(row._AssignedThroughGroupSID) : (row._GroupSID ? text(row._GroupSID) : '');
        if (!groupSid) {
          directRows.push(row);
          return;
        }
        if (!groupsBySid.has(groupSid)) {
          const group = {
            key: `${computerKey}|${groupSid}`,
            sid: groupSid,
            name: text(row.AddedThroughGroupName || row.GroupName || groupSid),
            rows: []
          };
          groupsBySid.set(groupSid, group);
          groups.push(group);
        }
        const group = groupsBySid.get(groupSid);
        if (!group.name || group.name === group.sid) group.name = text(row.AddedThroughGroupName || row.GroupName || group.sid);
        group.rows.push(row);
      });
      return { directRows, groups };
    }
    function paginationItemCount() {
      const rows = sortedRows(filteredRows());
      return state.view === 'summary' && state.grouped ? groupComputerRows(rows).length : rows.length;
    }
    function captureViewState() {
      return {
        ...state,
        windowScrollY: window.scrollY,
        tableScrollLeft: document.querySelector('.table-frame').scrollLeft
      };
    }
    function restoreViewState(savedState) {
      Object.assign(state, savedState);
      if (!Array.isArray(state.sortRules)) {
        state.sortRules = state.sort
          ? [{ key: state.sort, direction: state.direction === -1 ? -1 : 1 }]
          : [{ key: state.view === 'summary' ? 'ComputerName' : views[state.view]?.columns[0]?.[0] || 'RowKey', direction: 1 }];
      }
      delete state.sort;
      delete state.direction;
      elements.search.value = state.query;
      elements.joinFilter.value = state.join;
      elements.removedFilter.value = state.removed;
      elements.groupToggle.checked = Boolean(state.grouped);
      elements.staleThreshold.value = text(state.staleThresholdDays);
      state.expandedComputers = Array.isArray(state.expandedComputers) ? state.expandedComputers : [];
      state.expandedGroups = Array.isArray(state.expandedGroups) ? state.expandedGroups : [];
      elements.pageSize.value = text(state.size);
      document.querySelectorAll('.tab').forEach(tab => tab.setAttribute('aria-selected', text(tab.dataset.view === state.view)));
      elements.joinField.hidden = state.view !== 'summary';
      elements.removedField.hidden = state.view !== 'summary';
      elements.groupField.hidden = state.view !== 'summary';
      elements.staleField.hidden = state.view !== 'devices' && state.view !== 'review';
      elements.backButton.classList.toggle('visible', state.linked);
      updateViewLayout();
      if (views[state.view]) render();
      requestAnimationFrame(() => {
        document.querySelector('.table-frame').scrollLeft = savedState.tableScrollLeft || 0;
        window.scrollTo({ top: savedState.windowScrollY || 0 });
      });
    }
    function updateCurrentHistoryState() {
      if (history.state?.localAdminReport) {
        history.replaceState({ localAdminReport: true, viewState: captureViewState() }, '');
      }
    }
    function activateView(view, linkedQuery = '') {
      state.view = view; state.page = 1; state.linked = Boolean(linkedQuery);
      state.query = linkedQuery; elements.search.value = linkedQuery;
      if (views[view])       state.sortRules = [{ key: view === 'summary' ? 'ComputerName' : views[view].columns[0][0], direction: 1 }];
      document.querySelectorAll('.tab').forEach(tab => tab.setAttribute('aria-selected', text(tab.dataset.view === view)));
      elements.joinField.hidden = view !== 'summary'; elements.removedField.hidden = view !== 'summary'; elements.groupField.hidden = view !== 'summary';
      elements.staleField.hidden = view !== 'devices' && view !== 'review';
      elements.backButton.classList.toggle('visible', state.linked);
      updateViewLayout();
      if (views[view]) render();
    }
    function updateViewLayout() {
      const isStatic = state.view === 'settings' || state.view === 'guidance';
      layout.summaryBand.hidden = isStatic;
      layout.toolbar.hidden = isStatic;
      layout.tableFrame.hidden = isStatic;
      layout.pagination.hidden = isStatic;
      elements.headerCount.hidden = isStatic;
      elements.settingsPanel.hidden = state.view !== 'settings';
      elements.guidancePanel.hidden = state.view !== 'guidance';
      elements.proposeRuleButton.hidden = !['review', 'governance'].includes(state.view);
    }
    function openDetail(kind, sid) {
      history.replaceState({ localAdminReport: true, viewState: captureViewState() }, '');
      activateView(kind === 'user' ? 'users' : 'groups', sid);
      history.pushState({ localAdminReport: true, viewState: captureViewState() }, '', `#${kind}-details`);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
    function renderCell(row, key) {
      const cell = document.createElement('td');
      if ((state.view === 'users' && ['UserID', 'SamAccountName', 'UserPrincipalName'].includes(key)) ||
          (state.view === 'groups' && ['GroupID', 'GroupName'].includes(key))) {
        const button = document.createElement('button');
        button.className = 'detail-link';
        button.type = 'button';
        button.textContent = displayValue(key, row[key]);
        button.title = 'Show computers, membership paths and related rules from loaded data.';
        button.addEventListener('click', () => openIdentityUsageDialog(row, state.view === 'users' ? 'User' : 'Group'));
        cell.appendChild(button);
      } else if (state.view === 'summary' && key === 'Removed') {
        const badge = document.createElement('span'); badge.className = `status ${Number(row.Removed) === 1 ? 'removed' : 'active'}`; badge.textContent = Number(row.Removed) === 1 ? 'Removed' : 'Active'; cell.appendChild(badge);
      } else if (state.view === 'summary' && key === 'UserName' && row._UserSID) {
        const button = document.createElement('button'); button.className = 'detail-link'; button.type = 'button'; button.textContent = text(row.UserName); button.title = `Open user details for ${row._UserSID}`; button.addEventListener('click', () => openDetail('user', row._UserSID)); cell.appendChild(button);
      } else if (state.view === 'summary' && key === 'GroupName' && row._GroupSID) {
        const button = document.createElement('button'); button.className = 'detail-link'; button.type = 'button'; button.textContent = text(row.GroupName); button.title = `Open group details for ${row._GroupSID}`; button.addEventListener('click', () => openDetail('group', row._GroupSID)); cell.appendChild(button);
      } else if (state.view === 'summary' && key === 'AddedThroughGroupName' && row._AssignedThroughGroupSID) {
        const button = document.createElement('button'); button.className = 'detail-link'; button.type = 'button'; button.textContent = text(row.AddedThroughGroupName); button.title = `Open group details for ${row._AssignedThroughGroupSID}`; button.addEventListener('click', () => openDetail('group', row._AssignedThroughGroupSID)); cell.appendChild(button);
      } else { cell.textContent = displayValue(key, row[key]); }
      return cell;
    }
    function getVisibleColumns() {
      const tableLayout = state.tableLayouts[state.view] || defaultColumnLayoutForView(state.view);
      return tableLayout.map(column => {
        const match = (views[state.view].columns || []).find(([key]) => key === column.key);
        return match ? [match[0], match[1], column.width] : null;
      }).filter(Boolean);
    }
    function moveColumn(key, offset) {
      const current = state.tableLayouts[state.view] || defaultColumnLayoutForView(state.view);
      const fromIndex = current.findIndex(column => column.key === key);
      const toIndex = Math.max(0, Math.min(current.length - 1, fromIndex + offset));
      if (fromIndex < 0 || fromIndex === toIndex) return false;
      const reordered = [...current];
      const [moved] = reordered.splice(fromIndex, 1);
      reordered.splice(toIndex, 0, moved);
      state.tableLayouts[state.view] = reordered;
      return true;
    }
    function scheduleTableLayoutPersistence() {
      persistPreferences();
      if (tableLayoutSaveTimer) clearTimeout(tableLayoutSaveTimer);
      if (!profileSession) return;
      tableLayoutSaveTimer = setTimeout(() => {
        tableLayoutCloudSave = tableLayoutCloudSave
          .catch(() => {})
          .then(async () => {
            try {
              await saveCloudProfile();
              elements.cloudProfileStatus.textContent = 'Table layout saved to the active cloud profile.';
            } catch (error) {
              elements.cloudProfileStatus.textContent = `Table layout was saved locally, but cloud synchronization failed. ${profileErrorMessage(error)}`;
            }
          });
      }, 600);
    }
    function render() {
      const rows = sortedRows(filteredRows());
      const groupedSummary = state.view === 'summary' && state.grouped;
      const computerGroups = groupedSummary ? groupComputerRows(rows) : [];
      const itemCount = groupedSummary ? computerGroups.length : rows.length;
      const pages = Math.max(1, Math.ceil(itemCount / state.size)); state.page = Math.min(state.page, pages);
      const start = (state.page - 1) * state.size;
      const pageComputerGroups = groupedSummary ? computerGroups.slice(start, start + state.size) : [];
      const pageRows = groupedSummary ? [] : rows.slice(start, start + state.size);
      const computerCounts = new Map();
      if (groupedSummary) computerGroups.forEach(group => computerCounts.set(group.key, group.rows.length));
      const visibleColumns = getVisibleColumns();
      elements.visibleCount.textContent = formatter.format(rows.length);
      elements.tableHead.replaceChildren();
      visibleColumns.forEach(([key, label, width]) => {
        const th = document.createElement('th');
        const columnWidth = normalizeColumnWidth(width, defaultColumnWidth(key));
        th.dataset.key = key;
        th.style.width = `${columnWidth}px`;
        th.style.minWidth = `${columnWidth}px`;
        th.draggable = true;
        const ruleIndex = state.sortRules.findIndex(rule => rule.key === key);
        const rule = ruleIndex >= 0 ? state.sortRules[ruleIndex] : null;
        th.setAttribute('aria-sort', ruleIndex === 0 ? (rule.direction === 1 ? 'ascending' : 'descending') : 'none');
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'column-header-button';
        button.textContent = `${label}${rule ? `  ${rule.direction === 1 ? '▲' : '▼'}${ruleIndex + 1}` : ''}`;
        button.title = rule
          ? `${ruleIndex === 0 ? 'Primary' : `Priority ${ruleIndex + 1}`} sort: ${rule.direction === 1 ? 'ascending' : 'descending'}. Click to reverse, then remove. Drag the header or press Alt+Left/Right to move the column.`
          : 'Click to add as the next sort priority. Drag the header or press Alt+Left/Right to move the column.';
        button.setAttribute('aria-label', rule
          ? `${label}, ${rule.direction === 1 ? 'ascending' : 'descending'}, sort priority ${ruleIndex + 1}`
          : `${label}, not sorted`);
        button.addEventListener('click', () => {
          const selectedIndex = state.sortRules.findIndex(selectedRule => selectedRule.key === key);
          if (selectedIndex < 0) {
            state.sortRules = [...state.sortRules, { key, direction: 1 }];
          } else if (state.sortRules[selectedIndex].direction === 1) {
            state.sortRules[selectedIndex].direction = -1;
          } else {
            state.sortRules = state.sortRules.filter((_, index) => index !== selectedIndex);
          }
          state.page = 1;
          render();
          updateCurrentHistoryState();
        });
        button.addEventListener('keydown', event => {
          if (!event.altKey || !['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
          event.preventDefault();
          if (!moveColumn(key, event.key === 'ArrowLeft' ? -1 : 1)) return;
          render();
          scheduleTableLayoutPersistence();
          updateCurrentHistoryState();
          requestAnimationFrame(() => elements.tableHead.querySelector(`[data-key="${CSS.escape(key)}"] .column-header-button`)?.focus());
        });
        const resizeHandle = document.createElement('span');
        resizeHandle.className = 'column-resize-handle';
        resizeHandle.tabIndex = 0;
        resizeHandle.draggable = false;
        resizeHandle.setAttribute('role', 'separator');
        resizeHandle.setAttribute('aria-orientation', 'vertical');
        resizeHandle.setAttribute('aria-label', `Resize ${label} column`);
        resizeHandle.setAttribute('aria-valuemin', String(minimumColumnWidth));
        resizeHandle.setAttribute('aria-valuemax', String(maximumColumnWidth));
        resizeHandle.setAttribute('aria-valuenow', String(columnWidth));
        const applyWidth = requestedWidth => {
          const newWidth = normalizeColumnWidth(requestedWidth, columnWidth);
          const current = state.tableLayouts[state.view] || defaultColumnLayoutForView(state.view);
          const matching = current.find(column => column.key === key);
          if (matching) matching.width = newWidth;
          th.style.width = `${newWidth}px`;
          th.style.minWidth = `${newWidth}px`;
          resizeHandle.setAttribute('aria-valuenow', String(newWidth));
        };
        resizeHandle.addEventListener('pointerdown', event => {
          event.preventDefault();
          event.stopPropagation();
          const startX = event.clientX;
          const startWidth = Number.parseFloat(th.style.width) || defaultColumnWidth(key);
          const moveHandler = moveEvent => {
            applyWidth(startWidth + moveEvent.clientX - startX);
          };
          const stopHandler = () => {
            scheduleTableLayoutPersistence();
            updateCurrentHistoryState();
            window.removeEventListener('pointermove', moveHandler);
            window.removeEventListener('pointerup', stopHandler);
          };
          window.addEventListener('pointermove', moveHandler);
          window.addEventListener('pointerup', stopHandler);
        });
        resizeHandle.addEventListener('keydown', event => {
          if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
          event.preventDefault();
          const step = event.shiftKey ? 25 : 10;
          const currentWidth = Number.parseFloat(th.style.width) || columnWidth;
          applyWidth(currentWidth + (event.key === 'ArrowLeft' ? -step : step));
          scheduleTableLayoutPersistence();
          updateCurrentHistoryState();
        });
        th.addEventListener('dragstart', event => {
          if (event.target === resizeHandle) {
            event.preventDefault();
            return;
          }
          event.dataTransfer?.setData('text/plain', key);
          th.classList.add('dragging');
        });
        th.addEventListener('dragover', event => {
          event.preventDefault();
          th.classList.add('drag-over');
        });
        th.addEventListener('dragleave', () => th.classList.remove('drag-over'));
        th.addEventListener('drop', event => {
          event.preventDefault();
          const sourceKey = event.dataTransfer?.getData('text/plain');
          if (!sourceKey || sourceKey === key) return;
          const current = state.tableLayouts[state.view] || defaultColumnLayoutForView(state.view);
          const fromIndex = current.findIndex(column => column.key === sourceKey);
          const toIndex = current.findIndex(column => column.key === key);
          if (fromIndex < 0 || toIndex < 0) return;
          const reordered = [...current];
          const [moved] = reordered.splice(fromIndex, 1);
          reordered.splice(toIndex, 0, moved);
          state.tableLayouts[state.view] = reordered;
          th.classList.remove('drag-over');
          render();
          scheduleTableLayoutPersistence();
          updateCurrentHistoryState();
        });
        th.addEventListener('dragend', () => { th.classList.remove('dragging'); th.classList.remove('drag-over'); });
        th.appendChild(button);
        th.appendChild(resizeHandle);
        elements.tableHead.appendChild(th);
      });
      const adminColumn = adminActionsVisible();
      if (adminColumn) {
        const th = document.createElement('th');
        th.className = 'admin-actions-header';
        th.scope = 'col';
        th.textContent = 'Admin actions';
        elements.tableHead.appendChild(th);
      }
      elements.tableBody.replaceChildren();
      const appendDataRow = row => {
        const tr = document.createElement('tr'); visibleColumns.forEach(([key]) => tr.appendChild(renderCell(row, key)));
        if (adminColumn) tr.appendChild(renderAdminActionsCell(row));
        elements.tableBody.appendChild(tr);
      };
      pageRows.forEach(appendDataRow);
      pageComputerGroups.forEach(computerGroup => {
        const row = computerGroup.rows[0];
        const computerKey = computerGroup.key;
        const computerRow = document.createElement('tr'); computerRow.className = 'computer-group';
        const computerCell = document.createElement('td'); computerCell.colSpan = views.summary.columns.length;
        const computerExpanded = state.expandedComputers.includes(computerKey);
        const computerButton = document.createElement('button'); computerButton.className = 'computer-group-button'; computerButton.type = 'button'; computerButton.setAttribute('aria-expanded', text(computerExpanded));
        const computerIndicator = document.createElement('span'); computerIndicator.className = 'computer-group-indicator'; computerIndicator.setAttribute('aria-hidden', 'true'); computerIndicator.textContent = computerExpanded ? '▼' : '▶'; computerButton.appendChild(computerIndicator);
        computerButton.append(document.createTextNode(text(row.ComputerName) || 'Unnamed computer'));
        const computerMeta = document.createElement('span'); computerMeta.className = 'computer-group-meta'; computerMeta.textContent = `| SID: ${text(row.SID)}`; computerButton.appendChild(computerMeta);
        const computerCount = document.createElement('span'); computerCount.className = 'computer-group-count'; computerCount.textContent = `${formatter.format(computerCounts.get(computerKey) || 0)} entries`; computerButton.appendChild(computerCount);
        computerButton.addEventListener('click', () => { state.expandedComputers = computerExpanded ? state.expandedComputers.filter(key => key !== computerKey) : [...state.expandedComputers, computerKey]; render(); updateCurrentHistoryState(); });
        computerCell.appendChild(computerButton); computerRow.appendChild(computerCell); elements.tableBody.appendChild(computerRow);
        if (!computerExpanded) return;

        const accessRows = groupAccessRows(computerGroup.rows, computerKey);
        accessRows.directRows.forEach(appendDataRow);
        accessRows.groups.forEach(group => {
          const groupRow = document.createElement('tr'); groupRow.className = 'access-group';
          const groupCell = document.createElement('td'); groupCell.colSpan = views.summary.columns.length;
          const groupExpanded = state.expandedGroups.includes(group.key);
          const groupButton = document.createElement('button'); groupButton.className = 'access-group-button'; groupButton.type = 'button'; groupButton.setAttribute('aria-expanded', text(groupExpanded));
          const indicator = document.createElement('span'); indicator.className = 'access-group-indicator'; indicator.setAttribute('aria-hidden', 'true'); indicator.textContent = groupExpanded ? '▼' : '▶'; groupButton.appendChild(indicator);
          groupButton.append(document.createTextNode(group.name || 'Unnamed group'));
          const meta = document.createElement('span'); meta.className = 'access-group-meta'; meta.textContent = `| SID: ${group.sid}`; groupButton.appendChild(meta);
          const count = document.createElement('span'); count.className = 'access-group-count'; count.textContent = `${formatter.format(group.rows.length)} entries`; groupButton.appendChild(count);
          groupButton.addEventListener('click', () => { state.expandedGroups = groupExpanded ? state.expandedGroups.filter(key => key !== group.key) : [...state.expandedGroups, group.key]; render(); updateCurrentHistoryState(); });
          groupCell.appendChild(groupButton); groupRow.appendChild(groupCell); elements.tableBody.appendChild(groupRow);
          if (groupExpanded) group.rows.forEach(appendDataRow);
        });
      });
      elements.emptyState.hidden = rows.length !== 0;
      const itemLabel = groupedSummary ? 'computers' : 'rows';
      elements.pageInfo.textContent = itemCount ? `${formatter.format(start + 1)}-${formatter.format(Math.min(start + state.size, itemCount))} of ${formatter.format(itemCount)} ${itemLabel} | Page ${state.page} of ${pages}` : `0 ${itemLabel}`;
      elements.firstPage.disabled = elements.previousPage.disabled = state.page === 1;
      elements.nextPage.disabled = elements.lastPage.disabled = state.page === pages;
      elements.firstPage.title = state.page === 1 ? 'Already on the first page' : 'First page';
      elements.previousPage.title = state.page === 1 ? 'No previous page' : 'Previous page';
      elements.nextPage.title = state.page === pages ? 'No next page' : 'Next page';
      elements.lastPage.title = state.page === pages ? 'Already on the last page' : 'Last page';
    }
    function exportCsv() {
      const csv = buildCsv(getVisibleColumns(), sortedRows(filteredRows()), (key, value) => key === 'Removed' ? (Number(value) === 1 ? 'Removed' : 'Active') : value);
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' }); const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = `${state.csvFilenamePrefix}-${state.view}.csv`; link.click();
      setTimeout(() => URL.revokeObjectURL(link.href), 0);
    }
    function persistPreferences() {
      return savePreferences({
        staleThresholdDays: state.staleThresholdDays,
        reviewWindowDays: state.reviewWindowDays,
        pageSize: state.size,
        defaultView: state.defaultView,
        groupByComputer: state.grouped,
        timeDisplay: state.timeDisplay,
        csvFilenamePrefix: state.csvFilenamePrefix,
        tableLayouts: state.tableLayouts
      });
    }
    function currentProfileSettings() {
      return {
        staleThresholdDays: state.staleThresholdDays,
        reviewWindowDays: state.reviewWindowDays,
        pageSize: state.size,
        defaultView: state.defaultView,
        groupByComputer: state.grouped,
        timeDisplay: state.timeDisplay,
        csvFilenamePrefix: state.csvFilenamePrefix,
        tableLayouts: state.tableLayouts
      };
    }
    function applyProfileSettings(settings) {
      if (!settings || typeof settings !== 'object') throw new Error('The cloud profile did not contain valid settings.');
      const pageSize = Number(settings.pageSize);
      const staleDays = Number(settings.staleThresholdDays);
      const reviewDays = Number(settings.reviewWindowDays);
      if (![25, 50, 100, 250].includes(pageSize) ||
          !Number.isInteger(staleDays) || staleDays < 1 ||
          !Number.isInteger(reviewDays) || reviewDays < 1 ||
          !['summary', 'devices', 'review', 'governance'].includes(settings.defaultView) ||
          !['local', 'utc'].includes(settings.timeDisplay) ||
          typeof settings.groupByComputer !== 'boolean' ||
          !/^[A-Za-z0-9_-]{1,40}$/.test(settings.csvFilenamePrefix || '')) {
        throw new Error('The cloud profile contained unsupported settings.');
      }
      state.defaultView = settings.defaultView;
      state.size = pageSize;
      state.timeDisplay = settings.timeDisplay;
      state.staleThresholdDays = staleDays;
      state.reviewWindowDays = reviewDays;
      state.csvFilenamePrefix = settings.csvFilenamePrefix;
      state.grouped = settings.groupByComputer;
      state.tableLayouts = normalizeTableLayouts(settings.tableLayouts || state.tableLayouts || {});
      elements.pageSize.value = text(state.size);
      elements.staleThreshold.value = text(state.staleThresholdDays);
      elements.groupToggle.checked = state.grouped;
      updateSettingsForm();
      applyFreshnessThreshold();
      updateReportSummary();
      persistPreferences();
      if (views[state.view]) render();
    }
    function profileAuthentication() {
      if (profileSession?.type === 'entra' && entraAuthClient) {
        return { type: 'entra', getAccessToken: () => entraAuthClient.getAccessToken() };
      }
      if (profileSession?.type === 'recovery' && profileSession.recoveryCode) {
        return { type: 'recovery', recoveryCode: profileSession.recoveryCode };
      }
      return null;
    }
    function profileErrorMessage(error) {
      if (error instanceof ProfileApiError) {
        const correlation = error.correlationId ? ` Correlation ID: ${error.correlationId}.` : '';
        if (error.code === 'audit_write_failed' && error.details?.mutationCommitted) {
          return `The profile changed, but its audit record failed. Reload before retrying.${correlation}`;
        }
        return `${error.message}${correlation}`;
      }
      return error?.message || 'The cloud profile request failed.';
    }
    function updateProfileControls() {
      const entraSignedIn = Boolean(entraAuthClient?.getAccount());
      const popupPending = Boolean(entraAuthClient?.popupPending);
      elements.signInButton.disabled = hasEmbeddedData || !entraAuthClient || entraSignedIn || popupPending;
      elements.signOutButton.hidden = hasEmbeddedData || !entraSignedIn;
      elements.signOutButton.disabled = hasEmbeddedData || !entraSignedIn || popupPending;
      elements.syncProfileButton.disabled = hasEmbeddedData || !profileClient || !profileSession || popupPending;
      if (!entraAuthClient && document.getElementById('signInStatus').dataset.error !== 'true') {
        setSignInStatus(elements.cloudProfileStatus.textContent);
      }
      elements.signInButton.title = hasEmbeddedData
        ? 'Microsoft Entra sign-in is unavailable in generated snapshots.'
        : (!entraAuthClient
            ? 'Microsoft Entra sign-in requires complete runtime configuration.'
            : (entraSignedIn ? 'A Microsoft Entra account is already signed in.' : 'Sign in with Microsoft Entra.'));
      elements.signOutButton.title = hasEmbeddedData
        ? 'Microsoft Entra sign-out is unavailable in generated snapshots.'
        : (entraSignedIn ? 'Sign out of the active Microsoft Entra session.' : 'No Microsoft Entra account is signed in.');
      elements.syncProfileButton.title = hasEmbeddedData
        ? 'Cloud profile synchronization is unavailable in generated snapshots.'
        : (!profileClient
            ? 'Cloud profile synchronization requires a configured protected BFF URL.'
            : (profileSession ? 'Reload settings from the active cloud profile.' : 'Sign in or activate a recovery profile first.'));
      elements.saveSettingsButton.textContent = profileSession ? 'Save local and cloud settings' : 'Save local settings';
    }
    async function loadCloudProfile(statusPrefix = 'Cloud profile') {
      const authentication = profileAuthentication();
      if (!profileClient || !authentication) throw new Error('Cloud profile synchronization is not active.');
      elements.cloudProfileStatus.textContent = `${statusPrefix}: loading...`;
      const result = await profileClient.getProfile(authentication);
      profileSession.etag = result.etag;
      if (result.profile) {
        applyProfileSettings(result.profile.settings);
        elements.cloudProfileStatus.textContent = `${statusPrefix} loaded for ${result.profile.ownerKey}. Updated ${displayValue('UpdatedAtUtc', result.profile.updatedAtUtc)}.`;
      } else {
        elements.cloudProfileStatus.textContent = `${statusPrefix} has no saved settings yet. Saving Settings will create it.`;
      }
      updateProfileControls();
      return result;
    }
    async function saveCloudProfile() {
      const authentication = profileAuthentication();
      if (!profileClient || !authentication) return null;
      try {
        const result = await profileClient.putProfile(currentProfileSettings(), authentication, profileSession.etag);
        profileSession.etag = result.etag;
        elements.cloudProfileStatus.textContent = `Cloud profile saved for ${result.profile.ownerKey}.`;
        return result;
      } catch (error) {
        if (error instanceof ProfileApiError && error.code === 'audit_write_failed' && error.details?.mutationCommitted) {
          try {
            await loadCloudProfile('Cloud profile after partial failure');
          } catch {
            profileSession.etag = '';
          }
        }
        throw error;
      } finally {
        updateProfileControls();
      }
    }
    async function activateRecoveryProfile(profile, remembered = false) {
      profileSession = {
        type: 'recovery',
        recoveryCode: profile.recoveryCode,
        ownerKey: profile.ownerKey,
        profile,
        etag: ''
      };
      elements.rememberRecoveryProfile.checked = remembered;
      updateProfileControls();
      if (!profileClient) {
        elements.profileStatus.textContent = `Recovery profile ${profile.ownerKey} is active locally, but no protected BFF is configured.`;
        return;
      }
      try {
        await loadCloudProfile(remembered ? 'Remembered recovery profile' : 'Recovery profile');
        elements.profileStatus.textContent = `Recovery identity ${profile.ownerKey} is active for cloud synchronization.`;
      } catch (error) {
        elements.profileStatus.textContent = profileErrorMessage(error);
      }
    }
    function updateSettingsForm() {
      elements.defaultViewSetting.value = state.defaultView;
      elements.pageSizeSetting.value = text(state.size);
      elements.timeDisplaySetting.value = state.timeDisplay;
      elements.staleThresholdSetting.value = text(state.staleThresholdDays);
      elements.reviewWindowSetting.value = text(state.reviewWindowDays);
      elements.csvPrefixSetting.value = state.csvFilenamePrefix;
      elements.groupByComputerSetting.checked = state.grouped;
      updateNumberSuggestionStates();
    }
    function updateNumberSuggestionStates() {
      document.querySelectorAll('[data-number-target]').forEach(button => {
        const input = document.getElementById(button.dataset.numberTarget);
        button.setAttribute('aria-pressed', text(input?.value) === button.dataset.numberValue ? 'true' : 'false');
      });
    }
    function updateRecoveryStatus() {
      const profile = hasEmbeddedData ? null : loadRecoveryProfile();
      if (hasEmbeddedData) {
        elements.profileStatus.textContent = 'Recovery profile operations are disabled in generated snapshots.';
        return;
      }
      elements.rememberRecoveryProfile.checked = Boolean(profile);
      elements.profileStatus.textContent = profile
        ? `A recovery profile is remembered for owner ${profile.ownerKey}. Created ${displayValue('CreatedAtUtc', profile.createdAtUtc)}.`
        : 'No recovery profile is remembered in this browser.';
    }
    function showRecoveryResult(profile, stored, imported = false) {
      elements.recoveryResult.hidden = false;
      elements.recoveryCodeOutput.textContent = profile.recoveryCode;
      elements.profileStatus.textContent = `${imported ? 'Recovery code validated' : 'Recovery profile generated'}. Owner ${profile.ownerKey}.${stored ? ' It is remembered in this browser profile.' : ' It was not saved in browser storage.'}`;
    }
    function applyFreshnessThreshold() {
      const byComputerSid = new Map(REPORT.devices.map(device => [text(device.ComputerSid), device]));
      REPORT.devices.forEach(device => {
        const freshness = calculateReportingState(device.LastReportUtc, state.staleThresholdDays);
        device.DaysSinceLastReport = freshness.days;
        device.ReportingState = freshness.state;
      });
      REPORT.summary.forEach(row => {
        const device = byComputerSid.get(text(row.SID));
        const freshness = calculateReportingState(device?.LastReportUtc, state.staleThresholdDays);
        row.ReportingState = freshness.state;
      });
      views.devices.rows = REPORT.devices;
      views.summary.rows = REPORT.summary;
      REPORT.review = resolveReviewData(REPORT.summary, REPORT.governance, REPORT.actions, state.reviewWindowDays);
      views.review.rows = REPORT.review;
    }
    function canProposeRules() {
      return !hasEmbeddedData && Boolean(adminController) && Boolean(entraAuthClient?.getAccount());
    }
    function adminActionsVisible() {
      if (hasEmbeddedData || !adminController) return false;
      if (state.view === 'governance') return adminController.active;
      return state.view === 'review' && canProposeRules();
    }
    function adminErrorMessage(error) {
      if (error instanceof ProfileApiError) {
        const correlation = error.correlationId ? ` Correlation ID: ${error.correlationId}.` : '';
        if (error.code === 'role_required' && Array.isArray(error.details?.requiredRoles)) {
          return `${error.message} Required app role: ${error.details.requiredRoles.join(' or ')}.${correlation}`;
        }
        if (error.code === 'audit_write_failed' && error.details?.mutationCommitted) {
          return `The change was saved, but its audit record failed. Reload before retrying.${correlation}`;
        }
      }
      return profileErrorMessage(error);
    }
    async function privilegedFailureMessage(error) {
      if (isAdminSessionError(error)) {
        await adminController?.exit('expired');
        return 'Admin mode expired or lost its Conditional Access confirmation. Enter Admin mode again.';
      }
      if (error instanceof ProfileApiError && error.status === 412) {
        try {
          await loadGovernanceFromBackend();
        } catch {
          // The original conflict message remains more useful than a secondary reload failure.
        }
        return 'The rule was changed by someone else. The latest version was reloaded; review it and try again.';
      }
      return adminErrorMessage(error);
    }
    function refreshGovernanceViews() {
      views.governance.rows = REPORT.governance;
      applyFreshnessThreshold();
      updateCapabilityState();
      if (views[state.view]) render();
    }
    async function loadGovernanceFromBackend() {
      const result = await adminController.client.listRules(adminController.authentication(), 'governance');
      const rules = Array.isArray(result?.rules) ? result.rules : [];
      REPORT.governance = [...REPORT.governance.filter(rule => text(rule.PartitionKey).toLowerCase() !== 'org'), ...rules];
      refreshGovernanceViews();
      return rules.length;
    }
    function mergeGovernanceRule(rule) {
      if (!rule?.RowKey) return;
      const key = `${text(rule.PartitionKey).toLowerCase()}|${text(rule.RowKey).toLowerCase()}`;
      REPORT.governance = [
        ...REPORT.governance.filter(existing => `${text(existing.PartitionKey).toLowerCase()}|${text(existing.RowKey).toLowerCase()}` !== key),
        rule
      ];
      refreshGovernanceViews();
    }
    function updateAdminCountdown(remainingMs, totalRemainingMs) {
      for (const [element, milliseconds] of [[elements.adminIdleRemaining, remainingMs], [elements.adminTotalRemaining, totalRemainingMs]]) {
        const seconds = Math.ceil(milliseconds / 1000);
        element.textContent = `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
      }
      elements.adminIdleCountdown.hidden = !adminController?.active;
    }
    function handleAdminModeChange(change) {
      adminStatusMessage = change.active ? '' : ({
        idle: `Admin mode ended after ${adminIdleTimeoutMinutes} minutes without activity.`,
        expired: 'Admin mode expired. Enter it again to continue privileged work.',
        signout: 'Admin mode ended because you signed out.',
        account_changed: 'Admin mode ended because the signed-in account changed.'
      }[change.reason] || 'Admin mode ended. The elevated token was discarded.');
      if (!change.active && elements.reasonDialog.open) elements.reasonDialog.close();
      updateCapabilityState();
      if (views[state.view]) render();
    }
    function adminActionButton(label, enabledReason, onClick, warning = false) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = `admin-action${warning ? ' warning' : ''}`;
      button.textContent = label;
      button.disabled = Boolean(enabledReason);
      button.title = enabledReason || `${label} this item.`;
      if (!enabledReason) button.addEventListener('click', onClick);
      return button;
    }
    function renderAdminActionsCell(row) {
      const cell = document.createElement('td');
      cell.className = 'admin-actions-cell';
      if (state.view === 'review') {
        cell.appendChild(adminActionButton('Propose rule', '', () => openRuleDialog(proposalFromReviewRow(row))));
        cell.lastChild.title = 'Propose a governance rule prefilled from this access entry.';
        return cell;
      }
      if (text(row.RuleScope) !== 'Governance') {
        cell.textContent = 'Personal rule';
        return cell;
      }
      const capabilities = adminController.capabilities;
      const status = text(row.Status);
      const ownProposal = Boolean(adminController.session?.ownerKey) && text(row.CreatedByOwnerKey) === adminController.session.ownerKey;
      const baseReason = !capabilities.approveRules
        ? 'Requires the LocalAdmin.Governance.Approve app role.'
        : (!row.ETag ? 'This rule was not loaded from the protected backend. Re-enter Admin mode to reload it.' : '');
      const approveReason = baseReason || (status !== 'PendingApproval'
        ? `Only pending proposals can be approved. Current status: ${status || 'unknown'}.`
        : (ownProposal && !capabilities.selfApprove
            ? 'Four-eyes principle: another approver must approve your own proposal. The LocalAdmin.Governance.SelfApprove role permits this explicitly.'
            : ''));
      const rejectReason = baseReason || (status !== 'PendingApproval' ? `Only pending proposals can be rejected. Current status: ${status || 'unknown'}.` : '');
      const revokeReason = baseReason || (!['Active', 'PendingApproval'].includes(status) ? `Only active or pending rules can be revoked. Current status: ${status || 'unknown'}.` : '');
      const principalContext = [text(row.PrincipalDisplayName), text(row.PrincipalUserPrincipalName)].filter(Boolean).join(' / ');
      const ruleLabel = `${text(row.Effect)} ${text(row.PrincipalType).toLowerCase()} ${principalContext ? `${principalContext} (informational), ` : ''}${text(row.PrincipalValue)} (${text(row.DeviceScopeType)}${row.DeviceScopeValue ? ` ${text(row.DeviceScopeValue)}` : ''})`;
      const transition = (operation, title, required, submitLabel) => () => openReasonDialog({
        title,
        summary: `${ruleLabel}. Rule ID ${text(row.RowKey)}.${operation === 'approve' && ownProposal ? ' You proposed this rule; the approval is recorded as self-approved.' : ''}`,
        rule: row,
        required,
        submitLabel,
        onSubmit: async reason => {
          const updated = await adminController.client.transitionRule(adminController.authentication(), text(row.RowKey), operation, reason, row.ETag);
          mergeGovernanceRule(updated);
          adminStatusMessage = `Rule ${text(row.RowKey)} is now ${text(updated?.Status) || 'updated'}.`;
          updateCapabilityState();
        }
      });
      cell.append(
        adminActionButton('Approve', approveReason, transition('approve', 'Approve governance rule', false, 'Approve')),
        adminActionButton('Reject', rejectReason, transition('reject', 'Reject governance proposal', true, 'Reject'), true),
        adminActionButton('Revoke', revokeReason, transition('revoke', 'Revoke governance rule', true, 'Revoke'), true)
      );
      const preview = document.createElement('p');
      preview.className = 'dialog-preview governance-preview';
      renderRulePreview(preview, row);
      cell.appendChild(preview);
      return cell;
    }
    function openReasonDialog({ title, summary, rule, required, submitLabel, onSubmit }) {
      pendingReasonAction = { required, onSubmit };
      elements.reasonDialogTitle.textContent = title;
      elements.reasonDialogSummary.textContent = summary;
      elements.reasonRulePreview.hidden = !rule;
      if (rule) renderRulePreview(elements.reasonRulePreview, rule);
      elements.reasonInput.value = '';
      elements.reasonInput.placeholder = required ? 'Required: at least 10 characters for the audit record.' : 'Optional comment for the audit record.';
      elements.reasonFormStatus.textContent = '';
      elements.reasonSubmitButton.textContent = submitLabel;
      elements.reasonSubmitButton.disabled = false;
      elements.reasonDialog.showModal();
      elements.reasonInput.focus();
    }
    function setRuleForm(draft) {
      elements.ruleEffect.value = draft.effect || 'Allow';
      elements.rulePrincipalType.value = draft.principalType || 'User';
      elements.rulePrincipalSid.value = draft.principalSid || '';
      elements.rulePrincipalSource.value = draft.principalSource || 'Any';
      elements.ruleMembershipScope.value = draft.membershipScope || 'Any';
      elements.ruleAssignedThroughGroupSid.value = draft.assignedThroughGroupSid || '';
      elements.ruleDeviceScopeType.value = draft.deviceScopeType || 'Any';
      elements.ruleDeviceScopeValue.value = draft.deviceScopeValue || '';
      elements.ruleAllowedEntraJoined.checked = draft.allowedEntraJoined !== false;
      elements.ruleAllowedHybridJoined.checked = draft.allowedHybridJoined !== false;
      elements.ruleAllowedDomainJoined.checked = draft.allowedDomainJoined !== false;
      elements.ruleMaxDeviceAgeDays.value = draft.maxDeviceAgeDays ? text(draft.maxDeviceAgeDays) : '';
      elements.ruleValidFrom.value = '';
      elements.ruleValidUntil.value = '';
      elements.ruleTicketReference.value = '';
      elements.ruleReason.value = draft.reason || '';
      for (const picker of identityPickers) picker.cancel();
      for (const id of ['ruleIdentityQuery', 'ruleGroupQuery', 'ruleIdentityStatus', 'ruleGroupStatus']) {
        if ('value' in elements[id]) elements[id].value = '';
        else elements[id].textContent = '';
      }
      elements.ruleIdentityResults.replaceChildren();
      elements.ruleGroupResults.replaceChildren();
      selectedPrincipal = searchLocalIdentities(REPORT, elements.rulePrincipalType.value, draft.principalSid)
        .identities.find(item => item.sid === normalizeSidInput(draft.principalSid)) || null;
      if (!selectedPrincipal && draft.principalDisplayName) {
        selectedPrincipal = { sid: normalizeSidInput(draft.principalSid), principalType: elements.rulePrincipalType.value,
          displayName: draft.principalDisplayName, userPrincipalName: draft.principalUserPrincipalName || '' };
      }
      updateSelectedIdentity();
    }
    function readRuleForm() {
      const isoValue = value => {
        if (!value) return '';
        const date = new Date(value);
        return Number.isNaN(date.getTime()) ? value : date.toISOString();
      };
      const proposal = {
        effect: elements.ruleEffect.value,
        principalType: elements.rulePrincipalType.value,
        principalSid: normalizeSidInput(elements.rulePrincipalSid.value),
        principalSource: elements.rulePrincipalSource.value,
        membershipScope: elements.ruleMembershipScope.value,
        deviceScopeType: elements.ruleDeviceScopeType.value,
        allowedEntraJoined: elements.ruleAllowedEntraJoined.checked,
        allowedHybridJoined: elements.ruleAllowedHybridJoined.checked,
        allowedDomainJoined: elements.ruleAllowedDomainJoined.checked,
        reason: elements.ruleReason.value.trim()
      };
      const groupSid = normalizeSidInput(elements.ruleAssignedThroughGroupSid.value);
      const maxAge = elements.ruleMaxDeviceAgeDays.value.trim();
      const validFrom = isoValue(elements.ruleValidFrom.value);
      const validUntil = isoValue(elements.ruleValidUntil.value);
      const ticket = elements.ruleTicketReference.value.trim();
      if (selectedPrincipal?.sid === proposal.principalSid && selectedPrincipal.principalType === proposal.principalType) {
        if (selectedPrincipal.displayName) proposal.principalDisplayName = selectedPrincipal.displayName;
        if (selectedPrincipal.userPrincipalName) proposal.principalUserPrincipalName = selectedPrincipal.userPrincipalName;
      }
      if (groupSid) proposal.assignedThroughGroupSid = groupSid;
      if (proposal.deviceScopeType !== 'Any') proposal.deviceScopeValue = elements.ruleDeviceScopeValue.value.trim();
      if (maxAge) proposal.maxDeviceAgeDays = Number(maxAge);
      if (validFrom) proposal.validFromUtc = validFrom;
      if (validUntil) proposal.validUntilUtc = validUntil;
      if (ticket) proposal.ticketReference = ticket;
      return proposal;
    }
    function updateSelectedIdentity() {
      elements.ruleIdentitySummary.textContent = selectedPrincipal
        ? `Selected: ${selectedPrincipal.displayName}${selectedPrincipal.userPrincipalName ? ` (${selectedPrincipal.userPrincipalName})` : ''}. SID: ${selectedPrincipal.sid}. Names are informational, not matching criteria.`
        : "The selected SID is the rule's matching value. Names are informational only.";
    }
    function lookupAccountId() {
      return !hasEmbeddedData && profileClient ? entraAuthClient?.getAccount()?.homeAccountId || '' : '';
    }
    function createIdentityPicker(groupOnly) {
      const input = groupOnly ? elements.ruleGroupQuery : elements.ruleIdentityQuery;
      const results = groupOnly ? elements.ruleGroupResults : elements.ruleIdentityResults;
      const status = groupOnly ? elements.ruleGroupStatus : elements.ruleIdentityStatus;
      const sidInput = groupOnly ? elements.ruleAssignedThroughGroupSid : elements.rulePrincipalSid;
      const picker = new LocalFirstIdentityLookup({
        localSearch: (type, query) => searchLocalIdentities(REPORT, type, query),
        remoteSearch: async (type, query, accountId, signal) => {
          if (lookupAccountId() !== accountId) throw new Error('The signed-in account changed. Search again.');
          const authentication = { type: 'entra', getAccessToken: () => entraAuthClient.getAccessToken() };
          const { payload } = await profileClient.request('GET', `/identities/lookup?${new URLSearchParams({ type, q: query })}`, authentication, { signal });
          if (lookupAccountId() !== accountId) throw new Error('The signed-in account changed. Search again.');
          return payload;
        },
        onChange: result => {
          status.textContent = `${result.message}${result.truncated ? ' More results exist; narrow your search.' : ''}`;
          results.replaceChildren();
          for (const identity of result.identities) {
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'detail-link identity-result';
            button.textContent = `${identity.displayName}${identity.userPrincipalName ? ` (${identity.userPrincipalName})` : ''} | ${identity.source} | ${identity.sid} | ${identity.origin === 'inventory' ? 'Loaded inventory' : 'Entra directory'}`;
            button.addEventListener('click', () => {
              picker.cancel();
              sidInput.value = identity.sid;
              if (groupOnly) {
                elements.ruleMembershipScope.value = 'Transitive';
              } else {
                selectedPrincipal = identity;
                elements.rulePrincipalSource.value = ['Local', 'Entra', 'AD'].includes(identity.source) ? identity.source : 'Any';
                updateSelectedIdentity();
              }
              results.replaceChildren();
              status.textContent = `Selected ${identity.sid}.`;
              updateRulePreview();
            });
            results.appendChild(button);
          }
        }
      });
      const search = () => {
        sidInput.value = '';
        if (!groupOnly) { selectedPrincipal = null; updateSelectedIdentity(); }
        picker.search(input.value, groupOnly ? 'Group' : elements.rulePrincipalType.value, lookupAccountId());
        updateRulePreview();
      };
      input.addEventListener('input', search);
      input.addEventListener('keydown', event => {
        if (event.key === 'Enter') event.preventDefault();
      });
      sidInput.addEventListener('input', () => {
        picker.cancel();
        input.value = '';
        results.replaceChildren();
        status.textContent = '';
        if (!groupOnly) { selectedPrincipal = null; updateSelectedIdentity(); }
      });
      if (!groupOnly) elements.rulePrincipalType.addEventListener('change', search);
      return picker;
    }
    function renderIdentityTable(head, body, columns, rows) {
      const header = document.createElement('tr');
      for (const [, label] of columns) {
        const cell = document.createElement('th');
        cell.scope = 'col';
        cell.textContent = label;
        header.appendChild(cell);
      }
      head.replaceChildren(header);
      body.replaceChildren(...rows.slice(0, 250).map(entry => {
        const row = document.createElement('tr');
        for (const [key] of columns) {
          const cell = document.createElement('td');
          cell.textContent = key === 'Removed' ? (Number(entry[key]) === 1 ? 'Removed' : 'Active') : displayValue(key, entry[key]);
          row.appendChild(cell);
        }
        return row;
      }));
    }
    function openIdentityUsageDialog(row, principalType) {
      const sid = text(principalType === 'User' ? row.UserID : row.GroupID);
      const usage = identityUsage(REPORT, principalType, sid);
      elements.identityUsageSummary.textContent = `${text(row.UserPrincipalName || row.SamAccountName || row.GroupName)} (${sid}): ${formatter.format(usage.entries.length)} access paths on ${formatter.format(usage.computers)} computers; ${formatter.format(usage.rules.length)} related loaded rules.`;
      renderIdentityTable(elements.identityUsageHead, elements.identityUsageBody, [
        ['ComputerName', 'Computer'], ['PrincipalName', 'Principal'], ['PrincipalID', 'Principal SID'],
        ['MembershipType', 'Membership'], ['AddedThroughGroupName', 'Through group'],
        ['AssignedThroughGroupSid', 'Through group SID'], ['JoinState', 'Join state'], ['Removed', 'Status']
      ], usage.entries);
      renderIdentityTable(elements.identityRulesHead, elements.identityRulesBody, [
        ['RowKey', 'Rule ID'], ['Status', 'Status'], ['Effect', 'Effect'], ['PrincipalType', 'Principal type'],
        ['PrincipalDisplayName', 'Name (informational)'], ['PrincipalValue', 'SID'],
        ['AssignedThroughGroupSid', 'Through group SID'], ['DeviceScopeType', 'Device scope'], ['DeviceScopeValue', 'Device value']
      ], usage.rules);
      elements.identityUsageDialog.showModal();
    }
    function updateRulePreview() {
      elements.ruleDeviceScopeValue.disabled = elements.ruleDeviceScopeType.value === 'Any';
      elements.ruleDeviceScopeValue.title = elements.ruleDeviceScopeValue.disabled ? 'Choose an exact computer or name prefix scope first.' : 'Exact computer name or name prefix. Wildcards are not supported.';
      const proposal = readRuleForm();
      if (!REPORT.review.length) {
        renderRulePreview(elements.rulePreview, previewRuleFromProposal(proposal));
        return;
      }
      if (!/^S-\d(?:-\d+)+$/i.test(proposal.principalSid)) {
        elements.rulePreview.textContent = 'Enter a valid principal SID to preview matches.';
        return;
      }
      renderRulePreview(elements.rulePreview, previewRuleFromProposal(proposal));
    }
    function rulePreviewSummary(preview) {
      return `Preview: matches ${formatter.format(preview.rows)} loaded review ${preview.rows === 1 ? 'entry' : 'entries'} on ${formatter.format(preview.computers)} ${preview.computers === 1 ? 'computer' : 'computers'}.`;
    }
    function renderRulePreview(container, rule) {
      container.replaceChildren();
      if (!REPORT.review.length) {
        container.textContent = 'Load inventory data to preview which access entries this rule would match.';
        return;
      }
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'rule-preview-link';
      button.textContent = rulePreviewSummary(previewRuleMatches(rule, REPORT.review));
      button.setAttribute('aria-haspopup', 'dialog');
      button.setAttribute('aria-controls', 'ruleMatchesDialog');
      button.addEventListener('click', () => openRuleMatchesDialog(rule));
      container.appendChild(button);
    }
    function openRuleMatchesDialog(rule) {
      const preview = previewRuleMatches(rule, REPORT.review);
      elements.ruleMatchesSummary.textContent = `${text(rule.Effect)} ${text(rule.PrincipalType)} ${text(rule.PrincipalValue)}. ${rulePreviewSummary(preview)}`;
      const columns = [
        ['ComputerName', 'Computer name'], ['PrincipalName', 'Principal name'],
        ['PrincipalID', 'Principal SID'], ['PrincipalType', 'Principal type'],
        ['PrincipalSource', 'Principal source'], ['MembershipType', 'Membership type'],
        ['AddedThroughGroupName', 'Added through group'], ['AssignedThroughGroupSid', 'Assigned-through group SID'],
        ['JoinState', 'Join state'], ['LastReportUtc', 'Last report'],
        ['PolicyStatus', 'Current policy status'], ['ReviewStatus', 'Current review status']
      ];
      const header = document.createElement('tr');
      for (const [, label] of columns) {
        const cell = document.createElement('th');
        cell.scope = 'col';
        cell.textContent = label;
        header.appendChild(cell);
      }
      elements.ruleMatchesHead.replaceChildren(header);
      const rows = preview.entries.map(entry => {
        const row = document.createElement('tr');
        for (const [key] of columns) {
          const cell = document.createElement('td');
          cell.textContent = displayValue(key, key === 'AssignedThroughGroupSid'
            ? entry.AssignedThroughGroupSid || entry._AssignedThroughGroupSID
            : entry[key]);
          row.appendChild(cell);
        }
        return row;
      });
      elements.ruleMatchesBody.replaceChildren(...rows);
      elements.ruleMatchesEmpty.hidden = preview.rows !== 0;
      elements.ruleMatchesDialog.showModal();
    }
    function openRuleDialog(draft = proposalFromReviewRow({})) {
      if (!canProposeRules()) return;
      setRuleForm(draft);
      pendingProposalKey = '';
      pendingProposalFingerprint = '';
      elements.ruleFormStatus.textContent = '';
      elements.ruleSubmitButton.disabled = false;
      updateRulePreview();
      elements.ruleDialog.showModal();
      (draft.principalSid ? elements.ruleReason : elements.ruleIdentityQuery).focus();
    }

    identityPickers.push(createIdentityPicker(false), createIdentityPicker(true));
    elements.ruleDialog.addEventListener('close', () => identityPickers.forEach(picker => picker.cancel()));
    elements.identityUsageCloseButton.addEventListener('click', () => elements.identityUsageDialog.close());
    elements.connectionPanel.hidden = hasEmbeddedData;
    elements.groupToggle.checked = state.grouped;
    elements.pageSize.value = text(state.size);
    elements.staleThreshold.value = text(state.staleThresholdDays);
    updateSettingsForm();
    updateRecoveryStatus();
    if (hasEmbeddedData) {
      for (const element of [elements.generateRecoveryButton, elements.importRecoveryButton, elements.forgetRecoveryButton, elements.recoveryCodeInput, elements.rememberRecoveryProfile]) {
        element.disabled = true;
        element.title = 'Recovery profile operations are unavailable in generated snapshots.';
      }
      elements.cloudProfileStatus.textContent = 'Cloud profile synchronization and Microsoft Entra sign-in are disabled in generated snapshots.';
    }
    restoreSavedConnection();
    void runtimeConfigPromise.then(applyRuntimeConfig).catch(error => {
      elements.cloudProfileStatus.textContent = `Runtime configuration could not be applied: ${error.message}`;
      setSignInStatus(elements.cloudProfileStatus.textContent, true);
      return applyRuntimeConfig(runtimeConfigDefaults);
    });
    updateCapabilityState();
    updateReportSummary();
    activateView(views[state.view] || state.view === 'settings' || state.view === 'guidance' ? state.view : 'summary');
    history.replaceState({ localAdminReport: true, viewState: captureViewState() }, '', location.href.split('#')[0]);
    document.querySelectorAll('.tab').forEach(tab => tab.addEventListener('click', () => { activateView(tab.dataset.view); persistPreferences(); updateCurrentHistoryState(); }));
    elements.search.addEventListener('input', event => { state.query = event.target.value; state.page = 1; if (state.view === 'summary') { state.linked = false; elements.backButton.classList.remove('visible'); } render(); updateCurrentHistoryState(); });
    elements.joinFilter.addEventListener('change', event => { state.join = event.target.value; state.page = 1; render(); updateCurrentHistoryState(); });
    elements.removedFilter.addEventListener('change', event => { state.removed = event.target.value; state.page = 1; render(); updateCurrentHistoryState(); });
    elements.groupToggle.addEventListener('change', event => { state.grouped = event.target.checked; state.expandedComputers = []; state.expandedGroups = []; state.sortRules = [{ key: 'ComputerName', direction: 1 }]; state.page = 1; persistPreferences(); render(); updateCurrentHistoryState(); });
    elements.pageSize.addEventListener('change', event => { state.size = Number(event.target.value); state.page = 1; persistPreferences(); render(); updateCurrentHistoryState(); });
    elements.staleThreshold.addEventListener('change', event => {
      const value = Number(event.target.value);
      if (!Number.isInteger(value) || value < 1) {
        event.target.value = text(state.staleThresholdDays);
        return;
      }
      state.staleThresholdDays = value;
      applyFreshnessThreshold();
      persistPreferences();
      render();
      updateCurrentHistoryState();
    });
    elements.resetButton.addEventListener('click', () => { state.query = state.join = state.removed = ''; state.expandedComputers = []; state.expandedGroups = []; state.page = 1; elements.search.value = elements.joinFilter.value = elements.removedFilter.value = ''; render(); updateCurrentHistoryState(); });
    elements.resetTableLayoutButton.addEventListener('click', () => {
      state.tableLayouts[state.view] = defaultColumnLayoutForView(state.view);
      scheduleTableLayoutPersistence();
      render();
      updateCurrentHistoryState();
    });
    elements.exportButton.addEventListener('click', exportCsv); elements.backButton.addEventListener('click', () => history.back());
    elements.ruleMatchesCloseButton.addEventListener('click', () => elements.ruleMatchesDialog.close());
    elements.forgetConnection.addEventListener('click', () => {
      const removed = removeConnection();
      elements.storageAccountName.value = '';
      elements.sasToken.value = '';
      elements.governanceStorageAccountName.value = '';
      elements.governanceSasToken.value = '';
      elements.rememberConnection.checked = false;
      elements.refreshStatus.textContent = removed ? 'Saved connection forgotten. Loaded report data remains available until this page is closed or refreshed.' : 'The browser did not allow the saved connection to be removed.';
      updateCapabilityState();
    });
    elements.refreshButton.addEventListener('click', refreshFromAzure);
    elements.governanceStorageAccountName.addEventListener('input', updateCapabilityState);
    elements.governanceSasToken.addEventListener('input', updateCapabilityState);
    elements.rememberConnection.addEventListener('change', () => {
      if (!elements.rememberConnection.checked) {
        const removed = removeConnection();
        elements.refreshStatus.textContent = removed
          ? 'Saved connection credentials were removed from this browser profile.'
          : 'The browser did not allow the saved connection credentials to be removed.';
        return;
      }
      const result = rememberCurrentConnection();
      if (!result.saved) {
        elements.rememberConnection.checked = false;
        elements.refreshStatus.textContent = `Connection was not saved. ${result.message}`;
        return;
      }
      elements.refreshStatus.textContent = result.message;
    });
    document.querySelectorAll('[data-number-target]').forEach(button => {
      button.addEventListener('click', () => {
        const input = document.getElementById(button.dataset.numberTarget);
        if (!input) return;
        input.value = button.dataset.numberValue;
        input.dispatchEvent(new Event('input', { bubbles: true }));
      });
    });
    for (const input of [elements.staleThresholdSetting, elements.reviewWindowSetting]) {
      input.addEventListener('input', updateNumberSuggestionStates);
    }
    elements.saveSettingsButton.addEventListener('click', async () => {
      const staleDays = Number(elements.staleThresholdSetting.value);
      const reviewDays = Number(elements.reviewWindowSetting.value);
      const prefix = elements.csvPrefixSetting.value.trim();
      if (!Number.isInteger(staleDays) || staleDays < 1 || !Number.isInteger(reviewDays) || reviewDays < 1) {
        elements.settingsStatus.textContent = 'Stale and review windows must be positive whole numbers.';
        return;
      }
      if (!/^[A-Za-z0-9_-]{1,40}$/.test(prefix)) {
        elements.settingsStatus.textContent = 'CSV prefix may contain only letters, numbers, underscores, and hyphens.';
        return;
      }
      state.defaultView = elements.defaultViewSetting.value;
      state.size = Number(elements.pageSizeSetting.value);
      state.timeDisplay = elements.timeDisplaySetting.value;
      state.staleThresholdDays = staleDays;
      state.reviewWindowDays = reviewDays;
      state.csvFilenamePrefix = prefix;
      state.grouped = elements.groupByComputerSetting.checked;
      elements.pageSize.value = text(state.size);
      elements.staleThreshold.value = text(state.staleThresholdDays);
      elements.groupToggle.checked = state.grouped;
      applyFreshnessThreshold();
      updateReportSummary();
      const localSaved = persistPreferences();
      elements.settingsStatus.textContent = localSaved ? 'Local settings saved.' : 'The browser did not allow local settings to be saved.';
      if (profileSession) {
        try {
          await saveCloudProfile();
          elements.settingsStatus.textContent = localSaved ? 'Local and cloud settings saved.' : 'Cloud settings saved, but browser-local storage failed.';
        } catch (error) {
          elements.settingsStatus.textContent = `Local settings saved; cloud save failed. ${profileErrorMessage(error)}`;
        }
      }
    });
    document.getElementById('retryAuthButton').addEventListener('click', () => {
      if (entraAuthClient?.popupPending) {
        if (!entraAuthClient.getAccount()) setSignInStatus('Opening Microsoft Entra sign-in...');
        entraAuthClient.retryPopup();
      }
    });
    elements.signInButton.addEventListener('click', async () => {
      setSignInStatus('Opening Microsoft Entra sign-in...');
      try {
        const account = await entraAuthClient.signIn();
        identityPickers.forEach(picker => picker.reset());
        setSignInStatus(`Signed in as ${account.username || account.name || 'Microsoft Entra user'}.`);
        if (adminController?.accountChanged(account)) await adminController.exit('account_changed');
        profileSession = { type: 'entra', etag: '', account };
        updateProfileControls();
        updateCapabilityState();
        if (views[state.view]) render();
        try {
          await loadCloudProfile(`Microsoft Entra profile for ${account.username || account.name || 'signed-in user'}`);
        } catch (error) {
          elements.cloudProfileStatus.textContent = profileErrorMessage(error);
          setSignInStatus(`Signed in, but the cloud profile could not be loaded: ${profileErrorMessage(error)}`, true);
        }
      } catch (error) {
        setSignInStatus(profileErrorMessage(error), true);
        updateProfileControls();
      }
    });
    elements.signOutButton.addEventListener('click', async () => {
      identityPickers.forEach(picker => picker.reset());
      elements.ruleIdentityResults.replaceChildren();
      elements.ruleGroupResults.replaceChildren();
      await adminController?.exit('signout');
      try {
        await entraAuthClient.signOut();
      } catch (error) {
        elements.cloudProfileStatus.textContent = `Microsoft Entra sign-out did not complete: ${error.message}`;
        setSignInStatus(elements.cloudProfileStatus.textContent, true);
        updateCapabilityState();
        return;
      }
      if (profileSession?.type === 'entra') profileSession = null;
      elements.cloudProfileStatus.textContent = 'Signed out. OAuth tokens and the Entra profile session were removed from browser memory.';
      setSignInStatus('Signed out. Sign in with Microsoft Entra to continue.');
      updateProfileControls();
      updateCapabilityState();
      if (views[state.view]) render();
    });
    elements.adminModeButton.addEventListener('click', async () => {
      if (!adminController || adminBusy) return;
      adminBusy = true;
      updateCapabilityState();
      try {
        if (adminController.active) {
          await adminController.exit('user');
        } else {
          setAdminModeStatus('Confirming Admin mode with Microsoft Entra. Complete the sign-in prompt if one opens...');
          await adminController.enter();
          try {
            const count = await loadGovernanceFromBackend();
            adminStatusMessage = `Loaded ${formatter.format(count)} governance rules from the protected backend.`;
          } catch (error) {
            adminStatusMessage = `Governance rules could not be loaded: ${await privilegedFailureMessage(error)}`;
            markAdminStatusError();
          }
        }
      } catch (error) {
        adminStatusMessage = `Admin mode was not entered: ${adminErrorMessage(error)}`;
        markAdminStatusError();
      } finally {
        adminBusy = false;
        updateCapabilityState();
        if (views[state.view]) render();
      }
    });
    for (const eventName of ['pointerdown', 'keydown']) {
      document.addEventListener(eventName, () => adminController?.touch(), { passive: true });
    }
    elements.proposeRuleButton.addEventListener('click', () => openRuleDialog());
    elements.ruleCancelButton.addEventListener('click', () => elements.ruleDialog.close());
    elements.reasonCancelButton.addEventListener('click', () => elements.reasonDialog.close());
    elements.ruleForm.addEventListener('input', updateRulePreview);
    elements.ruleForm.addEventListener('change', updateRulePreview);
    elements.ruleForm.addEventListener('submit', async event => {
      event.preventDefault();
      const proposal = readRuleForm();
      const errors = validateProposalDraft(proposal);
      if (errors.length) {
        elements.ruleFormStatus.textContent = errors.join(' ');
        return;
      }
      const fingerprint = JSON.stringify(proposal);
      if (!pendingProposalKey || fingerprint !== pendingProposalFingerprint) {
        pendingProposalKey = globalThis.crypto.randomUUID();
        pendingProposalFingerprint = fingerprint;
      }
      elements.ruleSubmitButton.disabled = true;
      elements.ruleFormStatus.textContent = 'Submitting proposal...';
      try {
        const authentication = adminController.active
          ? adminController.authentication()
          : { type: 'entra', getAccessToken: () => entraAuthClient.getAccessToken() };
        const { rule, replay } = await adminController.client.proposeRule(authentication, proposal, pendingProposalKey);
        pendingProposalKey = '';
        pendingProposalFingerprint = '';
        elements.ruleDialog.close();
        adminStatusMessage = `${replay ? 'This proposal was already recorded' : 'Proposal submitted'}: rule ${text(rule?.RowKey)} awaits approval by a governance approver.`;
        mergeGovernanceRule(rule);
      } catch (error) {
        elements.ruleFormStatus.textContent = await privilegedFailureMessage(error);
      } finally {
        elements.ruleSubmitButton.disabled = false;
      }
    });
    elements.reasonForm.addEventListener('submit', async event => {
      event.preventDefault();
      if (!pendingReasonAction) return;
      const reason = elements.reasonInput.value.trim();
      if ((pendingReasonAction.required && reason.length < 10) || reason.length > 2000) {
        elements.reasonFormStatus.textContent = pendingReasonAction.required
          ? 'Enter a reason with 10 to 2000 characters.'
          : 'The comment may contain at most 2000 characters.';
        return;
      }
      elements.reasonSubmitButton.disabled = true;
      elements.reasonFormStatus.textContent = 'Submitting...';
      try {
        await pendingReasonAction.onSubmit(reason);
        pendingReasonAction = null;
        elements.reasonDialog.close();
      } catch (error) {
        const message = await privilegedFailureMessage(error);
        if (elements.reasonDialog.open) elements.reasonFormStatus.textContent = message;
        else {
          adminStatusMessage = message;
          markAdminStatusError();
        }
        updateCapabilityState();
      } finally {
        elements.reasonSubmitButton.disabled = false;
      }
    });
    elements.syncProfileButton.addEventListener('click', async () => {
      try {
        await loadCloudProfile();
      } catch (error) {
        elements.cloudProfileStatus.textContent = profileErrorMessage(error);
      }
    });
    elements.generateRecoveryButton.addEventListener('click', async () => {
      elements.recoveryResult.hidden = true;
      try {
        const result = await generateRecoveryProfile(elements.rememberRecoveryProfile.checked);
        showRecoveryResult(result.profile, result.stored);
        await activateRecoveryProfile(result.profile, result.stored);
        if (profileClient) {
          await saveCloudProfile();
          elements.profileStatus.textContent = `Recovery cloud profile created for ${result.profile.ownerKey}. Save the displayed recovery code now.`;
        }
      } catch (error) {
        elements.profileStatus.textContent = profileErrorMessage(error);
      }
    });
    elements.importRecoveryButton.addEventListener('click', async () => {
      elements.recoveryResult.hidden = true;
      try {
        const result = await importRecoveryProfile(elements.recoveryCodeInput.value, elements.rememberRecoveryProfile.checked);
        elements.recoveryCodeInput.value = '';
        showRecoveryResult(result.profile, result.stored, true);
        await activateRecoveryProfile(result.profile, result.stored);
      } catch (error) {
        elements.profileStatus.textContent = profileErrorMessage(error);
      }
    });
    elements.rememberRecoveryProfile.addEventListener('change', () => {
      if (profileSession?.type !== 'recovery') {
        elements.profileStatus.textContent = elements.rememberRecoveryProfile.checked
          ? 'The next generated or imported recovery profile will be remembered in this browser.'
          : 'Recovery profiles will remain in memory only unless this option is selected.';
        return;
      }
      if (elements.rememberRecoveryProfile.checked) {
        const stored = saveRecoveryProfile(profileSession.profile);
        if (!stored) elements.rememberRecoveryProfile.checked = false;
        elements.profileStatus.textContent = stored
          ? `Recovery identity ${profileSession.ownerKey} is now remembered in this browser profile.`
          : 'The browser did not allow the recovery code to be stored.';
      } else {
        const removed = removeRecoveryProfile();
        elements.profileStatus.textContent = removed
          ? `Recovery identity ${profileSession.ownerKey} remains active for this page but is no longer remembered by the browser.`
          : 'The browser did not allow the remembered recovery code to be removed.';
      }
    });
    elements.forgetRecoveryButton.addEventListener('click', () => {
      elements.recoveryResult.hidden = true;
      elements.recoveryCodeOutput.textContent = '';
      elements.recoveryCodeInput.value = '';
      elements.rememberRecoveryProfile.checked = false;
      if (profileSession?.type === 'recovery') profileSession = null;
      elements.profileStatus.textContent = removeRecoveryProfile()
        ? 'The recovery profile was forgotten by this browser. This does not revoke a cloud credential.'
        : 'The browser did not allow the recovery profile to be removed.';
      updateProfileControls();
    });
    elements.firstPage.addEventListener('click', () => { state.page = 1; render(); updateCurrentHistoryState(); }); elements.previousPage.addEventListener('click', () => { state.page--; render(); updateCurrentHistoryState(); }); elements.nextPage.addEventListener('click', () => { state.page++; render(); updateCurrentHistoryState(); }); elements.lastPage.addEventListener('click', () => { state.page = Math.max(1, Math.ceil(paginationItemCount() / state.size)); render(); updateCurrentHistoryState(); });
    window.addEventListener('popstate', event => {
      if (event.state?.localAdminReport && event.state.viewState) restoreViewState(event.state.viewState);
    });
