import { normalizedSource, ruleMatches } from './apiContract.js';

function normalized(value) {
  return String(value || '').trim().replace(/[\u2010\u2011]/g, '-');
}

export function searchLocalIdentities(report, principalType, query) {
  const term = normalized(query).toLowerCase();
  if (!term) return { identities: [], truncated: false };
  const rows = principalType === 'Group' ? report.groups || [] : report.users || [];
  const exact = [];
  const partial = [];
  for (const row of rows) {
    const values = (principalType === 'Group'
      ? [row.GroupID, row.GroupName]
      : [row.UserID, row.SamAccountName, row.UserPrincipalName, row.DisplayName]
    ).map(value => normalized(value).toLowerCase());
    if (values.includes(term)) exact.push(row);
    else if (values.some(value => value.includes(term))) partial.push(row);
  }
  const matches = [...exact, ...partial];
  return {
    identities: matches.slice(0, 20).map(row => ({
      sid: normalized(principalType === 'Group' ? row.GroupID : row.UserID).toUpperCase(),
      principalType,
      displayName: normalized(row.DisplayName || row.GroupName || row.SamAccountName),
      userPrincipalName: normalized(row.UserPrincipalName),
      source: normalizedSource(row.LocalOrEntraOrAD),
      origin: 'inventory'
    })),
    truncated: matches.length > 20
  };
}

export function identityUsage(report, principalType, sid) {
  const target = normalized(sid).toUpperCase();
  const entries = (report.summary || []).filter(row =>
    (row.PrincipalType === principalType && normalized(row.PrincipalID).toUpperCase() === target) ||
    (principalType === 'Group' && normalized(row._AssignedThroughGroupSID || row.AssignedThroughGroupSid).toUpperCase() === target)
  ).map(row => ({
    ...row,
    PrincipalName: row.UserName || row.GroupName,
    AssignedThroughGroupSid: row._AssignedThroughGroupSID || row.AssignedThroughGroupSid || ''
  }));
  const rules = (report.governance || []).filter(rule => rule.RuleScope === 'Governance' && (
    (rule.PrincipalType === principalType && rule.MatchType === 'SID' && normalized(rule.PrincipalValue).toUpperCase() === target) ||
    (principalType === 'Group' && normalized(rule.AssignedThroughGroupSid).toUpperCase() === target) ||
    entries.some(entry => ruleMatches(rule, entry))
  ));
  return { entries, rules, computers: new Set(entries.map(row => normalized(row.ComputerName).toLowerCase())).size };
}

export class LocalFirstIdentityLookup {
  constructor({ localSearch, remoteSearch, onChange, delayMs = 800, setTimer = (callback, delay) => setTimeout(callback, delay), clearTimer = timer => clearTimeout(timer), now = () => Date.now() }) {
    this.localSearch = localSearch;
    this.remoteSearch = remoteSearch;
    this.onChange = onChange;
    this.delayMs = delayMs;
    this.setTimer = setTimer;
    this.clearTimer = clearTimer;
    this.now = now;
    this.cache = new Map();
    this.sequence = 0;
  }

  cancel() {
    this.sequence++;
    if (this.timer !== undefined) this.clearTimer(this.timer);
    this.timer = undefined;
    this.abort?.abort();
    this.abort = null;
  }

  reset() {
    this.cancel();
    this.cache.clear();
  }

  search(query, principalType, accountId = '') {
    this.cancel();
    const sequence = this.sequence;
    const term = normalized(query);
    const local = this.localSearch(principalType, term);
    if (!term || local.identities.length) {
      this.onChange({ ...local, phase: 'local', message: term ? 'Matches from loaded inventory. Select a SID; no Entra search was made.' : '' });
      return;
    }
    if (!accountId || /^S-\d/i.test(term)) {
      this.onChange({ ...local, phase: 'local', message: !accountId
        ? 'No local match. Sign in with Microsoft Entra for directory lookup, or enter a SID directly.'
        : 'No local match for this SID. You can enter it directly below.' });
      return;
    }
    if (term.length < 3 || term.length > 128) {
      this.onChange({ ...local, phase: 'local', message: 'Enter 3 to 128 characters for Entra lookup.' });
      return;
    }
    const key = `${accountId}:${principalType}:${term.toLowerCase()}`;
    const cached = this.cache.get(key);
    if (cached && cached.expires > this.now()) {
      this.onChange({ ...cached.result, phase: 'directory', message: 'Cached Entra results. Select the SID appropriate for the access path.' });
      return;
    }
    this.onChange({ identities: [], phase: 'waiting', message: 'No local match. Waiting until you finish typing before searching Entra...' });
    this.timer = this.setTimer(async () => {
      this.timer = undefined;
      this.abort = new AbortController();
      this.onChange({ identities: [], phase: 'loading', message: 'Searching Entra...' });
      try {
        const result = await this.remoteSearch(principalType, term, accountId, this.abort.signal);
        if (sequence !== this.sequence) return;
        if (!result || !Array.isArray(result.identities)) throw new Error('The backend returned an invalid identity search response.');
        const refreshedLocal = this.localSearch(principalType, term);
        if (refreshedLocal.identities.length) {
          this.onChange({ ...refreshedLocal, phase: 'local', message: 'Matches from refreshed inventory. Select a SID.' });
          return;
        }
        for (const [cacheKey, value] of this.cache) if (value.expires <= this.now()) this.cache.delete(cacheKey);
        if (this.cache.size >= 100) this.cache.delete(this.cache.keys().next().value);
        this.cache.set(key, { result, expires: this.now() + 5 * 60_000 });
        this.onChange({ ...result, phase: 'directory', message: result.identities.length
          ? 'Entra results. Select the SID appropriate for the access path; synced identities can have both Entra and AD SIDs.'
          : 'No matching identity found in Entra. You can still enter a SID directly.' });
      } catch (error) {
        if (sequence !== this.sequence) return;
        this.onChange({ identities: [], phase: 'error', message: `Entra lookup failed: ${error.message}` });
      }
    }, this.delayMs);
  }
}
