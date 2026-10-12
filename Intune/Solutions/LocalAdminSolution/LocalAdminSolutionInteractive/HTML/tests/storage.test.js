import test from 'node:test';
import assert from 'node:assert/strict';
import {
  generateRecoveryProfile,
  importRecoveryProfile,
  loadPreferences,
  loadRecoveryProfile,
  loadConnection,
  removeRecoveryProfile,
  removeConnection,
  saveConnection,
  saveRecoveryProfile,
  savePreferences
} from '../storage.js';

class MemoryStorage {
  constructor() {
    this.values = new Map();
  }
  getItem(key) {
    return this.values.has(key) ? this.values.get(key) : null;
  }
  setItem(key, value) {
    this.values.set(key, String(value));
  }
  removeItem(key) {
    this.values.delete(key);
  }
  clear() {
    this.values.clear();
  }
}

globalThis.localStorage = new MemoryStorage();

test('preferences validate new settings and reject unsafe CSV prefixes', () => {
  savePreferences({
    version: 1,
    staleThresholdDays: 30,
    reviewWindowDays: 60,
    pageSize: 100,
    defaultView: 'review',
    groupByComputer: false,
    timeDisplay: 'utc',
    csvFilenamePrefix: '../secret'
  });
  const preferences = loadPreferences();
  assert.equal(preferences.staleThresholdDays, 30);
  assert.equal(preferences.reviewWindowDays, 60);
  assert.equal(preferences.defaultView, 'review');
  assert.equal(preferences.timeDisplay, 'utc');
  assert.equal(preferences.csvFilenamePrefix, 'LocalAdmin');
});

test('preferences preserve table layout order and widths for normalization on load', () => {
  const tableLayouts = {
    summary: [
      { key: 'SID', label: 'SID', width: 420 },
      { key: 'ComputerName', label: 'Computer name', width: 180 }
    ]
  };
  savePreferences({
    version: 1,
    staleThresholdDays: 90,
    reviewWindowDays: 90,
    pageSize: 50,
    defaultView: 'summary',
    groupByComputer: true,
    timeDisplay: 'local',
    csvFilenamePrefix: 'LocalAdmin',
    tableLayouts
  });
  assert.deepEqual(loadPreferences().tableLayouts, tableLayouts);
});

test('connection credentials can be remembered and removed', () => {
  localStorage.clear();
  assert.equal(saveConnection('inventory', 'sv=token', 'governance', 'sv=governance'), true);
  assert.deepEqual(loadConnection(), {
    version: 1,
    accountName: 'inventory',
    token: 'sv=token',
    governanceAccountName: 'governance',
    governanceToken: 'sv=governance'
  });
  assert.equal(removeConnection(), true);
  assert.equal(loadConnection(), null);
});

test('recovery profile generation stores only after explicit consent', async () => {
  localStorage.clear();
  const transient = await generateRecoveryProfile(false);
  assert.match(transient.profile.recoveryCode, /^[A-Za-z0-9_-]{43}$/);
  assert.match(transient.profile.ownerKey, /^recovery:[0-9a-f]{64}$/);
  assert.equal(transient.stored, false);
  assert.equal(loadRecoveryProfile(), null);

  const remembered = await importRecoveryProfile(transient.profile.recoveryCode, true);
  assert.equal(remembered.profile.ownerKey, transient.profile.ownerKey);
  assert.equal(remembered.stored, true);
  assert.equal(loadRecoveryProfile().ownerKey, transient.profile.ownerKey);
  assert.equal(removeRecoveryProfile(), true);
  assert.equal(saveRecoveryProfile(transient.profile), true);
  assert.equal(loadRecoveryProfile().recoveryCode, transient.profile.recoveryCode);
  assert.equal(removeRecoveryProfile(), true);
  assert.equal(loadRecoveryProfile(), null);
});

test('malformed recovery codes are rejected', async () => {
  await assert.rejects(() => importRecoveryProfile('not-a-recovery-code', false), /256-bit base64url/);
});
