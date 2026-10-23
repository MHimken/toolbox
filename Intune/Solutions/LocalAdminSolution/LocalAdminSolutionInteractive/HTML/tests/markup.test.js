import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';

test('HTML patterns escape punctuation required by Unicode v-mode', async () => {
  const markup = await readFile(new URL('../index.html', import.meta.url), 'utf8');
  assert.match(markup, /pattern="\[A-Za-z0-9_\\-\]\+"/);
  assert.doesNotMatch(markup, /pattern="\[A-Za-z0-9_-\]\+"/);
  assert.doesNotThrow(() => new RegExp('[A-Za-z0-9_\\-]+', 'v'));
});

test('cloud profile application renders only active table views', async () => {
  const source = await readFile(new URL('../app.js', import.meta.url), 'utf8');
  const applyProfileSettings = source.match(
    /function applyProfileSettings\(settings\) \{[\s\S]*?\r?\n    \}\r?\n    function profileAuthentication/
  )?.[0];
  assert.ok(applyProfileSettings);
  assert.match(applyProfileSettings, /if \(views\[state\.view\]\) render\(\);/);
});

test('day settings use free numeric text with explicit suggestions', async () => {
  const markup = await readFile(new URL('../index.html', import.meta.url), 'utf8');
  for (const id of ['staleThresholdSetting', 'reviewWindowSetting']) {
    assert.match(markup, new RegExp(`id="${id}" type="text" inputmode="numeric"`));
    for (const value of ['30', '60', '90', '180']) {
      assert.match(markup, new RegExp(`data-number-target="${id}" data-number-value="${value}"`));
    }
  }
  assert.doesNotMatch(markup, /<datalist/);
});

test('interactive status and tables expose accessibility metadata', async () => {
  const markup = await readFile(new URL('../index.html', import.meta.url), 'utf8');
  const source = await readFile(new URL('../app.js', import.meta.url), 'utf8');
  assert.match(markup, /id="profileStatus" aria-live="polite"/);
  assert.match(markup, /<table aria-label="Current report data">/);
  assert.match(source, /setAttribute\('aria-sort'/);
  assert.match(source, /elements\.headerCount\.hidden = isStatic/);
  assert.match(source, /setAttribute\('role', 'separator'\)/);
  assert.match(source, /Alt\+Left\/Right/);
});

test('table layout can be reset and is included in profile settings', async () => {
  const markup = await readFile(new URL('../index.html', import.meta.url), 'utf8');
  const source = await readFile(new URL('../app.js', import.meta.url), 'utf8');
  assert.match(markup, /id="resetTableLayoutButton"/);
  assert.match(source, /tableLayouts: state\.tableLayouts/);
  assert.match(source, /state\.tableLayouts\[state\.view\] = defaultColumnLayoutForView\(state\.view\)/);
  assert.match(source, /scheduleTableLayoutPersistence\(\)/);
});

test('remember connection persists immediately and forgets immediately', async () => {
  const source = await readFile(new URL('../app.js', import.meta.url), 'utf8');
  assert.match(source, /elements\.rememberConnection\.addEventListener\('change'/);
  assert.match(source, /const result = rememberCurrentConnection\(\)/);
  assert.match(source, /elements\.rememberConnection\.checked = false/);
  assert.match(source, /Saved connection credentials were removed/);
});

test('table sorting supports ordered priorities and a three-click reset', async () => {
  const source = await readFile(new URL('../app.js', import.meta.url), 'utf8');
  assert.match(source, /sortRules: \[\{ key: 'ComputerName', direction: 1 \}\]/);
  assert.match(source, /state\.sortRules = \[\.\.\.state\.sortRules, \{ key, direction: 1 \}\]/);
  assert.match(source, /state\.sortRules\[selectedIndex\]\.direction === 1/);
  assert.match(source, /state\.sortRules = state\.sortRules\.filter\(\(_, index\) => index !== selectedIndex\)/);
  assert.match(source, /for \(const rule of effectiveRules\)/);
  assert.match(source, /sort priority \$\{ruleIndex \+ 1\}/);
});

test('control styling uses project tokens and restrained rounding', async () => {
  const styles = await readFile(new URL('../styles.css', import.meta.url), 'utf8');
  assert.doesNotMatch(styles, /border-radius:\s*999px/);
  assert.match(styles, /--warning-wash:/);
  assert.match(styles, /background:\s*var\(--warning-wash\)/);
});

test('every element bound by the application exists in the markup', async () => {
  const markup = await readFile(new URL('../index.html', import.meta.url), 'utf8');
  const source = await readFile(new URL('../app.js', import.meta.url), 'utf8');
  const ids = source.match(/Object\.fromEntries\(\[([^\]]+)\]\.map/)?.[1].match(/'([A-Za-z0-9]+)'/g).map(id => id.slice(1, -1));
  assert.ok(ids.includes('ruleDialog') && ids.includes('proposeRuleButton'));
  const directlyBoundIds = [...source.matchAll(/document\.getElementById\('([A-Za-z0-9]+)'\)/g)].map(match => match[1]);
  for (const id of [...ids, ...directlyBoundIds]) assert.match(markup, new RegExp(`id="${id}"`), `Missing element ${id}`);
});

test('Admin mode controls are explained and privileged actions use dialogs', async () => {
  const markup = await readFile(new URL('../index.html', import.meta.url), 'utf8');
  const source = await readFile(new URL('../app.js', import.meta.url), 'utf8');
  assert.match(markup, /<dialog class="admin-dialog" id="ruleDialog"/);
  assert.match(markup, /<dialog class="admin-dialog" id="reasonDialog"/);
  assert.match(source, /Four-eyes principle/);
  assert.match(source, /adminController\?\.exit\('signout'\)/);
  assert.match(source, /accountChanged\(account\)/);
  assert.doesNotMatch(source, /getAdminModeState/);
});

test('sign-in, sign-out and Retry sit beside Admin mode while profile reload stays in Settings', async () => {
  const markup = await readFile(new URL('../index.html', import.meta.url), 'utf8');
  const source = await readFile(new URL('../app.js', import.meta.url), 'utf8');
  const styles = await readFile(new URL('../styles.css', import.meta.url), 'utf8');
  const top = markup.split('<main>')[0];
  const cloudProfile = markup.match(/<h3>Cloud profile<\/h3>[\s\S]*?<hr>/)?.[0];
  assert.ok(cloudProfile);
  for (const id of ['signInButton', 'retryAuthButton', 'signOutButton', 'signInStatus', 'adminModeButton']) {
    assert.match(top, new RegExp(`id="${id}"`));
    assert.doesNotMatch(cloudProfile, new RegExp(`id="${id}"`));
    assert.equal([...markup.matchAll(new RegExp(`id="${id}"`, 'g'))].length, 1);
  }
  for (const id of ['cloudProfileStatus', 'syncProfileButton']) {
    assert.match(cloudProfile, new RegExp(`id="${id}"`));
  }
  assert.match(top, /id="signInStatus" aria-live="polite"/);
  const header = markup.match(/<header>[\s\S]*?<\/header>/)?.[0];
  assert.match(header, /id="signInButton"[\s\S]*id="retryAuthButton"[\s\S]*id="adminModeButton"[\s\S]*id="signInStatus"[\s\S]*id="adminModeStatus"/);
  assert.doesNotMatch(header, /id="headerCount"/);
  assert.match(markup.match(/<section class="mode-bar"[\s\S]*?<\/section>/)?.[0], /id="headerCount"/);
  assert.match(top, /class="command retry" id="retryAuthButton"[^>]* hidden>Retry<\/button>/);
  assert.doesNotMatch(markup, /authPopupNotice/);
  assert.match(styles, /\.command\.retry \{[^}]*background: var\(--accent-deep\)/);
  assert.match(source, /getElementById\('retryAuthButton'\)\.hidden = !pending/);
  assert.match(source, /elements\.signInButton\.disabled = [^;]*popupPending/);
  assert.match(source, /setSignInStatus\('Opening Microsoft Entra sign-in\.\.\.'\)/);
  assert.match(source, /setSignInStatus\(profileErrorMessage\(error\), true\)/);
});

test('sign-out is visible only for a signed-in account and is disabled during authentication', async () => {
  const source = await readFile(new URL('../app.js', import.meta.url), 'utf8');
  const helper = source.match(/    function updateProfileControls\(\) \{[\s\S]*?\r?\n    \}/)?.[0];
  assert.ok(helper);
  const elements = Object.fromEntries(
    ['signInButton', 'signOutButton', 'syncProfileButton', 'saveSettingsButton'].map(id => [id, {}])
  );
  let account = null;
  const auth = { getAccount: () => account, popupPending: false };
  const update = runInNewContext(`${helper}\nupdateProfileControls`, {
    elements, entraAuthClient: auth, hasEmbeddedData: false, profileClient: {}, profileSession: null
  });
  update();
  assert.equal(elements.signOutButton.hidden, true);
  assert.equal(elements.signOutButton.disabled, true);
  account = { username: 'admin@example.test' };
  update();
  assert.equal(elements.signOutButton.hidden, false);
  assert.equal(elements.signOutButton.disabled, false);
  auth.popupPending = true;
  update();
  assert.equal(elements.signOutButton.disabled, true);
  auth.popupPending = false;
  account = null;
  update();
  assert.equal(elements.signOutButton.hidden, true);
});

test('header status starts collapsed with a local arrow beside the visible timers', async () => {
  const markup = await readFile(new URL('../index.html', import.meta.url), 'utf8');
  const styles = await readFile(new URL('../styles.css', import.meta.url), 'utf8');
  const details = markup.match(/<details class="auth-status-box" id="authStatusBox">[\s\S]*?<\/details>/)?.[0];
  assert.ok(details);
  assert.match(details, /<summary aria-label="Authentication and Admin-mode status">[\s\S]*id="adminIdleCountdown"[\s\S]*<svg class="status-arrow"[\s\S]*<\/summary>/);
  assert.match(details, /<\/summary>[\s\S]*class="sign-in-status" id="signInStatus"[\s\S]*class="admin-status" id="adminModeStatus"/);
  assert.doesNotMatch(details, /authStatusHistory|visually-hidden/);
  assert.match(styles, /\.auth-status-box \{ width: 100%; \}/);
  assert.match(styles, /\.auth-status-box summary \{[^}]*width: fit-content; margin-left: auto;/);
  assert.match(styles, /\.status-arrow \{[^}]*color: var\(--paper\)/);
  assert.match(styles, /\.auth-status-box\[open\] \.status-arrow \{ transform: rotate\(180deg\)/);
  assert.doesNotMatch(styles, /\.command(?:\.secondary|\.retry)?:hover\s*\{/);
  assert.match(styles, /\.header-auth \.command\.secondary:hover:not\(:disabled\) \{[^}]*background: var\(--disabled\)/);
});

test('status box replaces current messages and expands only on new errors', async () => {
  const source = await readFile(new URL('../app.js', import.meta.url), 'utf8');
  const helpers = source.match(/    let pendingAdminStatusError = false;[\s\S]*?    function expandAuthStatus\(\) \{[\s\S]*?\n    \}/)?.[0];
  assert.ok(helpers);
  const nodes = { signInStatus: { textContent: '', dataset: {} }, adminModeStatus: { textContent: '', dataset: {} }, authStatusBox: { open: false } };
  const api = runInNewContext(`${helpers}\n({ setSignInStatus, setAdminModeStatus, markAdminStatusError })`, {
    document: { getElementById: id => nodes[id] }
  });
  api.setSignInStatus('Opening Microsoft Entra sign-in...');
  api.setAdminModeStatus('Admin mode is available.');
  api.setAdminModeStatus('Admin mode is available.');
  assert.equal(nodes.signInStatus.textContent, 'Opening Microsoft Entra sign-in...');
  assert.equal(nodes.adminModeStatus.textContent, 'Admin mode is available.');
  assert.equal(nodes.authStatusBox.open, false);
  api.setSignInStatus('Signed in as a@contoso.com.');
  api.setAdminModeStatus('Confirming Admin mode...');
  api.markAdminStatusError();
  api.setAdminModeStatus('Admin mode was not entered: cancelled.');
  assert.equal(nodes.signInStatus.textContent, 'Signed in as a@contoso.com.');
  assert.equal(nodes.adminModeStatus.textContent, 'Admin mode was not entered: cancelled.');
  assert.equal(nodes.adminModeStatus.dataset.error, 'true');
  assert.equal(nodes.authStatusBox.open, true);
  nodes.authStatusBox.open = false;
  api.setAdminModeStatus('Admin mode was not entered: cancelled.');
  assert.equal(nodes.authStatusBox.open, false);
  assert.equal(nodes.adminModeStatus.dataset.error, 'true');
  api.markAdminStatusError();
  api.setAdminModeStatus('Admin mode was not entered: cancelled.');
  assert.equal(nodes.authStatusBox.open, true);
  nodes.authStatusBox.open = false;
  api.setAdminModeStatus('Admin mode active.');
  assert.equal(nodes.adminModeStatus.dataset.error, 'false');
  assert.equal(nodes.authStatusBox.open, false);
  api.setSignInStatus('Authentication timed out.', true);
  assert.equal(nodes.authStatusBox.open, true);
  assert.equal(nodes.signInStatus.dataset.error, 'true');
  nodes.authStatusBox.open = false;
  api.setSignInStatus('Signed in.');
  assert.equal(nodes.signInStatus.textContent, 'Signed in.');
  assert.equal(nodes.signInStatus.dataset.error, 'false');
  assert.equal(nodes.authStatusBox.open, false);
  assert.match(source, /adminStatusMessage = `Admin mode was not entered:[\s\S]*?markAdminStatusError\(\)/);
});