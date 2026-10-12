import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

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
  for (const id of ids) assert.match(markup, new RegExp(`id="${id}"`), `Missing element ${id}`);
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