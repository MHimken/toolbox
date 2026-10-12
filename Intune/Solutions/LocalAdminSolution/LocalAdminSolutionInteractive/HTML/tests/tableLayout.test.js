import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createDefaultColumnLayout,
  maximumColumnWidth,
  minimumColumnWidth,
  normalizeColumnLayout
} from '../tableLayout.js';

const columns = [
  ['ComputerName', 'Computer name'],
  ['SID', 'SID'],
  ['UserName', 'User name'],
  ['Status', 'Status']
];

test('saved column order and widths survive layout normalization', () => {
  const normalized = normalizeColumnLayout(columns, [
    { key: 'SID', width: 420 },
    { key: 'Status', width: 130 },
    { key: 'ComputerName', width: 210 },
    { key: 'UserName', width: 240 }
  ]);
  assert.deepEqual(normalized.map(column => column.key), ['SID', 'Status', 'ComputerName', 'UserName']);
  assert.deepEqual(normalized.map(column => column.width), [420, 130, 210, 240]);
});

test('normalization removes invalid duplicates and appends newly introduced columns', () => {
  const normalized = normalizeColumnLayout(columns, [
    { key: 'SID', width: maximumColumnWidth + 100 },
    { key: 'SID', width: 100 },
    { key: 'RemovedColumn', width: 200 },
    { key: 'Status', width: minimumColumnWidth - 20 }
  ]);
  assert.deepEqual(normalized.map(column => column.key), ['SID', 'Status', 'ComputerName', 'UserName']);
  assert.equal(normalized[0].width, maximumColumnWidth);
  assert.equal(normalized[1].width, minimumColumnWidth);
});

test('default SID and ID columns receive readable widths', () => {
  const defaults = createDefaultColumnLayout(columns);
  assert.equal(defaults.find(column => column.key === 'SID')?.width, 260);
});
