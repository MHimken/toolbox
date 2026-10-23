import test from 'node:test';
import assert from 'node:assert/strict';
import { buildCsv, csvCell } from '../dataService.js';

test('csvCell quotes delimiters, quotes, newlines, and Unicode', () => {
  assert.equal(csvCell('a,b'), '"a,b"');
  assert.equal(csvCell('say "hi"'), '"say ""hi"""');
  assert.equal(csvCell('line1\r\nline2'), '"line1\r\nline2"');
  assert.equal(csvCell('Müller – 管理者'), '"Müller – 管理者"');
  assert.equal(csvCell(null), '""');
});

test('csvCell neutralizes spreadsheet formula prefixes but keeps numbers and SIDs', () => {
  for (const value of ['=HYPERLINK("x")', '+1+1', '-2+3', '@SUM(A1)', '\tcmd', '\rcmd']) {
    assert.equal(csvCell(value).startsWith(`"'`), true, value);
  }
  assert.equal(csvCell(-5), '"-5"');
  assert.equal(csvCell('S-1-5-21-1-2-3-500'), '"S-1-5-21-1-2-3-500"');
});

test('buildCsv emits BOM, header, every row, and applies the value formatter', () => {
  const csv = buildCsv(
    [['Name', 'Computer name'], ['Removed', 'Status']],
    [{ Name: 'PC1', Removed: 0, Secret: 'sv=2024' }, { Name: '=cmd', Removed: 1 }],
    (key, value) => key === 'Removed' ? (value === 1 ? 'Removed' : 'Active') : value
  );
  assert.equal(csv, '\uFEFF"Computer name","Status"\r\n"PC1","Active"\r\n"\'=cmd","Removed"');
});
