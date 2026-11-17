'use strict';

const assert = require('node:assert/strict');
const logic = require('../Templates/viewer.logic.js');

const groups = [
  { id: 'bbbbbbbb-0000-0000-0000-000000000000', name: 'Operations Readers' },
  { id: 'aaaaaaaa-0000-0000-0000-000000000000', name: 'Operations Admins' },
  { id: 'cccccccc-0000-0000-0000-000000000000', name: 'Café Devices' }
];

const operationMatches = logic.searchGroups('operations', groups, 1);
assert.deepEqual(operationMatches.map((group) => group.name), [
  'Operations Admins'
]);
assert.equal(operationMatches.total, 2);
assert.deepEqual(logic.searchGroups('operations', groups, 10).map((group) => group.name), [
  'Operations Admins',
  'Operations Readers'
]);
assert.equal(logic.searchGroups('cafe', groups, 10)[0].name, 'Café Devices');
assert.equal(logic.searchGroups('bbbbbbbb', groups, 10)[0].id, groups[0].id);
assert.equal(logic.searchGroups('bbbb', groups, 10).length, 0);
assert.equal(logic.searchGroups('missing', groups, 10).length, 0);
assert.equal(logic.abbreviate('Short', 10, 'Middle'), 'Short');
assert.equal(logic.abbreviate('1234567890', 6, 'End'), '12345…');
assert.equal(logic.abbreviate('1234567890', 6, 'Middle'), '123…90');
assert.equal(logic.abbreviate('abcdefghij', 0, 'Middle'), 'abcdefghij');
assert.equal(logic.abbreviate('A😀BCDEFG', 5, 'End'), 'A😀BC…');

const linkedGroupId = groups[0].id;
assert.deepEqual(logic.parseGroupLink(`file:///C:/reports/groups.html#group=${linkedGroupId}`), {
  present: true,
  valid: true,
  id: linkedGroupId,
  source: 'hash'
});
assert.deepEqual(logic.parseGroupLink(`https://example.test/groups.html?view=all&group=${linkedGroupId}`), {
  present: true,
  valid: true,
  id: linkedGroupId,
  source: 'query'
});
assert.equal(logic.parseGroupLink('file:///C:/reports/groups.html#group=not-a-guid').valid, false);
assert.equal(logic.parseGroupLink('https://example.test/groups.html').present, false);
const unknownGroupLink = logic.parseGroupLink('https://example.test/groups.html#group=dddddddd-0000-0000-0000-000000000000');
assert.equal(unknownGroupLink.valid, true);
assert.equal(groups.find((group) => group.id === unknownGroupLink.id), undefined);
const updatedLink = logic.withGroupInHash(
  `https://example.test/groups.html?view=all&group=${groups[1].id}#theme=dark`,
  linkedGroupId
);
assert.equal(updatedLink, `https://example.test/groups.html?view=all#theme=dark&group=${linkedGroupId}`);
assert.throws(() => logic.withGroupInHash('file:///C:/reports/groups.html', 'not-a-guid'), TypeError);

console.log('Viewer logic checks passed.');
