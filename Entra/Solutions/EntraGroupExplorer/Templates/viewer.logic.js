(function (root) {
  'use strict';

  function normalize(value) {
    return String(value || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
  }

  function abbreviate(name, maximum, style) {
    const text = String(name || '');
    const points = Array.from(text);
    const limit = Number(maximum);
    if (!Number.isFinite(limit) || limit <= 0 || points.length <= limit) return text;
    if (limit < 2) return points.slice(0, limit).join('');
    if (style === 'End') return points.slice(0, limit - 1).join('') + '\u2026';
    const keep = limit - 1;
    const head = Math.ceil(keep * 0.6);
    return points.slice(0, head).join('') + '\u2026' + points.slice(points.length - (keep - head)).join('');
  }

  const groupIdPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

  function parseGroupLink(href) {
    const url = new URL(String(href));
    const hashParams = new URLSearchParams(url.hash.slice(1));
    const source = hashParams.has('group') ? 'hash' : url.searchParams.has('group') ? 'query' : null;
    if (!source) return { present: false, valid: true, id: null, source: null };
    const value = (source === 'hash' ? hashParams : url.searchParams).get('group').trim();
    return {
      present: true,
      valid: groupIdPattern.test(value),
      id: groupIdPattern.test(value) ? value.toLowerCase() : null,
      source
    };
  }

  function withGroupInHash(href, groupId) {
    const id = String(groupId || '');
    if (!groupIdPattern.test(id)) throw new TypeError('Group id must be a GUID.');
    const url = new URL(String(href));
    const hashParams = new URLSearchParams(url.hash.slice(1));
    hashParams.set('group', id);
    url.searchParams.delete('group');
    url.hash = hashParams.toString();
    return url.href;
  }

  const collator = new Intl.Collator();
  const indexCache = new WeakMap();

  // Normalizing and sorting once per dataset keeps per-keystroke search linear on large tenants.
  function searchIndex(groups) {
    let index = indexCache.get(groups);
    if (!index) {
      index = groups.map((group) => {
        const name = normalize(group.name);
        return { group, name, id: normalize(group.id), parts: name.split(/\s+/) };
      });
      index.sort((left, right) => collator.compare(String(left.group.name), String(right.group.name)) ||
        collator.compare(String(left.group.id), String(right.group.id)));
      indexCache.set(groups, index);
    }
    return index;
  }

  function searchGroups(query, groups, limit) {
    const value = normalize(String(query || '').trim());
    if (!value) return [];
    const looksLikeGuid = /^[0-9a-f-]{8,36}$/.test(value);
    const buckets = [[], [], [], [], []];
    let total = 0;
    for (const entry of searchIndex(groups)) {
      let rank = -1;
      if (looksLikeGuid && entry.id.startsWith(value)) rank = 0;
      else if (entry.name === value) rank = 1;
      else if (entry.name.startsWith(value)) rank = 2;
      else if (entry.parts.some((part) => part.startsWith(value))) rank = 3;
      else if (entry.name.includes(value)) rank = 4;
      if (rank >= 0) {
        buckets[rank].push(entry.group);
        total++;
      }
    }
    const results = [];
    for (const bucket of buckets) {
      for (const group of bucket) {
        if (results.length >= limit) break;
        results.push(group);
      }
    }
    Object.defineProperty(results, 'total', { value: total });
    return results;
  }

  const api = { abbreviate, normalize, parseGroupLink, searchGroups, withGroupInHash };
  root.ExplorerLogic = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
}(typeof globalThis === 'undefined' ? this : globalThis));
