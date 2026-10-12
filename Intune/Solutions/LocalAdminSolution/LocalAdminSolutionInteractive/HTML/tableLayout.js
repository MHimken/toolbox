export const minimumColumnWidth = 90;
export const maximumColumnWidth = 800;

export function defaultColumnWidth(key) {
  const normalizedKey = String(key || '').toLowerCase();
  if (normalizedKey.includes('sid') ||
      normalizedKey.includes('id') ||
      normalizedKey.includes('partitionkey') ||
      normalizedKey.includes('rowkey')) return 260;
  if (normalizedKey.includes('computername') ||
      normalizedKey.includes('username') ||
      normalizedKey.includes('groupname') ||
      normalizedKey.includes('principalname') ||
      normalizedKey.includes('displayname')) return 180;
  if (normalizedKey.includes('timestamp') ||
      normalizedKey.includes('report') ||
      normalizedKey.includes('last')) return 150;
  if (normalizedKey.includes('state') ||
      normalizedKey.includes('status') ||
      normalizedKey.includes('type')) return 120;
  return 150;
}

export function normalizeColumnWidth(width, fallback) {
  const numericWidth = Number(width);
  if (!Number.isFinite(numericWidth)) return fallback;
  return Math.min(maximumColumnWidth, Math.max(minimumColumnWidth, Math.round(numericWidth)));
}

export function createDefaultColumnLayout(columns) {
  return (columns || []).map(([key, label]) => ({ key, label, width: defaultColumnWidth(key) }));
}

export function normalizeColumnLayout(columns, savedLayout) {
  const defaults = createDefaultColumnLayout(columns);
  const defaultsByKey = new Map(defaults.map(column => [column.key, column]));
  const seen = new Set();
  const normalized = [];

  if (Array.isArray(savedLayout)) {
    for (const savedColumn of savedLayout) {
      const key = typeof savedColumn?.key === 'string' ? savedColumn.key : '';
      const defaultColumn = defaultsByKey.get(key);
      if (!defaultColumn || seen.has(key)) continue;
      seen.add(key);
      normalized.push({
        key,
        label: defaultColumn.label,
        width: normalizeColumnWidth(savedColumn.width, defaultColumn.width)
      });
    }
  }

  for (const defaultColumn of defaults) {
    if (!seen.has(defaultColumn.key)) normalized.push({ ...defaultColumn });
  }
  return normalized;
}

export function normalizeTableLayouts(viewDefinitions, savedLayouts) {
  return Object.fromEntries(
    Object.entries(viewDefinitions).map(([view, definition]) => [
      view,
      normalizeColumnLayout(definition.columns, savedLayouts?.[view])
    ])
  );
}
