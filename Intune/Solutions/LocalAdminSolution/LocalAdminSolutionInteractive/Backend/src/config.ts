export interface AppConfig {
  tenantId: string;
  clientId: string;
  spaClientId: string;
  governanceTableEndpoint: string;
  allowedOrigins: ReadonlySet<string>;
  adminAuthContextId: string;
  adminSessionMaxMinutes: number;
}

const guidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function required(name: string, values: NodeJS.ProcessEnv): string {
  const value = values[name]?.trim();
  if (!value) throw new Error(`Missing required configuration ${name}.`);
  return value;
}

export function loadConfig(values: NodeJS.ProcessEnv = process.env): AppConfig {
  const tenantId = required('TENANT_ID', values).toLowerCase();
  const clientId = required('API_CLIENT_ID', values).toLowerCase();
  const spaClientId = required('SPA_CLIENT_ID', values).toLowerCase();
  const governanceTableEndpoint = required('GOVERNANCE_TABLE_ENDPOINT', values).replace(/\/+$/, '');
  if (!guidPattern.test(tenantId)) throw new Error('TENANT_ID must be a GUID.');
  if (!guidPattern.test(clientId)) throw new Error('API_CLIENT_ID must be a GUID.');
  if (!guidPattern.test(spaClientId)) throw new Error('SPA_CLIENT_ID must be a GUID.');
  if (!/^https:\/\/[a-z0-9]{3,24}\.table\.core\.windows\.net$/i.test(governanceTableEndpoint)) {
    throw new Error('GOVERNANCE_TABLE_ENDPOINT must be an HTTPS Azure Table endpoint.');
  }
  const allowedOrigins = new Set(
    (values.ALLOWED_ORIGINS || '')
      .split(',')
      .map(value => value.trim())
      .filter(Boolean)
  );
  if ([...allowedOrigins].some(origin => origin !== '*' && !/^https:\/\/[^/]+$/i.test(origin))) {
    throw new Error('ALLOWED_ORIGINS must contain exact HTTPS origins or an explicit wildcard.');
  }
  const adminAuthContextId = (values.ADMIN_AUTH_CONTEXT_ID?.trim() || 'c1').toLowerCase();
  if (!/^c(?:[1-9]|[1-9][0-9])$/.test(adminAuthContextId)) {
    throw new Error('ADMIN_AUTH_CONTEXT_ID must be a Conditional Access authentication context ID from c1 to c99.');
  }
  const adminSessionMaxMinutes = Number(values.ADMIN_SESSION_MAX_MINUTES?.trim() || '30');
  if (!Number.isInteger(adminSessionMaxMinutes) || adminSessionMaxMinutes < 5 || adminSessionMaxMinutes > 240) {
    throw new Error('ADMIN_SESSION_MAX_MINUTES must be a whole number from 5 to 240.');
  }
  return { tenantId, clientId, spaClientId, governanceTableEndpoint, allowedOrigins, adminAuthContextId, adminSessionMaxMinutes };
}
