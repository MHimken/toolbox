function normalizedBaseUrl(value) {
  return String(value || '').trim().replace(/\/+$/, '');
}

function correlationId() {
  return globalThis.crypto?.randomUUID?.() || `profile-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export class ProfileApiError extends Error {
  constructor(status, code, message, correlation, details) {
    super(message);
    this.name = 'ProfileApiError';
    this.status = status;
    this.code = code;
    this.correlationId = correlation;
    this.details = details;
  }
}

export class ProfileClient {
  constructor(baseUrl, fetchImplementation = globalThis.fetch) {
    this.baseUrl = normalizedBaseUrl(baseUrl);
    if (!this.baseUrl) throw new Error('A protected BFF URL is required.');
    if (typeof fetchImplementation !== 'function') throw new Error('The browser Fetch API is unavailable.');
    this.fetch = fetchImplementation.bind(globalThis);
  }

  async authenticationHeaders(authentication) {
    if (authentication?.type === 'entra') {
      const token = await authentication.getAccessToken();
      if (!token) throw new Error('Microsoft Entra did not return an access token.');
      return { Authorization: `Bearer ${token}` };
    }
    if (authentication?.type === 'recovery' && authentication.recoveryCode) {
      return { 'x-recovery-code': authentication.recoveryCode };
    }
    throw new Error('A Microsoft Entra or recovery identity is required.');
  }

  async request(method, path, authentication, { body, etag, create = false, idempotencyKey = '' } = {}) {
    const requestCorrelation = correlationId();
    const headers = {
      Accept: 'application/json',
      ...(await this.authenticationHeaders(authentication))
    };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (create) headers['If-None-Match'] = '*';
    if (etag) headers['If-Match'] = etag;
    if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
    const response = await this.fetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      cache: 'no-store',
      ...(body !== undefined ? { body: JSON.stringify(body) } : {})
    });
    const payload = response.status === 204 ? null : await response.json().catch(() => null);
    const responseCorrelation = response.headers?.get?.('x-correlation-id') || requestCorrelation;
    if (!response.ok) {
      throw new ProfileApiError(
        response.status,
        payload?.code || 'profile_request_failed',
        payload?.message || `The profile request failed with HTTP ${response.status}.`,
        payload?.correlationId || responseCorrelation,
        payload?.details
      );
    }
    return {
      profile: payload,
      payload,
      status: response.status,
      etag: response.headers?.get?.('etag') || payload?.etag || payload?.ETag || '',
      correlationId: responseCorrelation
    };
  }

  async getProfile(authentication) {
    try {
      return await this.request('GET', '/profile', authentication);
    } catch (error) {
      if (error instanceof ProfileApiError && error.status === 404 && error.code === 'profile_not_found') {
        return { profile: null, etag: '', correlationId: error.correlationId };
      }
      throw error;
    }
  }

  putProfile(settings, authentication, etag = '') {
    return this.request('PUT', '/profile', authentication, {
      body: { settings },
      etag,
      create: !etag
    });
  }
}
