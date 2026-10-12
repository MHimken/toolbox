export function hasCompleteEntraConfig(config) {
  return Boolean(config?.entraTenantId && config?.spaClientId && config?.apiScope);
}

export class EntraAuthClient {
  constructor(config, msalImplementation = globalThis.msal) {
    if (!hasCompleteEntraConfig(config)) {
      throw new Error('Entra authentication requires tenant, SPA client, and API scope configuration.');
    }
    if (!msalImplementation?.PublicClientApplication) {
      throw new Error('The self-hosted MSAL browser library could not be loaded.');
    }
    this.scope = config.apiScope;
    this.redirectUri = config.redirectUri || globalThis.location?.href?.split('#')[0];
    this.msal = msalImplementation;
    this.client = new msalImplementation.PublicClientApplication({
      auth: {
        clientId: config.spaClientId,
        authority: `https://login.microsoftonline.com/${config.entraTenantId}`,
        redirectUri: this.redirectUri,
        // CP1 lets Entra return Conditional Access claims challenges for the Admin-mode authentication context.
        clientCapabilities: ['CP1']
      },
      cache: {
        cacheLocation: 'memoryStorage',
        storeAuthStateInCookie: false
      },
      system: {
        allowNativeBroker: false
      }
    });
  }

  async initialize() {
    await this.client.initialize();
  }

  getAccount() {
    return this.client.getActiveAccount();
  }

  async signIn() {
    const result = await this.client.loginPopup({
      scopes: [this.scope],
      prompt: 'select_account'
    });
    if (!result?.account) throw new Error('Microsoft Entra sign-in did not return an account.');
    this.client.setActiveAccount(result.account);
    return result.account;
  }

  async signOut() {
    const account = this.getAccount();
    if (account) {
      await this.client.logoutPopup({ account, mainWindowRedirectUri: this.redirectUri });
    }
    this.client.setActiveAccount(null);
  }

  async getAccessToken() {
    const account = this.getAccount();
    if (!account) throw new Error('Sign in with Microsoft Entra before synchronizing a profile.');
    try {
      const result = await this.client.acquireTokenSilent({ account, scopes: [this.scope] });
      return result.accessToken;
    } catch (error) {
      if (!(error instanceof this.msal.InteractionRequiredAuthError)) throw error;
      const result = await this.client.acquireTokenPopup({ account, scopes: [this.scope] });
      return result.accessToken;
    }
  }

  async getClaimsChallengeToken(claims) {
    const account = this.getAccount();
    if (!account) throw new Error('Sign in with Microsoft Entra before entering Admin mode.');
    if (typeof claims !== 'string' || !claims.trim()) throw new Error('The backend did not return a valid claims challenge.');
    const result = await this.client.acquireTokenPopup({ account, scopes: [this.scope], claims, loginHint: account.username });
    if (!result?.accessToken) throw new Error('Microsoft Entra did not return an Admin-mode access token.');
    if (result.account?.homeAccountId && account.homeAccountId && result.account.homeAccountId !== account.homeAccountId) {
      throw new Error('Admin mode must be confirmed with the account that is already signed in.');
    }
    return result.accessToken;
  }
}
