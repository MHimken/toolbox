export function isAuthenticationResponse(locationValue = globalThis.location) {
  if (!locationValue) return false;
  const response = `${locationValue.search || ''}${locationValue.hash || ''}`;
  return /(?:[?#&])(code|error|error_description|error_subcode)=/i.test(response);
}

export async function bootstrapBrowser(
  locationValue = globalThis.location,
  redirectBridge = globalThis.msalRedirectBridge
) {
  if (isAuthenticationResponse(locationValue)) {
    if (!redirectBridge?.broadcastResponseToMainFrame) {
      throw new Error('The Microsoft authentication redirect bridge could not be loaded.');
    }
    await redirectBridge.broadcastResponseToMainFrame();
    return;
  }
  await import('./app.js');
}

if (typeof document !== 'undefined') {
  void bootstrapBrowser().catch(error => {
    console.error(error);
    const status = document.getElementById('cloudProfileStatus');
    if (status) status.textContent = `Authentication startup failed: ${error.message}`;
  });
}
