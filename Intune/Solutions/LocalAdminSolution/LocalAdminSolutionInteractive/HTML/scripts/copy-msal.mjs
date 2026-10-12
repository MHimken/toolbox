import { copyFile, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const targetDirectory = resolve(root, 'vendor');
const assets = [
  ['msal-browser.min.js', resolve(root, 'node_modules', '@azure', 'msal-browser', 'lib', 'msal-browser.min.js')],
  ['msal-redirect-bridge.min.js', resolve(root, 'node_modules', '@azure', 'msal-browser', 'lib', 'redirect-bridge', 'msal-redirect-bridge.min.js')],
  ['LICENSE-msal-browser.txt', resolve(root, 'node_modules', '@azure', 'msal-browser', 'LICENSE')]
];

await mkdir(targetDirectory, { recursive: true });
await Promise.all(assets.map(([name, source]) => copyFile(source, resolve(targetDirectory, name))));
