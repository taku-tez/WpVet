import packageJson from '../package.json' assert { type: 'json' };

export const VERSION = packageJson.version;
export const USER_AGENT = `WpVet/${VERSION} (Security Scanner)`;
