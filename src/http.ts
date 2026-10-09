import { startHttpServer } from './http-server.js';

// HTTP entrypoint. Stdio stays in index.ts and does not consult
// CONDUIT_S2S_SECRET. Importing this module from tests is unsafe: when
// MCP_TRANSPORT is not "http" it loads the stdio server. Tests should
// import ./http-server.js instead.
const transport = process.env.MCP_TRANSPORT;
if (transport === 'http') {
  startHttpServer();
} else {
  import('./index.js');
}
