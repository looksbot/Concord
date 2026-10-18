// Concord server entrypoint: HTTP (REST + static) + WebSocket gateway.
import { createServer } from 'node:http';
import { readFileSync, existsSync, statSync } from 'node:fs';
import { join, dirname, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Store } from './store.js';
import { Gateway } from './gateway.js';
import { createApi } from './api.js';
import { acceptUpgrade } from './ws.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.json': 'application/json',
  '.woff2': 'font/woff2',
};

export function createApp({ dataDir, staticDir, port = 0, host = '127.0.0.1' } = {}) {
  const store = new Store(dataDir);
  const gateway = new Gateway(store);
  const api = createApi({ store, gateway });

  function serveStatic(req, res) {
    let urlPath;
    try { urlPath = decodeURIComponent(new URL(req.url, 'http://local').pathname); } catch { urlPath = '/'; }
    if (urlPath === '/') urlPath = '/index.html';
    const root = join(staticDir ?? join(__dirname, '..', 'public'));
    const filePath = join(root, urlPath);
    if (!filePath.startsWith(root)) { // path traversal guard
      res.writeHead(403); res.end('forbidden'); return;
    }
    if (!existsSync(filePath) || !statSync(filePath).isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('not found'); return;
    }
    const type = MIME[extname(filePath)] ?? 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-store' });
    res.end(readFileSync(filePath));
  }

  const server = createServer((req, res) => {
    if (req.url?.startsWith('/api/')) {
      api.handle(req, res).catch((e) => {
        console.error('[api] unhandled:', e);
        try { res.writeHead(500, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'internal error' })); } catch { /* socket gone */ }
      });
      return;
    }
    serveStatic(req, res);
  });

  server.on('upgrade', (req, socket, head) => {
    const pathname = new URL(req.url, 'http://local').pathname;
    if (pathname !== '/gateway') {
      socket.write('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    const conn = acceptUpgrade(req, socket, head);
    if (conn) gateway.onConnection(conn);
  });

  return {
    server, store, gateway,
    start: () => new Promise((resolve) => server.listen(port, host, () => resolve(server.address()))),
    stop: () => new Promise((resolve) => {
      store.flush();
      server.closeAllConnections?.(); // drop live gateway sockets so close() settles
      server.close(() => resolve());
    }),
  };
}

export function main() {
  const args = process.argv.slice(2);
  const readArg = (name, fallback) => {
    const i = args.indexOf('--' + name);
    return i !== -1 && args[i + 1] ? args[i + 1] : fallback;
  };
  const port = parseInt(readArg('port', process.env.CONCORD_PORT ?? '3000'), 10);
  const host = readArg('host', process.env.CONCORD_HOST ?? '127.0.0.1');
  const dataDir = readArg('data', process.env.CONCORD_DATA ?? 'data');
  const app = createApp({ dataDir, port, host });
  app.start().then((addr) => {
    console.log(`concord 0.1.0 — listening on http://${addr.address}:${addr.port}`);
    console.log(`data dir: ${dataDir}  (messages are stored as ciphertext)`);
    const flush = () => { app.store.flush(); process.exit(0); };
    process.on('SIGINT', flush);
    process.on('SIGTERM', flush);
  }).catch((e) => { console.error('failed to start:', e); process.exit(1); });
}

if (process.argv[1] && process.argv[1].endsWith('index.js')) main();
