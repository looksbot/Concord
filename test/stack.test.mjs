// Full-stack integration test: boots the real server, registers two users,
// runs the actual E2E flows over REST + the live gateway, and audits the data
// directory to prove the server never saw any plaintext.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApp } from '../server/index.js';
import * as C from '../public/concord-crypto.js';

const J = (o) => JSON.stringify(o);

let app, base;
const api = async (token, method, path, body) => {
  const res = await fetch(base + path, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`${method} ${path}: ${data.error ?? res.status}`);
  return data;
};

class Gw {
  constructor(token) { this.token = token; this.events = []; this.waiters = []; this.ready = null; }
  open() {
    this.ws = new WebSocket(base.replace('http', 'ws') + '/gateway');
    this.ws.onmessage = async (ev) => {
      const raw = typeof ev.data === 'string' ? ev.data : await ev.data.text();
      const f = JSON.parse(raw);
      if (f.op === 10) { // HELLO → identify + heartbeat
        this.ws.send(JSON.stringify({ op: 2, d: { token: this.token } }));
        this.hb = setInterval(() => this.ws.send(JSON.stringify({ op: 1, d: null })), f.d.heartbeat_interval);
        return;
      }
      if (f.op === 0) {
        this.events.push(f);
        for (const w of [...this.waiters]) {
          if ((w.t === f.t || w.t === null) && (!w.filter || w.filter(f.d))) {
            this.waiters.splice(this.waiters.indexOf(w), 1);
            w.resolve(f);
          }
        }
        if (f.t === 'READY') this._readyResolve?.(f.d);
      }
    };
    return Promise.race([
      new Promise((resolve) => { this._readyResolve = resolve; }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('gateway READY timeout')), 8000)),
    ]);
  }
  waitEvent(t, filter = null, timeout = 5000) {
    const match = (e) => e.t === t && !e._consumed && (!filter || filter(e.d));
    const found = this.events.find(match);
    if (found) { found._consumed = true; return Promise.resolve(found.d); }
    return new Promise((resolve, reject) => {
      const w = { t, filter, resolve: (f) => { f._consumed = true; resolve(f.d); } };
      this.waiters.push(w);
      setTimeout(() => reject(new Error(`timeout waiting for ${t}`)), timeout);
    });
  }
  close() { clearInterval(this.hb); this.ws?.close(); }
}

test('concord full stack: E2E DMs, E2E guild channels, server stays blind', async () => {
  const dataDir = mkdtempSync(join(tmpdir(), 'concord-test-'));
  app = createApp({ dataDir, port: 0, host: '127.0.0.1' });
  const addr = await app.start();
  base = `http://127.0.0.1:${addr.port}`;

  // ---- register two users, each with real client-side keys -----------------
  const step = (s) => console.error('  [step]', s);
  const mkUser = async (name) => {
    const { token, user } = await api(null, 'POST', '/api/auth/register', { username: name, password: 'correct-horse-battery' });
    const keys = await C.generateIdentityKeys();
    const bundle = await C.buildBundle(keys, 10);
    await api(token, 'PUT', '/api/keys/@me', bundle.upload);
    return { token, user, keys, bundle };
  };
  const alice = await mkUser('alice');
  const bob = await mkUser('bob');

  const ga = new Gw(alice.token); const gb = new Gw(bob.token);
  const [readyA, readyB] = await Promise.all([ga.open(), gb.open()]);
  assert.equal(readyA.user.username, 'alice');
  assert.equal(readyB.user.username, 'bob');

  // ---- E2E DM flow -----------------------------------------------------------
  step('DM flow');
  const { channel: dm } = await api(alice.token, 'POST', '/api/users/@me/channels', { recipient_id: bob.user.id });
  await gb.waitEvent('DM_CHANNEL_CREATE');

  const bundleBob = await api(alice.token, 'GET', `/api/keys/${bob.user.id}`);
  assert.ok(bundleBob.opk, 'OPK served to initiator');
  const { state: A, header } = await C.x3dhInitiator(alice.keys, bundleBob);

  const sendDm = async (state, text) => {
    const env = await C.ratchetEncrypt(state, dm.id, J({ kind: 'text', text }), alice.keys.signing);
    if (!state.established) env.hdr = header;
    return api(alice.token, 'POST', `/api/channels/${dm.id}/messages`, { envelope: env });
  };
  step('send m1+m2');
  await sendDm(A, 'the eagle lands at dawn');
  await sendDm(A, 'bring the blue folder');
  step('wait events');
  const ev1 = await gb.waitEvent('MESSAGE_CREATE');
  const ev2 = await gb.waitEvent('MESSAGE_CREATE');
  step('events arrived; responder bootstrap');

  // bob bootstraps his side from the first envelope's header
  const { state: B } = await C.x3dhResponder(bob.keys, bob.bundle.local, ev1.envelope.hdr);
  step('decrypt m1');
  assert.equal(await C.ratchetDecrypt(B, dm.id, ev1.envelope), J({ kind: 'text', text: 'the eagle lands at dawn' }));
  step('decrypt m2');
  assert.equal(await C.ratchetDecrypt(B, dm.id, ev2.envelope), J({ kind: 'text', text: 'bring the blue folder' }));
  // signatures check out
  assert.equal(await C.verify(alice.keys.signing.pub, ev1.envelope.sig, C.dmCanonical(dm.id, ev1.envelope)), true);

  // bob replies; alice's ratchet turns
  step('bob reply');
  const bEnv = await C.ratchetEncrypt(B, dm.id, J({ kind: 'text', text: 'understood' }), bob.keys.signing);
  await api(bob.token, 'POST', `/api/channels/${dm.id}/messages`, { envelope: bEnv });
  const evB = await ga.waitEvent('MESSAGE_CREATE', (d) => d.author_id !== alice.user.id);
  assert.equal(await C.ratchetDecrypt(A, dm.id, evB.envelope), J({ kind: 'text', text: 'understood' }));

  // ---- E2E guild flow ---------------------------------------------------------
  step('guild flow');
  const { guild } = await api(alice.token, 'POST', '/api/guilds', { name: 'Moon Base' });
  const general = guild.channels.find((c) => c.name === 'general');
  assert.ok(general, 'default #general channel exists');

  const { invite } = await api(alice.token, 'POST', '/api/invites', { guild_id: guild.id });
  const joined = await api(bob.token, 'POST', `/api/invites/${invite.code}/join`);
  assert.equal(joined.guild.id, guild.id);
  const memberAdd = await ga.waitEvent('GUILD_MEMBER_ADD', (d) => d.user?.id === bob.user.id);
  assert.equal(memberAdd.user.id, bob.user.id);

  // owner bootstraps the channel key generation (wraps for herself)
  let keysInfo = await api(alice.token, 'GET', `/api/channels/${general.id}/keys`);
  assert.equal(keysInfo.wrap, null);
  const ck = C.generateChannelKey();
  const selfWrap = await C.wrapKeyFor(alice.keys.identity, alice.keys.identity.pub, ck.key);
  await api(alice.token, 'PUT', `/api/channels/${general.id}/keys`, {
    key_id: ck.key_id, wraps: [{ user_id: alice.user.id, from: alice.keys.identity.pub, ...selfWrap }],
  });

  // alice wraps the same generation for bob (what the client does on GUILD_MEMBER_ADD)
  const bobWrap = await C.wrapKeyFor(alice.keys.identity, bob.keys.identity.pub, ck.key);
  await api(alice.token, 'PUT', `/api/channels/${general.id}/keys`, {
    key_id: ck.key_id, wraps: [{ user_id: bob.user.id, from: alice.keys.identity.pub, ...bobWrap }],
  });
  const keyUpd = await gb.waitEvent('CHANNEL_KEY_UPDATE');
  assert.equal(keyUpd.channel_id, general.id);

  // bob recovers the key server-side-wrapped form and decrypts traffic
  const bobKeysInfo = await api(bob.token, 'GET', `/api/channels/${general.id}/keys`);
  const recovered = await C.unwrapKeyFor(bob.keys.identity, bobKeysInfo.wrap.from, bobKeysInfo.wrap);
  assert.equal(recovered, ck.key);

  const chEnv = await C.channelEncrypt(ck.key, ck.key_id, general.id, { kind: 'text', text: 'guild-wide secret' }, alice.keys.signing);
  await api(alice.token, 'POST', `/api/channels/${general.id}/messages`, { envelope: chEnv });
  const evCh = await gb.waitEvent('MESSAGE_CREATE', (d) => d.channel_id === general.id);
  assert.deepEqual(await C.channelDecrypt(recovered, evCh.envelope), { kind: 'text', text: 'guild-wide secret' });

  // ---- edit + delete fan out ---------------------------------------------------
  step('edit/delete flow');
  const { messages } = await api(alice.token, 'GET', `/api/channels/${general.id}/messages`);
  const mid = messages.at(-1).id;
  const editedEnv = await C.channelEncrypt(ck.key, ck.key_id, general.id, { kind: 'text', text: 'guild-wide secret (edited)' }, alice.keys.signing);
  await api(alice.token, 'PATCH', `/api/channels/${general.id}/messages/${mid}`, { envelope: editedEnv });
  const evUpd = await gb.waitEvent('MESSAGE_UPDATE', (d) => d.channel_id === general.id);
  assert.deepEqual(await C.channelDecrypt(recovered, evUpd.envelope), { kind: 'text', text: 'guild-wide secret (edited)' });

  await api(alice.token, 'DELETE', `/api/channels/${general.id}/messages/${mid}`);
  await gb.waitEvent('MESSAGE_DELETE', (d) => d.channel_id === general.id);

  // ---- kick triggers key rotation bookkeeping -----------------------------------
  step('kick flow');
  await api(alice.token, 'DELETE', `/api/guilds/${guild.id}/members/${bob.user.id}`);
  const removed = await ga.waitEvent('GUILD_MEMBER_REMOVE');
  assert.equal(removed.user_id, bob.user.id);
  assert.equal(removed.rotate_keys, true);
  const afterKick = await api(alice.token, 'GET', `/api/channels/${general.id}/keys`);
  assert.equal(afterKick.wrap.key_id, ck.key_id, 'alice keeps her wrap');
  const bobAfterKick = await api(bob.token, 'GET', `/api/guilds/${guild.id}`).catch(() => 'blocked');
  assert.equal(bobAfterKick, 'blocked', 'kicked member loses guild access');

  // ---- the server never saw anything ---------------------------------------------
  const secrets = ['the eagle lands at dawn', 'bring the blue folder', 'understood', 'guild-wide secret'];
  const files = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      if (statSync(p).isDirectory()) walk(p); else files.push(p);
    }
  };
  app.store.flush();
  walk(dataDir);
  assert.ok(files.length >= 4, `expected persisted state, got ${files.length} files`);
  for (const f of files) {
    const raw = readFileSync(f, 'utf8');
    for (const s of secrets) assert.ok(!raw.includes(s), `PLAINTEXT LEAK in ${f}: ${s}`);
    assert.ok(!raw.includes(ck.key), `CHANNEL KEY LEAK in ${f}`);
  }

  ga.close(); gb.close();
  await app.stop();
}, 30000);
