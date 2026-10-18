// Concord REST API. The server treats every `envelope` as opaque ciphertext;
// it stores, routes, and broadcasts but can never read message content.
import { scryptSync, randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import { createWriteStream, existsSync, createReadStream, statSync } from 'node:fs';
import { unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { snowflake } from './snowflake.js';

const MAX_JSON_BODY = 256 * 1024;      // envelopes are small ciphertexts
const MAX_ATTACHMENT = 8 * 1024 * 1024;
const USERNAME_RE = /^[a-zA-Z0-9_.-]{3,32}$/;

function publicUser(u) {
  return { id: u.id, username: u.username, display: u.display, avatar_seed: u.avatar_seed, created: u.created };
}

export function createApi({ store, gateway }) {

  function auth(req) {
    const h = req.headers['authorization'] || '';
    const m = /^Bearer\s+(.+)$/i.exec(h);
    if (!m) return null;
    const hash = createHash('sha256').update(m[1]).digest('hex');
    const session = store.sessions.get(hash);
    if (!session) return null;
    return store.users.get(session.user_id) ?? null;
  }

  function json(res, code, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body), 'Cache-Control': 'no-store' });
    res.end(body);
  }
  const fail = (res, code, error) => json(res, code, { error });

  function readJson(req) {
    return new Promise((resolve, reject) => {
      const chunks = []; let size = 0;
      req.on('data', (c) => {
        size += c.length;
        if (size > MAX_JSON_BODY) { reject(Object.assign(new Error('payload too large'), { code: 413 })); req.destroy(); return; }
        chunks.push(c);
      });
      req.on('end', () => {
        try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); }
        catch { reject(Object.assign(new Error('invalid json'), { code: 400 })); }
      });
      req.on('error', reject);
    });
  }

  function channelAccessError(user, channel) {
    if (!channel) return 404;
    if (channel.type === 'dm') return channel.recipients.includes(user.id) ? null : 403;
    const guild = store.guilds.get(channel.guild_id);
    if (!guild) return 404;
    return guild.members.includes(user.id) ? null : 403;
  }

  async function handle(req, res) {
    const url = new URL(req.url, 'http://local');
    const path = url.pathname;
    const method = req.method;
    let m; // shared regex-route match variable

    if (method === 'GET' && path === '/api/health') return json(res, 200, { ok: true, name: 'concord', version: '0.1.0' });

    // ---- auth -------------------------------------------------------------
    if (method === 'POST' && path === '/api/auth/register') {
      const body = await readJson(req).catch((e) => fail(res, e.code ?? 400, e.message) ?? null);
      if (!body) return;
      const { username, password, display } = body;
      if (typeof username !== 'string' || !USERNAME_RE.test(username)) return fail(res, 400, 'username must match [a-zA-Z0-9_.-]{3,32}');
      if (typeof password !== 'string' || password.length < 8) return fail(res, 400, 'password must be at least 8 characters');
      if (store.byUsername(username)) return fail(res, 409, 'username taken');
      const salt = randomBytes(16).toString('hex');
      const hashHex = scryptSync(password, salt, 64).toString('hex');
      const user = store.createUser({ username, display, passwordSalt: salt, passwordHash: hashHex });
      const { token, hash: thash } = gateway.newToken();
      store.sessions.set(thash, { user_id: user.id, created: Date.now() });
      store.markDirty('sessions');
      return json(res, 201, { token, user: publicUser(user) });
    }

    if (method === 'POST' && path === '/api/auth/login') {
      const body = await readJson(req).catch((e) => fail(res, e.code ?? 400, e.message) ?? null);
      if (!body) return;
      const user = store.byUsername(String(body.username ?? ''));
      const salt = user?.password.salt, expected = user?.password.hash;
      const given = (salt && typeof body.password === 'string') ? scryptSync(body.password, salt, 64).toString('hex') : null;
      const ok = given && expected && given.length === expected.length && timingSafeEqual(Buffer.from(given), Buffer.from(expected));
      if (!ok) return fail(res, 401, 'invalid credentials');
      const { token, hash: thash } = gateway.newToken();
      store.sessions.set(thash, { user_id: user.id, created: Date.now() });
      store.markDirty('sessions');
      return json(res, 200, { token, user: publicUser(user) });
    }

    // ---- everything below requires auth ------------------------------------
    const me = auth(req);
    if (!me) return fail(res, 401, 'unauthorized');

    if (method === 'GET' && path === '/api/users/@me') {
      const guild_ids = [...store.guilds.values()].filter((g) => g.members.includes(me.id)).map((g) => g.id);
      return json(res, 200, { user: publicUser(me), guild_ids, has_keys: !!me.keys, opk_count: me.keys?.opks?.length ?? 0 });
    }

    if (method === 'GET' && path === '/api/users') {
      const q = (url.searchParams.get('query') ?? '').toLowerCase();
      if (q.length < 2) return json(res, 200, { users: [] });
      const out = [];
      for (const u of store.users.values()) {
        if (u.id === me.id) continue;
        if (u.username.toLowerCase().includes(q) || u.display.toLowerCase().includes(q)) out.push(publicUser(u));
        if (out.length >= 10) break;
      }
      return json(res, 200, { users: out });
    }

    // public key halves for signature verification / wrapping (does NOT consume an OPK)
    if (method === 'GET' && (m = /^\/api\/users\/([0-9]+)\/pubs$/.exec(path))) {
      const u = store.users.get(m[1]);
      if (!u || !u.keys) return fail(res, 404, 'no keys');
      return json(res, 200, { user_id: u.id, identity_pub: u.keys.identity_pub, signing_pub: u.keys.signing_pub });
    }

    // ---- key bundles --------------------------------------------------------
    if (method === 'PUT' && path === '/api/keys/@me') {
      const b = await readJson(req).catch((e) => fail(res, e.code ?? 400, e.message) ?? null);
      if (!b) return;
      const str = (v) => typeof v === 'string' && v.length > 0 && v.length < 512 ? v : null;
      const bundle = {
        identity_pub: str(b.identity_pub),
        signing_pub: str(b.signing_pub),
        spk: b.spk && str(b.spk.pub) && str(b.spk.sig) ? { pub: b.spk.pub, sig: b.spk.sig } : null,
        opks: Array.isArray(b.opks)
          ? b.opks.filter((k) => k && str(k.pub) && str(k.sig)).map((k) => ({ id: String(k.id ?? snowflake()), pub: k.pub, sig: k.sig })).slice(0, 100)
          : [],
      };
      if (!bundle.identity_pub || !bundle.signing_pub || !bundle.spk) return fail(res, 400, 'key bundle requires identity_pub, signing_pub, spk');
      me.keys = bundle;
      store.markDirty('users');
      return json(res, 200, { ok: true, opk_count: bundle.opks.length });
    }

    if (method === 'GET' && path === '/api/keys/@me/status') {
      return json(res, 200, { opk_count: me.keys?.opks?.length ?? 0 });
    }

    if (method === 'GET' && (m = /^\/api\/keys\/([0-9]+)$/.exec(path))) {
      const target = store.users.get(m[1]);
      if (!target || !target.keys) return fail(res, 404, 'no key bundle');
      const opk = target.keys.opks.shift() ?? null; // consume one OPK
      if (opk) store.markDirty('users');
      return json(res, 200, {
        user_id: target.id,
        identity_pub: target.keys.identity_pub,
        signing_pub: target.keys.signing_pub,
        spk: target.keys.spk,
        opk,
        opks_remaining: target.keys.opks.length,
      });
    }

    // ---- guilds -------------------------------------------------------------
    if (method === 'POST' && path === '/api/guilds') {
      const b = await readJson(req).catch((e) => fail(res, e.code ?? 400, e.message) ?? null);
      if (!b) return;
      const name = String(b.name ?? '').trim().slice(0, 64);
      if (!name) return fail(res, 400, 'guild name required');
      const { guild, channel } = store.createGuild({ name, ownerId: me.id });
      gateway.sendTo(me.id, 'GUILD_MEMBER_ADD', { guild_id: guild.id, user: publicUser(me) });
      return json(res, 201, { guild: { ...guild, channels: store.guildChannels(guild.id) }, default_channel: channel });
    }

    if (method === 'GET' && (m = /^\/api\/guilds\/([0-9]+)$/.exec(path))) {
      const guild = store.guilds.get(m[1]);
      if (!guild) return fail(res, 404, 'guild not found');
      if (!guild.members.includes(me.id)) return fail(res, 403, 'not a member');
      return json(res, 200, { guild: { ...guild, channels: store.guildChannels(guild.id) } });
    }

    if (method === 'POST' && (m = /^\/api\/guilds\/([0-9]+)\/channels$/.exec(path))) {
      const guild = store.guilds.get(m[1]);
      if (!guild) return fail(res, 404, 'guild not found');
      if (!guild.members.includes(me.id)) return fail(res, 403, 'not a member');
      const b = await readJson(req).catch((e) => fail(res, e.code ?? 400, e.message) ?? null);
      if (!b) return;
      const name = String(b.name ?? '').trim().toLowerCase().replace(/[^a-z0-9- ]/g, '').slice(1, 32);
      if (!name) return fail(res, 400, 'channel name required');
      const channel = store.createChannel({ guildId: guild.id, name });
      gateway.toGuild(guild.id, 'CHANNEL_CREATE', { channel });
      return json(res, 201, { channel });
    }

    if (method === 'DELETE' && (m = /^\/api\/guilds\/([0-9]+)\/channels\/([0-9]+)$/.exec(path))) {
      const guild = store.guilds.get(m[1]);
      const channel = store.channels.get(m[2]);
      if (!guild || !channel || channel.guild_id !== guild.id) return fail(res, 404, 'not found');
      if (guild.owner_id !== me.id) return fail(res, 403, 'owner only');
      store.channels.delete(channel.id);
      store.messages.delete(channel.id);
      store.markDirty('channels');
      gateway.toGuild(guild.id, 'CHANNEL_DELETE', { id: channel.id, guild_id: guild.id });
      return json(res, 200, { ok: true });
    }

    if (method === 'GET' && (m = /^\/api\/guilds\/([0-9]+)\/members$/.exec(path))) {
      const guild = store.guilds.get(m[1]);
      if (!guild) return fail(res, 404, 'guild not found');
      if (!guild.members.includes(me.id)) return fail(res, 403, 'not a member');
      return json(res, 200, { members: guild.members.map((id) => publicUser(store.users.get(id))).filter(Boolean) });
    }

    if (method === 'DELETE' && (m = /^\/api\/guilds\/([0-9]+)\/members\/([0-9]+)$/.exec(path))) {
      const guild = store.guilds.get(m[1]);
      if (!guild) return fail(res, 404, 'guild not found');
      if (guild.owner_id !== me.id) return fail(res, 403, 'owner only');
      if (m[2] === me.id) return fail(res, 400, 'cannot kick yourself');
      const idx = guild.members.indexOf(m[2]);
      if (idx === -1) return fail(res, 404, 'not a member');
      guild.members.splice(idx, 1);
      store.markDirty('guilds');
      // drop the kicked member's channel-key wraps; remaining members rotate
      for (const c of store.guildChannels(guild.id)) {
        if (c.wraps[m[2]]) { delete c.wraps[m[2]]; store.markDirty('channels'); }
      }
      gateway.sendTo(m[2], 'GUILD_MEMBER_REMOVE', { guild_id: guild.id, user_id: m[2] });
      gateway.toGuild(guild.id, 'GUILD_MEMBER_REMOVE', { guild_id: guild.id, user_id: m[2], rotate_keys: true }, m[2]);
      return json(res, 200, { ok: true });
    }

    // ---- invites --------------------------------------------------------------
    if (method === 'POST' && path === '/api/invites') {
      const b = await readJson(req).catch((e) => fail(res, e.code ?? 400, e.message) ?? null);
      if (!b) return;
      const guild = store.guilds.get(String(b.guild_id ?? ''));
      if (!guild) return fail(res, 404, 'guild not found');
      if (guild.owner_id !== me.id) return fail(res, 403, 'owner only');
      return json(res, 201, { invite: store.createInvite(guild.id) });
    }

    if (method === 'GET' && (m = /^\/api\/invites\/([a-z0-9]+)$/.exec(path))) {
      const invite = store.invites.get(m[1]);
      if (!invite) return fail(res, 404, 'invite not found');
      const guild = store.guilds.get(invite.guild_id);
      return json(res, 200, { invite: { code: invite.code, guild: { id: guild.id, name: guild.name } } });
    }

    if (method === 'POST' && (m = /^\/api\/invites\/([a-z0-9]+)\/join$/.exec(path))) {
      const invite = store.invites.get(m[1]);
      if (!invite) return fail(res, 404, 'invite not found');
      const guild = store.guilds.get(invite.guild_id);
      if (!guild) return fail(res, 404, 'guild gone');
      if (!guild.members.includes(me.id)) {
        guild.members.push(me.id);
        store.markDirty('guilds');
        gateway.toGuild(guild.id, 'GUILD_MEMBER_ADD', { guild_id: guild.id, user: publicUser(me) });
      }
      return json(res, 200, { guild: { ...guild, channels: store.guildChannels(guild.id) } });
    }

    // ---- DMs --------------------------------------------------------------------
    if (method === 'POST' && path === '/api/users/@me/channels') {
      const b = await readJson(req).catch((e) => fail(res, e.code ?? 400, e.message) ?? null);
      if (!b) return;
      const other = store.users.get(String(b.recipient_id ?? ''));
      if (!other) return fail(res, 404, 'user not found');
      if (other.id === me.id) return fail(res, 400, 'cannot DM yourself');
      const { channel } = store.openDm(me.id, other.id);
      const shape = { ...channel, recipients: channel.recipients.map((r) => publicUser(store.users.get(r))) };
      gateway.toChannel(channel, 'DM_CHANNEL_CREATE', { channel: shape });
      return json(res, 200, { channel: shape });
    }

    // ---- messages ------------------------------------------------------------------
    if (method === 'GET' && (m = /^\/api\/channels\/([0-9]+)\/messages$/.exec(path))) {
      const channel = store.channels.get(m[1]);
      const err = channelAccessError(me, channel);
      if (err) return fail(res, err, err === 403 ? 'no access' : 'channel not found');
      const before = url.searchParams.get('before');
      const limit = Math.min(parseInt(url.searchParams.get('limit') ?? '50', 10) || 50, 100);
      return json(res, 200, { messages: store.messagesBefore(channel.id, before, limit) });
    }

    if (method === 'POST' && (m = /^\/api\/channels\/([0-9]+)\/messages$/.exec(path))) {
      const channel = store.channels.get(m[1]);
      const err = channelAccessError(me, channel);
      if (err) return fail(res, err, err === 403 ? 'no access' : 'channel not found');
      const b = await readJson(req).catch((e) => fail(res, e.code ?? 400, e.message) ?? null);
      if (!b) return;
      if (!b.envelope || typeof b.envelope !== 'object') return fail(res, 400, 'envelope required');
      const msg = store.addMessage(channel.id, me.id, b.envelope);
      gateway.toChannel(channel, 'MESSAGE_CREATE', msg);
      return json(res, 201, { message: msg });
    }

    if (method === 'PATCH' && (m = /^\/api\/channels\/([0-9]+)\/messages\/([0-9]+)$/.exec(path))) {
      const channel = store.channels.get(m[1]);
      const err = channelAccessError(me, channel);
      if (err) return fail(res, err, err === 403 ? 'no access' : 'channel not found');
      const arr = store.messages.get(channel.id) ?? [];
      const msg = arr.find((x) => x.id === m[2]);
      if (!msg) return fail(res, 404, 'message not found');
      if (msg.author_id !== me.id) return fail(res, 403, 'not your message');
      const b = await readJson(req).catch((e) => fail(res, e.code ?? 400, e.message) ?? null);
      if (!b) return;
      if (!b.envelope || typeof b.envelope !== 'object') return fail(res, 400, 'envelope required');
      msg.envelope = b.envelope;
      msg.edited = Date.now();
      store.markDirty('msg:' + channel.id);
      gateway.toChannel(channel, 'MESSAGE_UPDATE', msg);
      return json(res, 200, { message: msg });
    }

    if (method === 'DELETE' && (m = /^\/api\/channels\/([0-9]+)\/messages\/([0-9]+)$/.exec(path))) {
      const channel = store.channels.get(m[1]);
      const err = channelAccessError(me, channel);
      if (err) return fail(res, err, err === 403 ? 'no access' : 'channel not found');
      const arr = store.messages.get(channel.id) ?? [];
      const i = arr.findIndex((x) => x.id === m[2]);
      if (i === -1) return fail(res, 404, 'message not found');
      const msg = arr[i];
      const guild = channel.guild_id ? store.guilds.get(channel.guild_id) : null;
      if (msg.author_id !== me.id && guild?.owner_id !== me.id) return fail(res, 403, 'not allowed');
      arr.splice(i, 1);
      store.markDirty('msg:' + channel.id);
      gateway.toChannel(channel, 'MESSAGE_DELETE', { id: msg.id, channel_id: channel.id });
      return json(res, 200, { ok: true });
    }

    // ---- wrapped channel keys ----------------------------------------------------------
    if (method === 'GET' && (m = /^\/api\/channels\/([0-9]+)\/keys$/.exec(path))) {
      const channel = store.channels.get(m[1]);
      const err = channelAccessError(me, channel);
      if (err) return fail(res, err, err === 403 ? 'no access' : 'channel not found');
      if (channel.type === 'dm') return fail(res, 400, 'dm channels use ratchets, not channel keys');
      return json(res, 200, {
        key_id: channel.key_id,
        wrap: channel.wraps[me.id] ?? null, // {key_id, by, from, iv, ct}
        wrapped_members: Object.keys(channel.wraps),
      });
    }

    if (method === 'PUT' && (m = /^\/api\/channels\/([0-9]+)\/keys$/.exec(path))) {
      const channel = store.channels.get(m[1]);
      const err = channelAccessError(me, channel);
      if (err) return fail(res, err, err === 403 ? 'no access' : 'channel not found');
      if (channel.type === 'dm') return fail(res, 400, 'dm channels use ratchets, not channel keys');
      const b = await readJson(req).catch((e) => fail(res, e.code ?? 400, e.message) ?? null);
      if (!b) return;
      const keyId = String(b.key_id ?? '');
      const wraps = Array.isArray(b.wraps) ? b.wraps : [];
      if (!keyId || !wraps.length) return fail(res, 400, 'key_id and wraps required');
      // wrap targets must be guild members; wrapper must hold the key (have a wrap) or be creating first generation
      const iHold = !!channel.wraps[me.id] || channel.key_id === null;
      if (!iHold) return fail(res, 403, 'only key holders can wrap for others');
      const guild = store.guilds.get(channel.guild_id);
      const valid = {};
      for (const w of wraps) {
        if (!w || typeof w.user_id !== 'string' || !guild.members.includes(w.user_id)) continue;
        if (typeof w.iv !== 'string' || typeof w.ct !== 'string' || w.iv.length > 128 || w.ct.length > 1024) continue;
        if (typeof w.from !== 'string' || w.from.length > 512) continue; // wrapper's identity pub (public material)
        valid[w.user_id] = { key_id: keyId, by: me.id, from: w.from, iv: w.iv, ct: w.ct };
      }
      if (!Object.keys(valid).length) return fail(res, 400, 'no valid wraps');
      if (b.rotate) {
        channel.wraps = {};
        channel.key_id = keyId;
      } else if (!channel.key_id) {
        channel.key_id = keyId;
      }
      Object.assign(channel.wraps, valid);
      store.markDirty('channels');
      for (const uid of Object.keys(valid)) gateway.sendTo(uid, 'CHANNEL_KEY_UPDATE', { channel_id: channel.id, key_id: keyId });
      return json(res, 200, { ok: true, key_id: channel.key_id, wrapped: Object.keys(channel.wraps) });
    }

    // ---- attachments (opaque encrypted blobs) --------------------------------------------
    if (method === 'POST' && path === '/api/attachments') {
      const len = parseInt(req.headers['content-length'] ?? '0', 10);
      if (!(len > 0) || len > MAX_ATTACHMENT) return fail(res, 400, `attachment must be 1 byte .. ${MAX_ATTACHMENT} bytes`);
      const id = snowflake();
      const file = join(store.attachmentsDir, id + '.bin');
      await new Promise((resolve, reject) => {
        const ws = createWriteStream(file);
        let size = 0;
        req.on('data', (c) => { size += c.length; if (size > MAX_ATTACHMENT) { req.destroy(); ws.destroy(); unlink(file).catch(() => {}); reject(Object.assign(new Error('too large'), { code: 413 })); } });
        req.on('end', () => ws.end(resolve));
        req.on('error', reject);
        ws.on('error', reject);
      }).catch((e) => fail(res, e.code ?? 500, e.message) ?? null);
      if (!existsSync(file)) return;
      return json(res, 201, { id, url: `/api/attachments/${id}` });
    }

    if (method === 'GET' && (m = /^\/api\/attachments\/([0-9]+)$/.exec(path))) {
      const file = join(store.attachmentsDir, m[1] + '.bin');
      if (!existsSync(file)) return fail(res, 404, 'not found');
      const stat = statSync(file);
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': stat.size, 'Cache-Control': 'no-store' });
      createReadStream(file).pipe(res);
      return;
    }

    return fail(res, 404, 'not found');
  }

  return { handle };
}
