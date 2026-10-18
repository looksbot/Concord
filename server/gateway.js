// Concord gateway: Discord-style opcodes (HELLO 10 / IDENTIFY 2 / HEARTBEAT 1 /
// HEARTBEAT_ACK 11 / DISPATCH 0). The server is a ciphertext router: every
// payload field named "envelope" is opaque encrypted bytes.
import { createHash, randomBytes } from 'node:crypto';
import { snowflake } from './snowflake.js';

const OP_DISPATCH = 0, OP_HEARTBEAT = 1, OP_IDENTIFY = 2, OP_HELLO = 10, OP_HEARTBEAT_ACK = 11;
const HEARTBEAT_INTERVAL = 30000;
const IDENTIFY_TIMEOUT = 10000;
const IDLE_TIMEOUT = 120000;

function publicUser(u) {
  return { id: u.id, username: u.username, display: u.display, avatar_seed: u.avatar_seed, created: u.created };
}

export class Gateway {
  constructor(store) {
    this.store = store;
    this.conns = new Map();      // uid -> Set<conn>
    this.sessions = new Map();   // conn -> uid (until identified)
  }

  onConnection(conn) {
    conn.sessionId = snowflake();
    this.sessions.set(conn, null);
    conn.onclose = () => this._drop(conn);
    conn.onmessage = (raw) => this._onFrame(conn, raw);
    conn._idle = setTimeout(() => conn.close(4000), IDLE_TIMEOUT);
    conn._idle.unref?.();
    conn.send(JSON.stringify({ op: OP_HELLO, d: { heartbeat_interval: HEARTBEAT_INTERVAL, session_id: conn.sessionId } }));
    const identifyTimer = setTimeout(() => { if (!this.sessions.get(conn)) conn.close(4001); }, IDENTIFY_TIMEOUT);
    identifyTimer.unref?.();
  }

  _onFrame(conn, raw) {
    conn._idle?.refresh();
    let msg;
    try { msg = JSON.parse(raw); } catch { return conn.close(4002); }
    if (!msg || typeof msg.op !== 'number') return conn.close(4002);
    switch (msg.op) {
      case OP_HEARTBEAT:
        conn.send(JSON.stringify({ op: OP_HEARTBEAT_ACK }));
        return;
      case OP_IDENTIFY: {
        const uid = this._authenticate(msg.d);
        if (!uid) { conn.send(JSON.stringify({ op: OP_DISPATCH, t: 'AUTH_FAILED', d: {} })); return conn.close(4003); }
        this._attach(conn, uid);
        return;
      }
      case 3: { // TYPING (client convention: op 3, d: {channel_id})
        const uid = this.sessions.get(conn);
        const d = msg.d || {};
        if (!uid || typeof d.channel_id !== 'string') return;
        const channel = this.store.channels.get(d.channel_id);
        if (!channel || !this._canAccess(uid, channel)) return;
        this.toChannel(channel, 'TYPING_START', { channel_id: channel.id, user_id: uid }, uid);
        return;
      }
      default: return; // ignore unknown ops
    }
  }

  _authenticate(d) {
    if (!d || typeof d.token !== 'string') return null;
    const hash = createHash('sha256').update(d.token).digest('hex');
    const session = this.store.sessions.get(hash);
    return session ? session.user_id : null;
  }

  _attach(conn, uid) {
    this.sessions.set(conn, uid);
    let set = this.conns.get(uid);
    if (!set) { set = new Set(); this.conns.set(uid, set); }
    set.add(conn);
    const user = this.store.users.get(uid);
    const guilds = [];
    for (const g of this.store.guilds.values()) {
      if (g.members.includes(uid)) {
        guilds.push({ ...g, channels: this.store.guildChannels(g.id) });
      }
    }
    const dmChannels = [];
    for (const c of this.store.channels.values()) {
      if (c.type === 'dm' && c.recipients.includes(uid)) {
        dmChannels.push({ ...c, recipients: c.recipients.map((r) => publicUser(this.store.users.get(r)).username ? publicUser(this.store.users.get(r)) : { id: r }) });
      }
    }
    conn.send(JSON.stringify({
      op: OP_DISPATCH, t: 'READY', d: {
        v: 1, session_id: conn.sessionId, user: publicUser(user),
        heartbeat_interval: HEARTBEAT_INTERVAL,
        guilds, dm_channels: dmChannels,
        presences: this._presenceFor(uid),
      },
    }));
    this._broadcastPresence(uid, 'online');
  }

  _presenceFor(uid) {
    const out = {};
    const seen = new Set([uid]);
    for (const g of this.store.guilds.values()) {
      if (!g.members.includes(uid)) continue;
      for (const m of g.members) {
        if (!seen.has(m)) { seen.add(m); out[m] = this.conns.has(m) ? 'online' : 'offline'; }
      }
    }
    for (const c of this.store.channels.values()) {
      if (c.type !== 'dm' || !c.recipients.includes(uid)) continue;
      for (const r of c.recipients) {
        if (!seen.has(r)) { seen.add(r); out[r] = this.conns.has(r) ? 'online' : 'offline'; }
      }
    }
    return out;
  }

  _broadcastPresence(uid, status) {
    this.toPeers(uid, 'PRESENCE_UPDATE', { user_id: uid, status });
  }

  _drop(conn) {
    clearTimeout(conn._idle);
    const uid = this.sessions.get(conn);
    this.sessions.delete(conn);
    if (uid) {
      const set = this.conns.get(uid);
      if (set) {
        set.delete(conn);
        if (set.size === 0) {
          this.conns.delete(uid);
          this._broadcastPresence(uid, 'offline');
        }
      }
    }
  }

  _canAccess(uid, channel) {
    if (channel.type === 'dm') return channel.recipients.includes(uid);
    const guild = this.store.guilds.get(channel.guild_id);
    return !!guild && guild.members.includes(uid);
  }

  audienceOf(channel) {
    if (channel.type === 'dm') return [...channel.recipients];
    const guild = this.store.guilds.get(channel.guild_id);
    return guild ? [...guild.members] : [];
  }

  // ---- broadcast helpers ---------------------------------------------------
  sendTo(uid, t, d) {
    const set = this.conns.get(uid);
    if (!set) return;
    const frame = JSON.stringify({ op: OP_DISPATCH, t, d });
    for (const c of set) c.send(frame);
  }

  toUsers(uids, t, d, except) {
    const frame = JSON.stringify({ op: OP_DISPATCH, t, d });
    for (const uid of new Set(uids)) {
      if (uid === except) continue;
      const set = this.conns.get(uid);
      if (set) for (const c of set) c.send(frame);
    }
  }

  toChannel(channel, t, d, except) {
    this.toUsers(this.audienceOf(channel), t, d, except);
  }

  toGuild(guildId, t, d, except) {
    const guild = this.store.guilds.get(guildId);
    if (guild) this.toUsers(guild.members, t, d, except);
  }

  toPeers(uid, t, d) {
    // everyone sharing a guild or DM with uid
    const peers = new Set();
    for (const g of this.store.guilds.values()) if (g.members.includes(uid)) g.members.forEach((m) => peers.add(m));
    for (const c of this.store.channels.values()) if (c.type === 'dm' && c.recipients.includes(uid)) c.recipients.forEach((r) => peers.add(r));
    peers.delete(uid);
    this.toUsers([...peers], t, d);
  }

  isOnline(uid) { return this.conns.has(uid); }

  newToken() {
    const token = randomBytes(32).toString('base64url');
    return { token, hash: createHash('sha256').update(token).digest('hex') };
  }
}
