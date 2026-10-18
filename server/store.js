// JSON persistence: collections in memory, atomic flush (tmp + rename), debounced.
import { mkdirSync, readFileSync, writeFileSync, renameSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { snowflake } from './snowflake.js';

export class Store {
  constructor(dir) {
    this.dir = dir;
    this.messagesDir = join(dir, 'messages');
    this.attachmentsDir = join(dir, 'attachments');
    mkdirSync(this.messagesDir, { recursive: true });
    mkdirSync(this.attachmentsDir, { recursive: true });
    this.users = new Map();     // uid -> user (incl. auth + key material public halves)
    this.sessions = new Map();  // tokenHash -> {user_id, created}
    this.guilds = new Map();    // gid -> guild
    this.channels = new Map();  // cid -> channel
    this.invites = new Map();   // code -> invite
    this.dmIndex = new Map();   // "uidA|uidB" (sorted) -> cid
    this.messages = new Map();  // cid -> [message, ...] ascending
    this._dirty = new Set();
    this._timer = null;
    this._load();
  }

  _file(name) { return join(this.dir, name + '.json'); }

  _load() {
    const readMap = (m, name) => {
      const f = this._file(name);
      if (!existsSync(f)) return;
      try {
        for (const [k, v] of JSON.parse(readFileSync(f, 'utf8'))) m.set(k, v);
      } catch (e) { console.error(`[store] failed to parse ${f}:`, e.message); }
    };
    readMap(this.users, 'users');
    readMap(this.sessions, 'sessions');
    readMap(this.guilds, 'guilds');
    readMap(this.channels, 'channels');
    readMap(this.invites, 'invites');
    readMap(this.dmIndex, 'dm-index');
    if (existsSync(this.messagesDir)) {
      for (const f of readdirSync(this.messagesDir)) {
        if (!f.endsWith('.json')) continue;
        try {
          const arr = JSON.parse(readFileSync(join(this.messagesDir, f), 'utf8'));
          this.messages.set(f.slice(0, -5), arr);
        } catch { /* skip corrupt file */ }
      }
    }
  }

  markDirty(name) {
    this._dirty.add(name);
    if (this._timer) return;
    this._timer = setTimeout(() => this.flush(), 250);
    this._timer.unref();
  }

  _atomicWrite(path, data) {
    const tmp = path + '.tmp';
    writeFileSync(tmp, data);
    renameSync(tmp, path);
  }

  _save(name, value) {
    this._atomicWrite(this._file(name), JSON.stringify(value));
  }

  flush() {
    if (this._timer) { clearTimeout(this._timer); this._timer = null; }
    const d = [...this._dirty]; this._dirty.clear();
    for (const name of d) {
      switch (name) {
        case 'users': this._save('users', [...this.users]); break;
        case 'sessions': this._save('sessions', [...this.sessions]); break;
        case 'guilds': this._save('guilds', [...this.guilds]); break;
        case 'channels': this._save('channels', [...this.channels]); break;
        case 'invites': this._save('invites', [...this.invites]); break;
        case 'dm-index': this._save('dm-index', [...this.dmIndex]); break;
        default:
          if (name.startsWith('msg:')) {
            const cid = name.slice(4);
            this._atomicWrite(join(this.messagesDir, cid + '.json'), JSON.stringify(this.messages.get(cid) ?? []));
          }
      }
    }
  }

  // ---- users -------------------------------------------------------------
  createUser({ username, display, passwordSalt, passwordHash }) {
    const id = snowflake();
    const user = {
      id, username, display: display || username,
      created: Date.now(), avatar_seed: Math.floor(Math.random() * 8),
      password: { salt: passwordSalt, hash: passwordHash },
      keys: null, // {identity_pub, signing_pub, spk:{pub,sig}, opks:[{id,pub,sig}]}
    };
    this.users.set(id, user);
    this.markDirty('users');
    return user;
  }

  byUsername(name) {
    const lower = name.toLowerCase();
    for (const u of this.users.values()) if (u.username.toLowerCase() === lower) return u;
    return null;
  }

  // ---- guilds / channels --------------------------------------------------
  createGuild({ name, ownerId }) {
    const id = snowflake();
    const guild = { id, name, owner_id: ownerId, created: Date.now(), members: [ownerId] };
    this.guilds.set(id, guild);
    this.markDirty('guilds');
    const channel = this.createChannel({ guildId: id, name: 'general' });
    return { guild, channel };
  }

  createChannel({ guildId, name }) {
    const id = snowflake();
    const channel = {
      id, guild_id: guildId, name, type: 'text', created: Date.now(),
      key_id: null, wraps: {}, // wraps: uid -> {key_id, by, iv, ct}
    };
    this.channels.set(id, channel);
    this.markDirty('channels');
    return channel;
  }

  guildChannels(guildId) {
    const out = [];
    for (const c of this.channels.values()) if (c.guild_id === guildId) out.push(c);
    out.sort((a, b) => idCmp(a.id, b.id));
    return out;
  }

  openDm(a, b) {
    const key = [a, b].sort().join('|');
    let cid = this.dmIndex.get(key);
    if (cid) {
      const existing = this.channels.get(cid);
      if (existing) return { channel: existing, created: false };
    }
    const id = snowflake();
    const channel = { id, guild_id: null, name: null, type: 'dm', created: Date.now(), recipients: [a, b] };
    this.channels.set(id, channel);
    this.dmIndex.set(key, id);
    this.markDirty('channels'); this.markDirty('dm-index');
    return { channel, created: true };
  }

  // ---- messages -----------------------------------------------------------
  addMessage(channelId, authorId, envelope) {
    const id = snowflake();
    const msg = { id, channel_id: channelId, author_id: authorId, created: Date.now(), edited: null, envelope };
    let arr = this.messages.get(channelId);
    if (!arr) { arr = []; this.messages.set(channelId, arr); }
    arr.push(msg);
    if (arr.length > 5000) arr.splice(0, arr.length - 5000);
    this.markDirty('msg:' + channelId);
    return msg;
  }

  messagesBefore(channelId, before, limit = 50) {
    const arr = this.messages.get(channelId) ?? [];
    let list = before ? arr.filter((m) => BigInt(m.id) < BigInt(before)) : arr;
    return list.slice(-limit);
  }

  // ---- invites ------------------------------------------------------------
  createInvite(guildId) {
    const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
    let code;
    do {
      code = Array.from({ length: 8 }, () => alphabet[Math.floor(Math.random() * alphabet.length)]).join('');
    } while (this.invites.has(code));
    this.invites.set(code, { code, guild_id: guildId, created: Date.now() });
    this.markDirty('invites');
    return this.invites.get(code);
  }
}

function idCmp(a, b) { return BigInt(a) < BigInt(b) ? -1 : BigInt(a) > BigInt(b) ? 1 : 0; }
