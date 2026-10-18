// Concord web client. All decryption happens here, in the browser.
import * as C from './concord-crypto.js';

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const LS = {
  get(k, d) { try { const v = localStorage.getItem('concord.' + k); return v ? JSON.parse(v) : d; } catch { return d; } },
  set(k, v) { localStorage.setItem('concord.' + k, JSON.stringify(v)); },
  del(k) { localStorage.removeItem('concord.' + k); },
};

const S = {
  token: null, me: null, keys: null, prekeys: null,
  guilds: new Map(),    // gid -> guild {…, channels:[]}
  channels: new Map(),  // cid -> channel
  users: new Map(),     // uid -> publicUser (+ pubs {identity_pub, signing_pub} once fetched)
  msgs: new Map(),      // cid -> Map(mid -> row)
  dmSessions: new Map(),// cid -> ratchet state (persisted)
  dmHeaders: new Map(), // cid -> X3DH header to attach until established
  channelKeys: new Map(),// cid -> {key_id, key} (persisted)
  unread: new Map(),
  presences: new Map(),
  typing: new Map(),    // cid -> Map(uid -> expiry)
  sel: null,            // selected channel id
  view: 'dm',           // 'dm' | 'guild'
  selGuild: null,
  ws: null, hb: null, backoff: 1000, ready: false,
  lastTypingSent: 0,
};

// ============================ api ============================
async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (S.token) opts.headers['Authorization'] = 'Bearer ' + S.token;
  if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function toast(msg, isErr = false) {
  const el = document.createElement('div');
  el.className = 'toast' + (isErr ? ' error' : '');
  el.textContent = msg;
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), 3800);
}

// ============================ local key storage ============================
const kKeys = () => `keys.${S.me.id}`;
const kPrekeys = () => `prekeys.${S.me.id}`;
const kDm = (cid) => `dm.${S.me.id}.${cid}`;
const kCk = (cid) => `ck.${S.me.id}.${cid}`;
const saveSession = (cid) => { const st = S.dmSessions.get(cid); st ? LS.set(kDm(cid), st) : LS.del(kDm(cid)); };
const saveChannelKey = (cid) => { const k = S.channelKeys.get(cid); k ? LS.set(kCk(cid), k) : LS.del(kCk(cid)); };
function loadLocalCrypto() {
  S.keys = LS.get(kKeys(), null);
  S.prekeys = LS.get(kPrekeys(), null);
  S.dmSessions = new Map();
  S.channelKeys = new Map();
}

async function setupFreshKeys() {
  S.keys = await C.generateIdentityKeys();
  LS.set(kKeys(), S.keys);
  await topUpPrekeys(true);
}

async function topUpPrekeys(force = false) {
  if (!force) {
    const st = await api('GET', '/api/keys/@me/status').catch(() => null);
    if (!st || st.opk_count >= 8) return;
  }
  const bundle = await C.buildBundle(S.keys, 20);
  await api('PUT', '/api/keys/@me', bundle.upload);
  const prev = S.prekeys;
  S.prekeys = {
    spk: bundle.local.spk,
    prevSpks: [...(prev?.prevSpks ?? []), ...(prev?.spk ? [prev.spk] : [])].slice(-3),
    opks: [...(prev?.opks ?? []), ...bundle.local.opks], // keep old privs: in-flight sessions may still consume them
  };
  LS.set(kPrekeys(), S.prekeys);
}

// ============================ users/pubs cache ============================
async function getPubs(uid) {
  if (uid === S.me.id) return { identity_pub: S.keys.identity.pub, signing_pub: S.keys.signing.pub };
  const u = S.users.get(uid);
  if (u?.pubs) return u.pubs;
  const pubs = await api('GET', `/api/users/${uid}/pubs`);
  if (u) u.pubs = pubs; else S.users.set(uid, { id: uid, pubs });
  return pubs;
}
const displayName = (uid) => (uid === S.me.id ? S.me.display : (S.users.get(uid)?.display ?? S.users.get(uid)?.username ?? 'unknown'));
const hueOf = (id) => parseInt(id, 10) % 360;
function avatarHtml(uid, cls = '') {
  const name = displayName(uid);
  return `<div class="avatar ${cls}" style="background:hsl(${hueOf(uid ?? '0')} 42% 42%)">${esc((name || '?').slice(0, 2).toUpperCase())}</div>`;
}

// ============================ gateway ============================
function connect() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/gateway`);
  S.ws = ws;
  ws.onopen = () => {
    ws.send(JSON.stringify({ op: 2, d: { token: S.token } }));
    S.backoff = 1000;
  };
  ws.onmessage = (ev) => {
    let f; try { f = JSON.parse(ev.data); } catch { return; }
    if (f.op === 10) {
      clearInterval(S.hb);
      S.hb = setInterval(() => ws.send(JSON.stringify({ op: 1, d: null })), (f.d?.heartbeat_interval ?? 30000));
    } else if (f.op === 0) {
      onDispatch(f.t, f.d).catch((e) => console.error('[dispatch]', f.t, e));
    }
  };
  ws.onclose = () => {
    clearInterval(S.hb);
    S.ready = false;
    if (S.token) setTimeout(connect, S.backoff), S.backoff = Math.min(S.backoff * 2, 30000);
  };
}

async function onDispatch(t, d) {
  switch (t) {
    case 'READY': {
      S.me = d.user; S.users.set(d.user.id, d.user);
      S.presences = new Map(Object.entries(d.presences ?? {}));
      S.guilds = new Map(); S.channels = new Map();
      for (const g of d.guilds ?? []) {
        S.guilds.set(g.id, g);
        for (const c of g.channels ?? []) S.channels.set(c.id, { ...c, guild_id: g.id, type: 'text' });
      }
      for (const c of d.dm_channels ?? []) {
        S.channels.set(c.id, c);
        for (const r of c.recipients ?? []) if (r?.id) S.users.set(r.id, r);
      }
      S.ready = true;
      loadLocalCrypto();
      topUpPrekeys().catch(() => {});
      if (!S.sel) renderAll();
      else { renderAll(); openChannel(S.sel, true); }
      break;
    }
    case 'PRESENCE_UPDATE':
      S.presences.set(d.user_id, d.status);
      renderMembers(); renderChannels(); break;

    case 'MESSAGE_CREATE': onMessage(d); break;
    case 'MESSAGE_UPDATE': {
      const rows = S.msgs.get(d.channel_id);
      const row = rows?.get(d.id);
      if (row) { row.env = d.envelope; row.edited = d.edited; row.payload = null; await decryptRow(row, d.channel_id); }
      break;
    }
    case 'MESSAGE_DELETE': {
      S.msgs.get(d.channel_id)?.delete(d.id);
      if (S.sel === d.channel_id) renderMessages();
      break;
    }
    case 'TYPING_START': {
      if (d.user_id === S.me.id) break;
      let m = S.typing.get(d.channel_id);
      if (!m) { m = new Map(); S.typing.set(d.channel_id, m); }
      m.set(d.user_id, Date.now() + 4000);
      renderTyping();
      break;
    }
    case 'GUILD_MEMBER_ADD': {
      const g = S.guilds.get(d.guild_id);
      if (!g) { // it's me joining a new guild
        if (d.user?.id === S.me.id) {
          const full = await api('GET', `/api/guilds/${d.guild_id}`);
          S.guilds.set(full.guild.id, full.guild);
          for (const c of full.guild.channels ?? []) S.channels.set(c.id, { ...c, guild_id: full.guild.id, type: 'text' });
          renderAll();
        }
        break;
      }
      if (!g.members.includes(d.user.id)) g.members.push(d.user.id);
      S.users.set(d.user.id, d.user);
      renderMembers();
      if (d.user.id !== S.me.id) wrapKeysForNewMember(g.id, d.user.id).catch(console.error);
      break;
    }
    case 'GUILD_MEMBER_REMOVE': {
      const g = S.guilds.get(d.guild_id);
      if (d.user_id === S.me.id) {
        S.guilds.delete(d.guild_id);
        for (const [cid, c] of [...S.channels]) if (c.guild_id === d.guild_id) S.channels.delete(cid);
        if (S.selGuild === d.guild_id) { S.selGuild = null; S.view = 'dm'; S.sel = null; }
        renderAll(); toast('You were removed from a guild');
        break;
      }
      if (!g) break;
      g.members = g.members.filter((m) => m !== d.user_id);
      renderMembers();
      if (d.rotate_keys && g.owner_id === S.me.id) rotateGuildKeys(g.id).catch(console.error);
      break;
    }
    case 'CHANNEL_CREATE': {
      S.channels.set(d.channel.id, d.channel);
      if (!S.guilds.get(d.channel.guild_id)?.channels?.find((c) => c.id === d.channel.id))
        S.guilds.get(d.channel.guild_id)?.channels?.push(d.channel);
      renderChannels(); break;
    }
    case 'CHANNEL_DELETE': {
      S.channels.delete(d.id);
      const g = S.guilds.get(d.guild_id);
      if (g?.channels) g.channels = g.channels.filter((c) => c.id !== d.id);
      if (S.sel === d.id) { S.sel = null; renderChat(); }
      renderChannels(); break;
    }
    case 'CHANNEL_KEY_UPDATE': {
      if (!S.channelKeys.get(d.channel_id) || S.channelKeys.get(d.channel_id).key_id !== d.key_id) {
        S.channelKeys.delete(d.channel_id);
        await ensureChannelKey(d.channel_id).catch(console.error);
        await tryDecryptLocked(d.channel_id);
        renderMessages();
      }
      break;
    }
    case 'DM_CHANNEL_CREATE': {
      if (!S.channels.has(d.channel.id)) {
        S.channels.set(d.channel.id, d.channel);
        for (const r of d.channel.recipients ?? []) if (r?.id) S.users.set(r.id, r);
        renderChannels();
      }
      break;
    }
  }
}

// ============================ messages: receive/decrypt ============================
function rowMap(cid) { let m = S.msgs.get(cid); if (!m) { m = new Map(); S.msgs.set(cid, m); } return m; }

function onMessage(d) {
  const rows = rowMap(d.channel_id);
  if (rows.has(d.id)) return;
  const row = { id: d.id, author_id: d.author_id, created: d.created, edited: d.edited ?? null, env: d.envelope, payload: null, state: 'pending' };
  rows.set(d.id, row);
  if (S.sel === d.channel_id) {
    decryptRow(row, d.channel_id).then(() => { renderMessages(); scrollToBottom(); });
    renderTypingClear(d.author_id, d.channel_id);
  } else {
    const ch = S.channels.get(d.channel_id);
    if (ch) {
      S.unread.set(d.channel_id, (S.unread.get(d.channel_id) ?? 0) + 1);
      renderChannels(); renderGuilds(); updateTitle();
    }
  }
}

async function decryptRow(row, cid) {
  try {
    const payload = await decryptEnv(cid, row.env, row.author_id);
    row.payload = payload;
    row.state = 'ok';
  } catch (e) {
    row.state = 'locked';
    console.warn('decrypt failed', e.message);
  }
}

async function decryptEnv(cid, env, authorId) {
  const ch = S.channels.get(cid);
  if (env?.kind === 'dm' || ch?.type === 'dm') return decryptDmEnv(cid, env, authorId);
  return decryptChannelEnv(cid, env, authorId);
}

async function decryptDmEnv(cid, env, authorId) {
  // signature first — ciphertext authenticity does not depend on our session state
  if (env.sig) {
    const pubs = await getPubs(authorId);
    const ok = await C.verify(pubs.signing_pub, env.sig, C.dmCanonical(cid, env));
    if (!ok) throw new Error('signature check failed');
  }
  if (authorId === S.me.id) { // our own message: use stored send-chain message keys
    const st = S.dmSessions.get(cid);
    const mk = st?.sent?.[`${env.dh}:${env.n}`];
    if (!mk) throw new Error('own message from another device/session');
    return JSON.parse(await C.aeadOpen(mk, env.nonce, env.ct, `${cid}|${env.dh}|${env.n}`));
  }
  let st = S.dmSessions.get(cid);
  if (!st && env.hdr) {
    // first envelope of a session: bootstrap (and verify by opening this very envelope)
    const boot = await bootstrapResponderSession(cid, env);
    if (boot) return JSON.parse(boot.plaintext);
    throw new Error('could not establish session (prekey mismatch)');
  }
  if (!st) throw new Error('no session');
  const pt = await C.ratchetDecrypt(st, cid, env);
  saveSession(cid);
  return JSON.parse(pt);
}

async function bootstrapResponderSession(cid, env) {
  const hdr = env.hdr;
  const attempts = [S.prekeys?.spk, ...(S.prekeys?.prevSpks ?? [])].filter(Boolean);
  for (const spk of attempts) {
    try {
      const { state, consumedOpkId } = await C.x3dhResponder(S.keys, { spk, opks: S.prekeys.opks }, hdr);
      const pt = await C.ratchetDecrypt(state, cid, env); // verify the session actually opens this envelope
      if (consumedOpkId) {
        S.prekeys.opks = S.prekeys.opks.filter((k) => k.id !== consumedOpkId);
        LS.set(kPrekeys(), S.prekeys);
        topUpPrekeys().catch(() => {});
      }
      S.dmSessions.set(cid, state);
      saveSession(cid);
      return { state, plaintext: pt };
    } catch { /* try an older prekey generation */ }
  }
  return null;
}

async function decryptChannelEnv(cid, env, authorId) {
  if (env.sig) {
    const pubs = await getPubs(authorId);
    const ok = await C.verify(pubs.signing_pub, env.sig, C.channelCanonical(cid, env.key_id, env));
    if (!ok) throw new Error('signature check failed');
  }
  let k = S.channelKeys.get(cid);
  if (!k || k.key_id !== env.key_id) {
    k = await ensureChannelKey(cid);
    if (!k || k.key_id !== env.key_id) throw new Error('no channel key');
  }
  return C.channelDecrypt(k.key, env);
}

// ============================ sending ============================
async function ensureDmSession(cid, otherUid) {
  let st = S.dmSessions.get(cid);
  if (st) return st;
  const bundle = await api('GET', `/api/keys/${otherUid}`);
  const { state, header } = await C.x3dhInitiator(S.keys, bundle);
  S.dmSessions.set(cid, state);
  S.dmHeaders.set(cid, header);
  saveSession(cid);
  return state;
}

async function ensureChannelKey(cid) {
  const ch = S.channels.get(cid);
  if (!ch || ch.type === 'dm') return null;
  const cached = S.channelKeys.get(cid);
  if (cached) return cached;
  const r = await api('GET', `/api/channels/${cid}/keys`);
  if (r.wrap?.from) {
    const key = await C.unwrapKeyFor(S.keys.identity.priv, r.wrap.from, r.wrap);
    const entry = { key_id: r.wrap.key_id, key };
    S.channelKeys.set(cid, entry); saveChannelKey(cid);
    return entry;
  }
  // no key yet: the guild owner bootstraps the first generation
  const guild = S.guilds.get(ch.guild_id);
  if (guild?.owner_id === S.me.id) {
    const { key_id, key } = C.generateChannelKey();
    const wrap = await C.wrapKeyFor(S.keys.identity, S.keys.identity.pub, key);
    await api('PUT', `/api/channels/${cid}/keys`, { key_id, wraps: [{ user_id: S.me.id, from: S.keys.identity.pub, ...wrap }] });
    const entry = { key_id, key };
    S.channelKeys.set(cid, entry); saveChannelKey(cid);
    return entry;
  }
  return null;
}

async function sendMessage(payload) {
  const cid = S.sel;
  const ch = S.channels.get(cid);
  if (!ch) return;
  if (ch.type === 'dm') {
    const other = ch.recipients.find((r) => r !== S.me.id) ?? ch.recipients[0];
    const st = await ensureDmSession(cid, other);
    const env = await C.ratchetEncrypt(st, cid, JSON.stringify(payload), S.keys.signing);
    if (!st.established) env.hdr = S.dmHeaders.get(cid);
    saveSession(cid);
    return postEnvelope(cid, env, payload);
  }
  const k = await ensureChannelKey(cid);
  if (!k) return toast('Channel key not distributed yet — try again in a moment', true);
  const env = await C.channelEncrypt(k.key, k.key_id, cid, payload, S.keys.signing);
  return postEnvelope(cid, env, payload);
}

async function postEnvelope(cid, env, payload) {
  try {
    const { message } = await api('POST', `/api/channels/${cid}/messages`, { envelope: env });
    const rows = rowMap(cid);
    if (!rows.has(message.id)) {
      rows.set(message.id, { id: message.id, author_id: message.author_id, created: message.created, edited: null, env, payload, state: 'ok' });
    }
    renderMessages(); scrollToBottom();
  } catch (e) { toast('send failed: ' + e.message, true); }
}

// ============================ key ops for membership changes ============================
async function wrapKeysForNewMember(gid, uid) {
  const pubs = await getPubs(uid).catch(() => null);
  if (!pubs?.identity_pub) return;
  for (const c of S.guilds.get(gid)?.channels ?? []) {
    const k = S.channelKeys.get(c.id) ?? await ensureChannelKey(c.id).catch(() => null);
    if (!k) continue;
    const live = await api('GET', `/api/channels/${c.id}/keys`);
    if (live.key_id && k.key_id !== live.key_id) continue; // someone rotated; that holder wraps
    const wrap = await C.wrapKeyFor(S.keys.identity, pubs.identity_pub, k.key);
    await api('PUT', `/api/channels/${c.id}/keys`, {
      key_id: k.key_id,
      wraps: [{ user_id: uid, from: S.keys.identity.pub, ...wrap }],
    }).catch(console.error);
  }
}

async function rotateGuildKeys(gid) {
  const g = S.guilds.get(gid);
  if (!g) return;
  const memberPubs = {};
  for (const uid of g.members) memberPubs[uid] = (await getPubs(uid).catch(() => null))?.identity_pub;
  for (const c of g.channels ?? []) {
    if (!S.channelKeys.get(c.id) && !(await ensureChannelKey(c.id).catch(() => null))) continue;
    const old = S.channelKeys.get(c.id);
    const { key_id, key } = C.generateChannelKey();
    const wraps = [];
    for (const uid of g.members) {
      if (!memberPubs[uid]) continue;
      const wrap = await C.wrapKeyFor(S.keys.identity, memberPubs[uid], key);
      wraps.push({ user_id: uid, from: S.keys.identity.pub, ...wrap });
    }
    if (!wraps.length) continue;
    await api('PUT', `/api/channels/${c.id}/keys`, { key_id, wraps, rotate: true }).catch(console.error);
    S.channelKeys.set(c.id, { key_id, key }); saveChannelKey(c.id);
    void old;
  }
  toast('Channel keys rotated for remaining members 🔑');
}

async function tryDecryptLocked(cid) {
  const rows = S.msgs.get(cid);
  if (!rows) return;
  for (const row of rows.values()) if (row.state === 'locked') await decryptRow(row, cid);
}

// ============================ ui: rendering ============================
function renderAll() { renderGuilds(); renderChannels(); renderChat(); renderMe(); updateTitle(); }

function updateTitle() {
  const n = [...S.unread.values()].reduce((a, b) => a + b, 0);
  document.title = (n ? `(${n}) ` : '') + 'Concord';
}

function renderGuilds() {
  const el = $('#guildButtons');
  el.innerHTML = '';
  for (const g of S.guilds.values()) {
    const b = document.createElement('button');
    b.title = g.name;
    b.textContent = g.name.slice(0, 2).toUpperCase();
    if (S.view === 'guild' && S.selGuild === g.id) b.classList.add('active');
    let unread = false;
    for (const c of g.channels ?? []) if (S.unread.get(c.id)) unread = true;
    if (unread) b.classList.add('unread');
    b.onclick = () => { S.view = 'guild'; S.selGuild = g.id; renderAll(); const first = (g.channels ?? [])[0]; if (first) openChannel(first.id); };
    el.appendChild(b);
  }
}

function renderChannels() {
  const list = $('#channelList');
  const actions = $('#sidebarActions');
  const isHome = S.view === 'dm';
  $('#dmSearch').hidden = !isHome;
  $('#sidebarTitle').textContent = isHome ? 'Direct Messages' : (S.guilds.get(S.selGuild)?.name ?? '');
  actions.innerHTML = '';
  list.innerHTML = '';

  if (isHome) {
    const dms = [...S.channels.values()].filter((c) => c.type === 'dm');
    dms.sort((a, b) => b.created - a.created);
    for (const c of dms) {
      const other = c.recipients.find((r) => r?.id !== S.me.id) ?? c.recipients[0];
      const oid = other?.id ?? other;
      const online = S.presences.get(oid) === 'online';
      const el = document.createElement('div');
      el.className = 'chan' + (S.sel === c.id ? ' active' : '');
      el.innerHTML = `${avatarHtml(oid)}<span class="name">${esc(displayName(oid))}</span>` +
        (S.unread.get(c.id) ? `<span class="badge">${S.unread.get(c.id)}</span>` : '');
      el.prepend(Object.assign(document.createElement('span'), { className: 'presence' + (online ? ' online' : '') }));
      el.onclick = () => openChannel(c.id);
      list.appendChild(el);
    }
    if (!dms.length) list.innerHTML = '<div class="side-label">No conversations yet — search above</div>';
    return;
  }

  const g = S.guilds.get(S.selGuild);
  if (!g) return;
  const chans = (g.channels ?? []).slice().sort((a, b) => (a.id > b.id ? 1 : -1));
  for (const c of chans) {
    const el = document.createElement('div');
    el.className = 'chan' + (S.sel === c.id ? ' active' : '');
    el.innerHTML = `<span class="hash">#</span><span class="name">${esc(c.name)}</span>` +
      (S.unread.get(c.id) ? `<span class="badge">${S.unread.get(c.id)}</span>` : '');
    el.onclick = () => openChannel(c.id);
    list.appendChild(el);
  }
  if (g.owner_id === S.me.id) {
    const addCh = document.createElement('button');
    addCh.className = 'header-actions-btn'; addCh.textContent = '+ #'; addCh.title = 'Create channel';
    addCh.onclick = async () => {
      const name = prompt('New channel name (lowercase, no spaces)');
      if (!name) return;
      try {
        const { channel } = await api('POST', `/api/guilds/${g.id}/channels`, { name });
        S.channels.set(channel.id, channel);
        g.channels = [...(g.channels ?? []), channel];
        renderChannels(); openChannel(channel.id);
      } catch (e) { toast(e.message, true); }
    };
    actions.appendChild(addCh);

    const invite = document.createElement('button');
    invite.textContent = '🔑'; invite.title = 'Create invite code';
    invite.onclick = async () => {
      try {
        const { invite: inv } = await api('POST', '/api/invites', { guild_id: g.id });
        await navigator.clipboard?.writeText(inv.code).catch(() => {});
        toast(`Invite code: ${inv.code} (copied)`);
      } catch (e) { toast(e.message, true); }
    };
    actions.appendChild(invite);
  }
}

function renderMembers() {
  const panel = $('#members');
  if (S.view !== 'guild' || !S.selGuild) { panel.hidden = true; return; }
  const g = S.guilds.get(S.selGuild);
  if (!g) { panel.hidden = true; return; }
  panel.hidden = false;
  $('#membersTitle').textContent = `Members — ${g.members.length}`;
  const el = $('#memberList');
  el.innerHTML = '';
  const sorted = [...g.members].sort((a, b) => displayName(a).localeCompare(displayName(b)));
  for (const uid of sorted) {
    const div = document.createElement('div');
    const online = S.presences.get(uid) === 'online';
    div.className = 'member' + (online ? '' : ' off');
    div.innerHTML = `${avatarHtml(uid)}<span class="nm">${esc(displayName(uid))}${uid === g.owner_id ? ' <sub>👑 owner</sub>' : ''}</span><span class="dot ${online ? 'on' : ''}"></span>`;
    el.appendChild(div);
  }
}

function renderMe() {
  if (!S.me) return;
  $('#meName').textContent = `${S.me.display} (@${S.me.username})`;
  $('#meAvatar').outerHTML = avatarHtml(S.me.id, 'tiny').replace('class="avatar', 'id="meAvatar" class="avatar');
}

function renderChat() {
  const ch = S.channels.get(S.sel);
  $('#chatHash').textContent = ch?.type === 'dm' ? '@' : '#';
  $('#chatTitle').textContent = ch ? (ch.type === 'dm'
    ? displayName((ch.recipients.find((r) => r?.id !== S.me.id) ?? ch.recipients[0])?.id ?? ch.recipients[0])
    : ch.name) : 'Pick a channel';
  const lock = $('#chatLock');
  if (!ch) { lock.hidden = true; $('#chatSub').textContent = ''; }
  else if (ch.type === 'dm') {
    lock.hidden = false; lock.textContent = '🔒 E2E · signal ratchet';
    const other = (ch.recipients.find((r) => r?.id !== S.me.id) ?? ch.recipients[0])?.id;
    getPubs(other).then((p) => p && C.safetyNumber(S.keys.identity.pub, p.identity_pub).then((n) => {
      lock.title = `Safety number:\n${n}`;
      $('#chatSub').textContent = n.split(' ').slice(0, 4).join(' ') + '…';
    })).catch(() => {});
  } else {
    const k = S.channelKeys.get(ch.id);
    lock.hidden = false;
    lock.textContent = k ? `🔒 key ${k.key_id.slice(0, 6)}` : '🔒 pending key';
    lock.title = 'Messages encrypted with a channel key wrapped per member';
    $('#chatSub').textContent = k ? '' : 'waiting for key distribution…';
  }
  $('#msgInput').disabled = !ch;
  $('#msgInput').placeholder = ch ? 'Send an encrypted message…' : 'Select a channel first';
  renderMessages();
  renderMembers();
}

function rowHtml(row, prev) {
  const grouped = prev && prev.author_id === row.author_id && row.created - prev.created < 5 * 60 * 1000 && row.state !== 'locked' && prev.state !== 'locked';
  let body;
  if (row.state === 'pending') body = '<span class="text" style="opacity:.4">decrypting…</span>';
  else if (row.state === 'locked') body = '<span class="text">🔒 encrypted message (no key on this device)</span>';
  else {
    const p = row.payload ?? {};
    if (p.kind === 'text') body = `<div class="text">${esc(p.text)}</div>`;
    else if (p.kind === 'file') body = `<div class="text"><span class="file-link" data-id="${row.id}">📎 ${esc(p.name)} <small>(${Math.ceil((p.size ?? 0) / 1024)} KB, encrypted)</small></span></div>`;
    else body = '<span class="text" style="opacity:.5">unsupported message</span>';
  }
  const mine = row.author_id === S.me.id;
  const ch = S.channels.get(S.sel);
  const canDelete = mine || (ch && S.guilds.get(ch.guild_id)?.owner_id === S.me.id);
  return `<div class="msg ${row.state === 'locked' ? 'failed' : ''}" data-mid="${row.id}">
    ${grouped ? '<div class="avatar" style="visibility:hidden"></div>' : avatarHtml(row.author_id)}
    <div class="body">
      ${grouped ? '' : `<div class="meta"><span class="author">${esc(displayName(row.author_id))}</span><span class="time">${new Date(row.created).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}${row.edited ? ' <span class="edited">(edited)</span>' : ''}</span></div>`}
      ${body}
    </div>
    ${mine || canDelete ? `<div class="actions">${mine ? `<button data-act="edit" title="Edit">✎</button>` : ''}${canDelete ? `<button data-act="del" title="Delete">🗑</button>` : ''}</div>` : ''}
  </div>`;
}

function renderMessages() {
  const el = $('#messages');
  const rows = S.msgs.get(S.sel);
  if (!rows || !rows.size) {
    el.innerHTML = '<div class="empty-state">🔒 Everything you send here is end-to-end encrypted.<br>The server only ever sees ciphertext.</div>';
    return;
  }
  const list = [...rows.values()].sort((a, b) => (a.id > b.id ? 1 : -1));
  let html = '', prev = null, prevDay = '';
  for (const row of list) {
    const day = new Date(row.created).toDateString();
    if (day !== prevDay) { html += `<div class="day-sep">${day}</div>`; prevDay = day; prev = null; }
    html += rowHtml(row, prev);
    prev = row;
  }
  el.innerHTML = html;
  el.querySelectorAll('[data-act="del"]').forEach((b) => b.onclick = () => deleteMessage(b.closest('.msg').dataset.mid));
  el.querySelectorAll('[data-act="edit"]').forEach((b) => b.onclick = () => editMessage(b.closest('.msg').dataset.mid));
  el.querySelectorAll('.file-link').forEach((f) => f.onclick = () => downloadFile(f.dataset.id));
}

function renderTypingClear(uid, cid) {
  S.typing.get(cid)?.delete(uid);
  renderTyping();
}
function renderTyping() {
  const m = S.typing.get(S.sel);
  if (!m) { $('#typingBar').textContent = ''; return; }
  const now = Date.now();
  const names = [...m.entries()].filter(([, t]) => t > now).map(([uid]) => displayName(uid));
  $('#typingBar').textContent = names.length ? `${names.join(', ')} ${names.length === 1 ? 'is' : 'are'} typing…` : '';
}

async function openChannel(cid, silent = false) {
  S.sel = cid;
  S.unread.delete(cid);
  const ch = S.channels.get(cid);
  if (ch?.type !== 'dm') ensureChannelKey(cid).then(() => { renderChat(); }).catch(() => {});
  renderChannels(); renderGuilds(); renderChat(); updateTitle();
  if (!silent) scrollToBottom(true);
  // fetch + decrypt history
  try {
    const { messages } = await api('GET', `/api/channels/${cid}/messages?limit=50`);
    const rows = rowMap(cid);
    let changed = false;
    for (const msg of messages) {
      if (!rows.has(msg.id)) {
        rows.set(msg.id, { id: msg.id, author_id: msg.author_id, created: msg.created, edited: msg.edited, env: msg.envelope, payload: null, state: 'pending' });
        changed = true;
      }
    }
    if (changed) {
      for (const row of rows.values()) if (row.state === 'pending') await decryptRow(row, cid);
      renderMessages(); scrollToBottom(true);
    }
  } catch (e) { if (!silent) toast('history: ' + e.message, true); }
}

function scrollToBottom(inst = false) {
  const el = $('#messages');
  if (inst) el.scrollTop = el.scrollHeight;
  else if (el.scrollHeight - el.scrollTop - el.clientHeight < 240) el.scrollTop = el.scrollHeight;
}

async function editMessage(mid) {
  const rows = S.msgs.get(S.sel);
  const row = rows?.get(mid);
  if (!row || row.state !== 'ok') return;
  const p = row.payload;
  if (p.kind !== 'text') return;
  const next = prompt('Edit message', p.text);
  if (next === null || next === p.text) return;
  const ch = S.channels.get(S.sel);
  let env;
  if (ch.type === 'dm') {
    const st = S.dmSessions.get(S.sel);
    if (!st) return toast('no session', true);
    env = await C.ratchetEncrypt(st, S.sel, JSON.stringify({ kind: 'text', text: next }), S.keys.signing);
    saveSession(S.sel);
  } else {
    const k = await ensureChannelKey(S.sel);
    if (!k) return;
    env = await C.channelEncrypt(k.key, k.key_id, S.sel, { kind: 'text', text: next }, S.keys.signing);
  }
  await api('PATCH', `/api/channels/${S.sel}/messages/${mid}`, { envelope: env });
  row.payload = { kind: 'text', text: next }; row.env = env; row.edited = Date.now();
  renderMessages();
}

async function deleteMessage(mid) {
  if (!confirm('Delete this message?')) return;
  try { await api('DELETE', `/api/channels/${S.sel}/messages/${mid}`); } catch (e) { toast(e.message, true); }
}

// ============================ attachments ============================
async function sendFile(file) {
  const key = C.randomB64u(32);
  const buf = await file.arrayBuffer();
  const { nonce, ct } = await C.aeadSealBytes(key, buf);
  const ctBytes = C.unb64u(ct);
  const res = await fetch('/api/attachments', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + S.token, 'Content-Type': 'application/octet-stream' },
    body: ctBytes,
  });
  if (!res.ok) throw new Error('upload failed');
  const { id } = await res.json();
  await sendMessage({ kind: 'file', id, key, nonce, name: file.name, mime: file.type || 'application/octet-stream', size: file.size });
}

async function downloadFile(mid) {
  const row = S.msgs.get(S.sel)?.get(mid);
  const p = row?.payload;
  if (!p || p.kind !== 'file') return;
  toast('Downloading + decrypting…');
  const res = await fetch(`/api/attachments/${p.id}`, { headers: { 'Authorization': 'Bearer ' + S.token } });
  if (!res.ok) return toast('download failed', true);
  const ctB64 = C.b64u(new Uint8Array(await res.arrayBuffer()));
  const bytes = await C.aeadOpenBytes(p.key, p.nonce, ctB64);
  const url = URL.createObjectURL(new Blob([bytes], { type: p.mime }));
  const a = document.createElement('a');
  a.href = url; a.download = p.name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

// ============================ auth + boot ============================
async function boot() {
  bindUi();
  S.token = LS.get('token', null);
  const uid = LS.get('uid', null);
  if (S.token && uid) {
    try {
      const { user } = await api('GET', '/api/users/@me');
      S.me = user;
      loadLocalCrypto();
      if (!S.keys) { await setupFreshKeys(); }
      showApp(); connect();
      return;
    } catch { LS.del('token'); LS.del('uid'); S.token = null; }
  }
  $('#auth').hidden = false;
}

function showApp() {
  $('#auth').hidden = true;
  $('#app').hidden = false;
}

function bindUi() {
  $('#swapAuth').onclick = (e) => {
    e.preventDefault();
    $('#loginForm').hidden = true; $('#registerForm').hidden = false;
    $('#swapAuth').parentElement.hidden = true; $('#backAuth').parentElement.hidden = false;
  };
  $('#backAuth').onclick = (e) => {
    e.preventDefault();
    $('#loginForm').hidden = false; $('#registerForm').hidden = true;
    $('#swapAuth').parentElement.hidden = false; $('#backAuth').parentElement.hidden = true;
  };
  $('#loginForm').onsubmit = async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    try {
      const { token, user } = await api('POST', '/api/auth/login', { username: f.get('username'), password: f.get('password') });
      S.token = token; S.me = user; LS.set('token', token); LS.set('uid', user.id);
      loadLocalCrypto();
      if (!S.keys) await setupFreshKeys();
      showApp(); connect();
    } catch (err) { toast(err.message, true); }
  };
  $('#registerForm').onsubmit = async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    try {
      const { token, user } = await api('POST', '/api/auth/register', { username: f.get('username'), password: f.get('password'), display: f.get('display') });
      S.token = token; S.me = user; LS.set('token', token); LS.set('uid', user.id);
      await setupFreshKeys();
      showApp(); connect();
      toast('Welcome! Your encryption keys were generated on this device 🔑');
    } catch (err) { toast(err.message, true); }
  };

  $('#homeBtn').onclick = () => { S.view = 'dm'; S.selGuild = null; S.sel = null; renderAll(); };
  $('#addGuildBtn').onclick = () => $('#guildDialog').showModal();
  $('#guildDialogClose').onclick = () => $('#guildDialog').close();
  $('#guildForm').onsubmit = async (e) => {
    e.preventDefault();
    const name = new FormData(e.target).get('name');
    if (!name) return;
    try {
      const { guild } = await api('POST', '/api/guilds', { name });
      S.guilds.set(guild.id, guild);
      for (const c of guild.channels ?? []) S.channels.set(c.id, { ...c, guild_id: guild.id, type: 'text' });
      $('#guildDialog').close(); e.target.reset();
      S.view = 'guild'; S.selGuild = guild.id; renderAll();
      openChannel(guild.channels?.[0]?.id).catch(() => {});
    } catch (err) { toast(err.message, true); }
  };
  $('#joinForm').onsubmit = async (e) => {
    e.preventDefault();
    const code = new FormData(e.target).get('code').trim();
    if (!code) return;
    try {
      const { guild } = await api('POST', `/api/invites/${encodeURIComponent(code)}/join`);
      S.guilds.set(guild.id, guild);
      for (const c of guild.channels ?? []) S.channels.set(c.id, { ...c, guild_id: guild.id, type: 'text' });
      $('#guildDialog').close(); e.target.reset();
      S.view = 'guild'; S.selGuild = guild.id; renderAll();
      openChannel(guild.channels?.[0]?.id).catch(() => {});
    } catch (err) { toast(err.message, true); }
  };

  $('#userSearch').oninput = async (e) => {
    const q = e.target.value.trim();
    if (q.length < 2) { $('#searchResults').innerHTML = ''; return; }
    try {
      const { users } = await api('GET', `/api/users?query=${encodeURIComponent(q)}`);
      const el = $('#searchResults');
      el.innerHTML = '';
      for (const u of users) {
        S.users.set(u.id, u);
        const d = document.createElement('div');
        d.className = 'chan';
        d.innerHTML = `${avatarHtml(u.id)}<span class="name">${esc(u.display)} <small>@${esc(u.username)}</small></span>`;
        d.onclick = async () => {
          try {
            const { channel } = await api('POST', '/api/users/@me/channels', { recipient_id: u.id });
            for (const r of channel.recipients ?? []) if (r?.id) S.users.set(r.id, r);
            S.channels.set(channel.id, channel);
            e.target.value = ''; el.innerHTML = '';
            openChannel(channel.id);
          } catch (err) { toast(err.message, true); }
        };
        el.appendChild(d);
      }
    } catch { /* ignore */ }
  };

  const input = $('#msgInput');
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); submit(); }
  });
  input.addEventListener('input', () => {
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight, 160) + 'px';
    if (Date.now() - S.lastTypingSent > 2500 && S.sel && S.ws?.readyState === 1) {
      S.lastTypingSent = Date.now();
      S.ws.send(JSON.stringify({ op: 3, d: { channel_id: S.sel } }));
    }
  });
  $('#sendBtn').onclick = submit;
  $('#attachBtn').onclick = () => $('#fileInput').click();
  $('#fileInput').onchange = async (e) => {
    const file = e.target.files[0];
    e.target.value = '';
    if (!file) return;
    if (file.size > 8 * 1024 * 1024) return toast('Max 8 MB', true);
    try { await sendFile(file); } catch (err) { toast(err.message, true); }
  };

  setInterval(renderTyping, 1000);
}

async function submit() {
  const input = $('#msgInput');
  const text = input.value.trim();
  if (!text || !S.sel) return;
  input.value = ''; input.style.height = 'auto';
  try { await sendMessage({ kind: 'text', text }); }
  catch (e) { toast(e.message, true); input.value = text; }
}

boot();
