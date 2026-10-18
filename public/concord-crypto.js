// Concord E2E crypto — runs identically in browsers and Node >= 22 (WebCrypto).
// Everything the server relays (ciphertexts, wraps, headers) is produced here
// and only here; private keys never leave localStorage on the client.
//
// Primitives: X25519 (agreement), Ed25519 (signatures), HKDF-SHA256,
// AES-256-GCM (AEAD). No third-party code.

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();
const td = new TextDecoder();

// ---- base64url helpers -----------------------------------------------------
export function b64u(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function unb64u(str) {
  const s = str.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
export const randomB64u = (n = 32) => b64u(crypto.getRandomValues(new Uint8Array(n)));

const X = 'X25519', ED = 'Ed25519';

// ---- key generation / import ------------------------------------------------
export async function generateIdentityKeys() {
  const [identity, signing] = await Promise.all([
    subtle.generateKey({ name: X }, true, ['deriveBits']),
    subtle.generateKey({ name: ED }, true, ['sign', 'verify']),
  ]);
  const [idPub, idPriv, sPub, sPriv] = await Promise.all([
    subtle.exportKey('jwk', identity.publicKey),
    subtle.exportKey('jwk', identity.privateKey),
    subtle.exportKey('jwk', signing.publicKey),
    subtle.exportKey('jwk', signing.privateKey),
  ]);
  return {
    identity: { pub: idPub.x, priv: idPriv.d },
    signing: { pub: sPub.x, priv: sPriv.d },
  };
}
export async function generateEphemeral() { // X25519 pair, e.g. signed prekeys / ratchets
  const kp = await subtle.generateKey({ name: X }, true, ['deriveBits']);
  const [pub, priv] = await Promise.all([subtle.exportKey('jwk', kp.publicKey), subtle.exportKey('jwk', kp.privateKey)]);
  return { pub: pub.x, priv: priv.d };
}

const importXpub = (x) => subtle.importKey('jwk', { kty: 'OKP', crv: X, x }, { name: X }, false, []);
// private OKP JWKs must carry both d and x
const importXpriv = (pair) => subtle.importKey('jwk', { kty: 'OKP', crv: X, x: pair.pub, d: pair.priv }, { name: X }, false, ['deriveBits']);
const importSpub = (x) => subtle.importKey('jwk', { kty: 'OKP', crv: ED, x }, { name: ED }, false, ['verify']);
const importSpriv = (pair) => subtle.importKey('jwk', { kty: 'OKP', crv: ED, x: pair.pub, d: pair.priv }, { name: ED }, false, ['sign']);

// `pair` is always a {pub, priv} keypair object
async function dh(pair, pubB64u) {
  return new Uint8Array(await subtle.deriveBits({ name: X, public: await importXpub(pubB64u) }, await importXpriv(pair), 256));
}

// ---- signatures ---------------------------------------------------------------
export async function sign(pair, message) {
  const sig = await subtle.sign({ name: ED }, await importSpriv(pair), te.encode(message));
  return b64u(new Uint8Array(sig));
}
export async function verify(pubB64u, sigB64u, message) {
  try {
    return await subtle.verify({ name: ED }, await importSpub(pubB64u), unb64u(sigB64u), te.encode(message));
  } catch { return false; }
}

// ---- HKDF / AEAD ----------------------------------------------------------------
async function hkdf(ikm, salt, info, lengthBytes) {
  const key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  // deriveBits measures length in BITS; callers pass bytes
  return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: te.encode(info) }, key, lengthBytes * 8));
}
const ZEROS = new Uint8Array(32);

async function aesKey(raw) {
  return subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
export async function aeadSeal(rawKeyB64u, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await aesKey(unb64u(rawKeyB64u));
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(plaintext));
  return { nonce: b64u(iv), ct: b64u(new Uint8Array(ct)) };
}
export async function aeadOpen(rawKeyB64u, nonce, ct, associatedData = '') {
  const key = await aesKey(unb64u(rawKeyB64u));
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: unb64u(nonce), additionalData: te.encode(associatedData) }, key, unb64u(ct));
  return td.decode(pt);
}
export async function aeadSealBytes(rawKeyB64u, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await aesKey(unb64u(rawKeyB64u));
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes);
  return { nonce: b64u(iv), ct: b64u(new Uint8Array(ct)) };
}
export async function aeadOpenBytes(rawKeyB64u, nonce, ctB64u) {
  const key = await aesKey(unb64u(rawKeyB64u));
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: unb64u(nonce) }, key, unb64u(ctB64u));
  return new Uint8Array(pt);
}
async function aeadSealAD(rawKeyB64u, plaintext, ad) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await aesKey(unb64u(rawKeyB64u));
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: te.encode(ad) }, key, te.encode(plaintext));
  return { nonce: b64u(iv), ct: b64u(new Uint8Array(ct)) };
}

// ---- key bundles (server stores public halves only) --------------------------------
export async function buildBundle(keys, nOpks = 20) {
  const spk = await generateEphemeral();
  const spkSig = await sign(keys.signing, `concord/spk:${spk.pub}`);
  const opks = [];
  for (let i = 0; i < nOpks; i++) {
    const k = await generateEphemeral();
    const id = randomB64u(8);
    opks.push({ id, pub: k.pub, priv: k.priv, sig: await sign(keys.signing, `concord/opk:${id}:${k.pub}`) });
  }
  return {
    upload: {
      identity_pub: keys.identity.pub,
      signing_pub: keys.signing.pub,
      spk: { pub: spk.pub, sig: spkSig },
      opks: opks.map(({ id, pub, sig }) => ({ id, pub, sig })),
    },
    // private halves stay local: the current SPK + unconsumed OPKs
    local: { spk: { id: 'spk', pub: spk.pub, priv: spk.priv }, opks: opks.map(({ id, pub, priv }) => ({ id, pub, priv })) },
  };
}

// ---- X3DH-lite session setup ----------------------------------------------------------
// Alice:  DH1=X(idA,idB) DH2=X(idA,spkB) DH3=X(ekA,idB) DH4=X(ekA,spkB) DH5=X(ekA,opkB)?
export async function x3dhInitiator(myKeys, bundle) {
  // verify the bundle is authentic before trusting it (server could tamper)
  const spkOk = await verify(bundle.signing_pub, bundle.spk.sig, `concord/spk:${bundle.spk.pub}`);
  if (!spkOk) throw new Error('SPK signature invalid');
  if (bundle.opk) {
    const ok = await verify(bundle.signing_pub, bundle.opk.sig, `concord/opk:${bundle.opk.id}:${bundle.opk.pub}`);
    if (!ok) throw new Error('OPK signature invalid');
  }
  const eph = await generateEphemeral();
  const d1 = await dh(myKeys.identity, bundle.identity_pub);
  const d2 = await dh(myKeys.identity, bundle.spk.pub);
  const d3 = await dh(eph, bundle.identity_pub);
  const d4 = await dh(eph, bundle.spk.pub);
  const d5 = bundle.opk ? await dh(eph, bundle.opk.pub) : null;
  const ikm = new Uint8Array(32 * (d5 ? 5 : 4));
  ikm.set(d1, 0); ikm.set(d2, 32); ikm.set(d3, 64); ikm.set(d4, 96); if (d5) ikm.set(d5, 128);
  const rk = await hkdf(ikm, ZEROS, 'concord/x3dh/dm', 32);
  const chain = await hkdf(d4, rk, 'concord/chain', 32);
  const state = {
    rk: b64u(rk), cks: b64u(chain), ckr: null,
    dhs: eph, dhr: bundle.spk.pub,
    ns: 0, nr: 0, pn: 0, skipped: {}, sent: {}, established: false,
  };
  const header = { ik: myKeys.identity.pub, ek: eph.pub, opk_id: bundle.opk?.id ?? null };
  return { state, header };
}

// Bob derives the same SK from the header carried on the first envelope.
export async function x3dhResponder(myKeys, localPrekeys, header) {
  const spkPriv = localPrekeys?.spk?.priv;
  if (!spkPriv) throw new Error('no local signed prekey');
  const opk = header.opk_id ? localPrekeys.opks?.find((k) => k.id === header.opk_id) : null;
  const d1 = await dh(myKeys.identity, header.ik);
  const d2 = await dh(localPrekeys.spk, header.ik);
  const d3 = await dh(myKeys.identity, header.ek);
  const d4 = await dh(localPrekeys.spk, header.ek);
  const d5 = opk ? await dh(opk, header.ek) : null;
  const ikm = new Uint8Array(32 * (d5 ? 5 : 4));
  ikm.set(d1, 0); ikm.set(d2, 32); ikm.set(d3, 64); ikm.set(d4, 96); if (d5) ikm.set(d5, 128);
  const rk = await hkdf(ikm, ZEROS, 'concord/x3dh/dm', 32);
  const chain = await hkdf(d4, rk, 'concord/chain', 32);
  return {
    state: {
      rk: b64u(rk), cks: null, ckr: b64u(chain),
      dhs: localPrekeys.spk, dhr: header.ek,
      ns: 0, nr: 0, pn: 0, skipped: {}, sent: {}, established: true,
    },
    consumedOpkId: opk?.id ?? null,
  };
}

// ---- double ratchet -------------------------------------------------------------------
const MAX_SKIP = 200;

async function kdfRk(rkB64u, dhOut) {
  const out = await hkdf(dhOut, unb64u(rkB64u), 'concord/rk', 64);
  return { rk: b64u(out.subarray(0, 32)), ck: b64u(out.subarray(32, 64)) };
}
async function kdfCk(ckB64u) {
  const out = await hkdf(ZEROS, unb64u(ckB64u), 'concord/ck', 64);
  return { ck: b64u(out.subarray(0, 32)), mk: b64u(out.subarray(32, 64)) };
}

export function dmCanonical(channelId, e) {
  return `${channelId}|${e.dh}|${e.pn}|${e.n}|${e.nonce}|${e.ct}`;
}

export async function ratchetEncrypt(state, channelId, plaintext, signingPair) {
  if (!state.cks) {
    // responder's first send: turn the DH ratchet on our own initiative.
    // The peer mirrors this on receive: their KDF_RK(RK, DH(dhs_old, our new pub))
    // reproduces exactly this chain.
    state.dhs = await generateEphemeral();
    const dhOut = await dh(state.dhs, state.dhr);
    const r = await kdfRk(state.rk, dhOut);
    state.rk = r.rk;
    state.cks = r.ck;
    state.ns = 0;
    state.established = true;
  }
  const { ck, mk } = await kdfCk(state.cks);
  state.cks = ck;
  // keep our own message keys (bounded) so local history stays readable after a refresh
  state.sent[`${state.dhs.pub}:${state.ns}`] = mk;
  const sentIds = Object.keys(state.sent);
  if (sentIds.length > 300) delete state.sent[sentIds[0]];
  const { nonce, ct } = await aeadSealAD(mk, plaintext, `${channelId}|${state.dhs.pub}|${state.ns}`);
  const envelope = { v: 1, kind: 'dm', dh: state.dhs.pub, pn: state.pn, n: state.ns, nonce, ct };
  envelope.sig = await sign(signingPair, dmCanonical(channelId, envelope));
  state.ns += 1;
  return envelope;
}

async function trySkipped(state, header, channelId, nonce, ct) {
  const key = `${header.dh}:${header.n}`;
  const mk = state.skipped[key];
  if (mk === undefined) return null;
  delete state.skipped[key];
  const pt = await aeadOpen(mk, nonce, ct, `${channelId}|${header.dh}|${header.n}`);
  state.established = true;
  return pt;
}

async function skipTo(state, until) {
  if (state.nr + MAX_SKIP <= until) throw new Error('too many skipped messages');
  while (state.nr < until) {
    const { ck, mk } = await kdfCk(state.ckr);
    state.ckr = ck;
    state.skipped[`${state.dhr}:${state.nr}`] = mk;
    state.nr += 1;
    if (Object.keys(state.skipped).length > MAX_SKIP) break;
  }
}

export async function ratchetDecrypt(state, channelId, envelope) {
  const { dh: dhPub, pn, n, nonce, ct } = envelope;
  const fromSkipped = await trySkipped(state, { dh: dhPub, n }, channelId, nonce, ct);
  if (fromSkipped !== null) return fromSkipped;

  if (dhPub !== state.dhr) { // remote turned the DH ratchet
    await skipTo(state, pn);
    const dhOut1 = await dh(state.dhs, dhPub);
    const r1 = await kdfRk(state.rk, dhOut1);
    state.rk = r1.rk; state.ckr = r1.ck;
    state.dhs = await generateEphemeral();
    const dhOut2 = await dh(state.dhs, dhPub);
    const r2 = await kdfRk(state.rk, dhOut2);
    state.rk = r2.rk; state.cks = r2.ck;
    state.dhr = dhPub;
    state.pn = state.ns; state.ns = 0; state.nr = 0;
  }
  await skipTo(state, n);
  const { ck, mk } = await kdfCk(state.ckr);
  state.ckr = ck;
  state.nr += 1;
  const pt = await aeadOpen(mk, nonce, ct, `${channelId}|${dhPub}|${n}`);
  state.established = true;
  return pt;
}

// ---- guild channel envelope encryption (MLS-lite) ---------------------------------------
export const generateChannelKey = () => ({ key_id: randomB64u(8), key: randomB64u(32) });

export async function wrapKeyFor(myIdentity, theirIdentityPubB64u, keyB64u) {
  const shared = await dh(myIdentity, theirIdentityPubB64u);
  const kek = await hkdf(shared, ZEROS, 'concord/kek', 32);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const k = await aesKey(kek);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, k, unb64u(keyB64u));
  return { iv: b64u(iv), ct: b64u(new Uint8Array(ct)) };
}
export async function unwrapKeyFor(myIdentity, wrapperIdentityPubB64u, wrap) {
  const shared = await dh(myIdentity, wrapperIdentityPubB64u);
  const kek = await hkdf(shared, ZEROS, 'concord/kek', 32);
  const k = await aesKey(kek);
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: unb64u(wrap.iv) }, k, unb64u(wrap.ct));
  return b64u(new Uint8Array(pt));
}

export function channelCanonical(channelId, keyId, e) {
  return `${channelId}|${keyId}|${e.nonce}|${e.ct}`;
}
export async function channelEncrypt(keyB64u, keyId, channelId, payloadObj, signingPair) {
  const { nonce, ct } = await aeadSeal(keyB64u, JSON.stringify(payloadObj));
  const envelope = { v: 1, kind: 'channel', key_id: keyId, nonce, ct };
  envelope.sig = await sign(signingPair, channelCanonical(channelId, keyId, envelope));
  return envelope;
}
export async function channelDecrypt(keyB64u, envelope) {
  return JSON.parse(await aeadOpen(keyB64u, envelope.nonce, envelope.ct));
}

// ---- verification helpers ------------------------------------------------------------------
export async function sha256Hex(bytes) {
  const h = await subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
export async function safetyNumber(idPubA, idPubB) {
  const pair = [idPubA, idPubB].sort().join('|');
  const hex = (await sha256Hex(te.encode(`concord/safety:${pair}`))).slice(0, 60);
  return (hex.match(/.{1,5}/g) ?? []).join(' ');
}
export const fingerprint = async (pubB64u) => (await sha256Hex(te.encode('concord/fp:' + pubB64u))).slice(0, 16);
