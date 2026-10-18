// Concord crypto unit tests: X3DH-lite handshake, double ratchet, AEAD tamper
// detection, signatures, channel-key wrapping, safety numbers.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as C from '../public/concord-crypto.js';

const J = (o) => JSON.stringify(o);

test('x3dh + double ratchet: alice -> bob, bob -> alice, many turns', async () => {
  const alice = await C.generateIdentityKeys();
  const bob = await C.generateIdentityKeys();
  const bobBundle = await C.buildBundle(bob, 5);

  const bundle = { ...bobBundle.upload, opk: bobBundle.upload.opks[0] };
  const { state: A, header } = await C.x3dhInitiator(alice, bundle);
  const CID = '9999';

  // 1) alice sends before bob ever replies; header rides on the envelope
  const e1 = await C.ratchetEncrypt(A, CID, J({ text: 'hello bob' }), alice.signing);
  e1.hdr = header;
  assert.equal((await C.verify(alice.signing.pub, e1.sig, C.dmCanonical(CID, e1))), true, 'envelope signed');

  const { state: B } = await C.x3dhResponder(bob, bobBundle.local, e1.hdr);
  assert.equal(await C.ratchetDecrypt(B, CID, e1), J({ text: 'hello bob' }));

  // 2) more sends on the same chain
  const e2 = await C.ratchetEncrypt(A, CID, J({ text: 'second' }), alice.signing);
  e2.hdr = header;
  assert.equal(await C.ratchetDecrypt(B, CID, e2), J({ text: 'second' }));

  // 3) bob replies — DH ratchet turns on both sides
  const b1 = await C.ratchetEncrypt(B, CID, J({ text: 'hi alice' }), bob.signing);
  assert.equal(await C.ratchetDecrypt(A, CID, b1), J({ text: 'hi alice' }));

  const a3 = await C.ratchetEncrypt(A, CID, J({ text: 'ratchet works' }), alice.signing);
  assert.equal(await C.ratchetDecrypt(B, CID, a3), J({ text: 'ratchet works' }));

  const b2 = await C.ratchetEncrypt(B, CID, J({ text: 'yes it does' }), bob.signing);
  assert.equal(await C.ratchetDecrypt(A, CID, b2), J({ text: 'yes it does' }));

  // 4) own history: alice can re-open her own old messages from stored send keys
  const mk = A.sent[`${a3.dh}:${a3.n}`];
  assert.ok(mk, 'send-chain message key kept');
  assert.equal(await C.aeadOpen(mk, a3.nonce, a3.ct, `${CID}|${a3.dh}|${a3.n}`), J({ text: 'ratchet works' }));
});

test('out-of-order delivery via skipped message keys', async () => {
  const alice = await C.generateIdentityKeys();
  const bob = await C.generateIdentityKeys();
  const bb = await C.buildBundle(bob, 3);
  const { state: A, header } = await C.x3dhInitiator(alice, { ...bb.upload, opk: bb.upload.opks[0] });
  const CID = '42';
  const envs = [];
  for (const t of ['m1', 'm2', 'm3']) {
    const e = await C.ratchetEncrypt(A, CID, J({ text: t }), alice.signing);
    e.hdr = header;
    envs.push(e);
  }
  const { state: B } = await C.x3dhResponder(bob, bb.local, header);
  // deliver 3rd first (bootstrap on it), then 1st and 2nd from the skipped cache
  assert.equal(await C.ratchetDecrypt(B, CID, envs[2]), J({ text: 'm3' }));
  assert.equal(await C.ratchetDecrypt(B, CID, envs[0]), J({ text: 'm1' }));
  assert.equal(await C.ratchetDecrypt(B, CID, envs[1]), J({ text: 'm2' }));
});

test('tampered ciphertext / wrong AD fails', async () => {
  const alice = await C.generateIdentityKeys();
  const bob = await C.generateIdentityKeys();
  const bb = await C.buildBundle(bob, 3);
  const { state: A, header } = await C.x3dhInitiator(alice, { ...bb.upload, opk: bb.upload.opks[0] });
  const e = await C.ratchetEncrypt(A, '7', J({ text: 'secret' }), alice.signing);
  e.hdr = header;
  // flip a byte inside the ciphertext tail
  const bytes = C.unb64u(e.ct); bytes[bytes.length - 2] ^= 1;
  const tampered = { ...e, ct: C.b64u(bytes) };
  const { state: B } = await C.x3dhResponder(bob, bb.local, header);
  await assert.rejects(() => C.ratchetDecrypt(B, '7', tampered));
});

test('envelope signatures detect forgery', async () => {
  const alice = await C.generateIdentityKeys();
  const mallory = await C.generateIdentityKeys();
  const e = { dh: 'AAAA', pn: 0, n: 0, nonce: 'BB', ct: 'CC' };
  const sig = await C.sign(alice.signing, C.dmCanonical('5', e));
  assert.equal(await C.verify(alice.signing.pub, sig, C.dmCanonical('5', e)), true);
  assert.equal(await C.verify(mallory.signing.pub, sig, C.dmCanonical('5', e)), false, 'wrong key fails');
  const e2 = { ...e, n: 1 };
  assert.equal(await C.verify(alice.signing.pub, sig, C.dmCanonical('5', e2)), false, 'altered content fails');
});

test('guild channel: key wrap/unwrap only for intended member', async () => {
  const alice = await C.generateIdentityKeys();
  const bob = await C.generateIdentityKeys();
  const eve = await C.generateIdentityKeys();
  const { key_id, key } = C.generateChannelKey();

  const wrap = await C.wrapKeyFor(alice.identity, bob.identity.pub, key);
  const got = await C.unwrapKeyFor(bob.identity, alice.identity.pub, wrap);
  assert.equal(got, key, 'bob recovers the channel key');
  await assert.rejects(() => C.unwrapKeyFor(eve.identity, alice.identity.pub, wrap), undefined, 'eve cannot');

  const CID = '31';
  const env = await C.channelEncrypt(key, key_id, CID, { text: 'guild secret' }, alice.signing);
  assert.equal(await C.verify(alice.signing.pub, env.sig, C.channelCanonical(CID, key_id, env)), true);
  assert.deepEqual(await C.channelDecrypt(key, env), { text: 'guild secret' });
  await assert.rejects(() => C.channelDecrypt(C.generateChannelKey().key, env));
});

test('safety number is symmetric and stable', async () => {
  const a = await C.generateIdentityKeys();
  const b = await C.generateIdentityKeys();
  const s1 = await C.safetyNumber(a.identity.pub, b.identity.pub);
  const s2 = await C.safetyNumber(b.identity.pub, a.identity.pub);
  assert.equal(s1, s2);
  assert.match(s1, /^[0-9a-f]{5}( [0-9a-f]{5})*$/);
});

test('bundle signatures reject a tampered SPK', async () => {
  const alice = await C.generateIdentityKeys();
  const bob = await C.generateIdentityKeys();
  const bb = await C.buildBundle(bob, 2);
  const tampered = { ...bb.upload, spk: { pub: bb.upload.spk.pub.slice(0, -4) + 'AAAA', sig: bb.upload.spk.sig } };
  await assert.rejects(() => C.x3dhInitiator(alice, { ...tampered, opk: tampered.opks[0] }), /signature/i);
});
