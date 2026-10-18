// Discord-style snowflake IDs: (ts - epoch) << 22 | worker << 17 | seq.
// BigInt internally, decimal string on the wire.
const EPOCH = 1767225600000n; // 2026-01-01T00:00:00Z
const WORKER = BigInt(process.pid % 32);
let last = 0n;
let seq = 0n;

export function snowflake() {
  let now = BigInt(Date.now());
  if (now < last) now = last;
  if (now === last) {
    seq = (seq + 1n) & 4095n;
    if (seq === 0n) while (BigInt(Date.now()) === now) { /* spin to next ms */ }
  } else {
    seq = 0n;
  }
  last = now;
  return (((now - EPOCH) << 22n) | (WORKER << 17n) | seq).toString();
}

export function idCompare(a, b) {
  const x = BigInt(a), y = BigInt(b);
  return x < y ? -1 : x > y ? 1 : 0;
}
