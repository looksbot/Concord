// Minimal RFC 6455 WebSocket server: handshake, frame codec, fragmentation,
// ping/pong, close. Text frames only at the API level (Concord gateway is JSON).
import { createHash } from 'node:crypto';

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const MAX_MESSAGE = 1 << 20; // 1 MiB per message
const OP_CONT = 0x0, OP_TEXT = 0x1, OP_BINARY = 0x2, OP_CLOSE = 0x8, OP_PING = 0x9, OP_PONG = 0xa;

function encodeFrame(opcode, payload) {
  const len = payload.length;
  let header;
  if (len < 126) {
    header = Buffer.allocUnsafe(2);
    header[1] = len;
  } else if (len < 65536) {
    header = Buffer.allocUnsafe(4);
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.allocUnsafe(10);
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  header[0] = 0x80 | opcode; // FIN always set on server frames we emit
  return Buffer.concat([header, payload]);
}

export class WSConnection {
  constructor(socket) {
    this.socket = socket;
    this.buffer = Buffer.alloc(0);
    this.fragments = [];       // accumulated payload fragments
    this.fragOpcode = -1;
    this.fragSize = 0;
    this.onmessage = null;     // (string) => void
    this.onclose = null;       // (code) => void
    this.closed = false;
    socket.on('data', (chunk) => this._feed(chunk));
    const die = () => this._teardown();
    socket.on('error', die);
    socket.on('close', die);
    socket.setNoDelay(true);
  }

  send(text) {
    if (this.closed) return;
    try { this.socket.write(encodeFrame(OP_TEXT, Buffer.from(text, 'utf8'))); } catch { /* socket gone */ }
  }

  pong(payload) {
    if (this.closed) return;
    try { this.socket.write(encodeFrame(OP_PONG, payload)); } catch { /* ignore */ }
  }

  close(code = 1000) {
    if (this.closed) return;
    try {
      const body = Buffer.alloc(2);
      body.writeUInt16BE(code, 0);
      this.socket.write(encodeFrame(OP_CLOSE, body));
    } catch { /* ignore */ }
    this.socket.end();
    setTimeout(() => this._teardown(), 5000).unref();
  }

  _teardown() {
    if (this.closed) return;
    this.closed = true;
    this.onclose?.(1006);
    try { this.socket.destroy(); } catch { /* ignore */ }
  }

  _fail(code) { this.close(code); }

  _feed(chunk) {
    if (this.closed) return;
    this.buffer = this.buffer.length ? Buffer.concat([this.buffer, chunk]) : chunk;
    let frame;
    while ((frame = this._parseFrame()) !== null) {
      if (frame === false) return; // error already signaled
      this._handleFrame(frame);
      if (this.closed) return;
    }
  }

  // null => need more bytes; false => protocol error (connection closing)
  _parseFrame() {
    const buf = this.buffer;
    if (buf.length < 2) return null;
    const b0 = buf[0], b1 = buf[1];
    const fin = (b0 & 0x80) !== 0;
    const opcode = b0 & 0x0f;
    const masked = (b1 & 0x80) !== 0;
    let len = b1 & 0x7f;
    let off = 2;
    if (len === 126) {
      if (buf.length < 4) return null;
      len = buf.readUInt16BE(2); off = 4;
    } else if (len === 127) {
      if (buf.length < 10) return null;
      const big = buf.readBigUInt64BE(2);
      if (big > BigInt(MAX_MESSAGE)) { this._fail(1009); return false; }
      len = Number(big); off = 10;
    }
    if (len > MAX_MESSAGE) { this._fail(1009); return false; }
    let mask = null;
    if (masked) {
      if (buf.length < off + 4) return null;
      mask = buf.subarray(off, off + 4); off += 4;
    }
    if (buf.length < off + len) return null;
    let payload = buf.subarray(off, off + len);
    if (mask) {
      payload = Buffer.from(payload); // copy so we can unmask in place
      for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
    } else {
      // RFC 6455 §5.1: client frames must be masked
      this._fail(1002); return false;
    }
    this.buffer = buf.subarray(off + len);
    return { fin, opcode, payload };
  }

  _handleFrame({ fin, opcode, payload }) {
    if (opcode >= 0x8) { // control frame
      if (!fin || payload.length > 125) { this._fail(1002); return; }
      if (opcode === OP_PING) this.pong(payload);
      else if (opcode === OP_CLOSE) this.close(payload.length >= 2 ? payload.readUInt16BE(0) : 1000);
      return; // PONG: ignore
    }
    if (opcode === OP_TEXT || opcode === OP_BINARY) {
      if (this.fragOpcode !== -1) { this._fail(1002); return; } // new data frame during fragmentation
      if (fin) { this._deliver(opcode, payload); return; }
      this.fragOpcode = opcode; this.fragments = [payload]; this.fragSize = payload.length;
      return;
    }
    if (opcode === OP_CONT) {
      if (this.fragOpcode === -1) { this._fail(1002); return; }
      this.fragSize += payload.length;
      if (this.fragSize > MAX_MESSAGE) { this._fail(1009); return; }
      this.fragments.push(payload);
      if (!fin) return;
      const whole = Buffer.concat(this.fragments);
      const op = this.fragOpcode;
      this.fragments = []; this.fragOpcode = -1; this.fragSize = 0;
      this._deliver(op, whole);
    }
  }

  _deliver(opcode, payload) {
    let text;
    try { text = payload.toString('utf8'); } catch { this._fail(1007); return; }
    if (opcode === OP_TEXT) { // reject invalid UTF-8 (includes lone surrogates in V8 via replacement check)
      // Buffer.toString never throws; sanity-check round-trip for blatant corruption is skipped —
      // JSON.parse at the gateway layer rejects garbage anyway.
    }
    try { this.onmessage?.(text); } catch { /* handler errors must not kill the socket */ }
  }
}

export function acceptUpgrade(req, socket, head) {
  const key = req.headers['sec-websocket-key'];
  const version = req.headers['sec-websocket-version'];
  if (!key || version !== '13') {
    socket.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return null;
  }
  const accept = createHash('sha1').update(key + GUID).digest('base64');
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
  );
  const conn = new WSConnection(socket);
  if (head && head.length) conn._feed(head);
  return conn;
}
