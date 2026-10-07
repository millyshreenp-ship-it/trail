// Browser model of integrations/hardware/src/main.cpp and backend/app/security/extensions.py.
export type Phase = 'idle' | 'rejected' | 'awaiting_hold' | 'holding' | 'signed' | 'expired';
export const HOLD_MS = 3000;
export const DEVICE_WINDOW_MS = 120_000;
export const SERVER_WINDOW_MS = 120_000;
export const ACK_SUFFIX = '\nACKNOWLEDGE_REVIEW';
const SCHEMA = 'earlytrace.device.challenge.v1';
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export interface ChallengeDetails { event_id: string; amount_bucket: string; payee_pseudonym: string; risk_band: string }
export interface Challenge { payload: Record<string, string>; message: Uint8Array; signature: Uint8Array }
export type AckResult = { ok: true; receipt: { challenge_id: string; receipt_id: string; effect: 'recorded_only'; assurance: string } } | { ok: false; reason: string };

const subtle = () => globalThis.crypto.subtle;
const ab = (bytes: Uint8Array): ArrayBuffer => bytes.slice().buffer as ArrayBuffer;
export const toB64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
export const hex = (bytes: Uint8Array) => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
const randomHex = (length: number) => hex(globalThis.crypto.getRandomValues(new Uint8Array(length)));
const canonical = (value: Record<string, string>) => encoder.encode(JSON.stringify(Object.fromEntries(Object.entries(value).sort(([a], [b]) => (a < b ? -1 : 1)))));

export async function supportsEd25519(): Promise<boolean> {
  try { await subtle().generateKey('Ed25519', false, ['sign', 'verify']); return true; } catch { return false; }
}

export class SigningKey {
  private constructor(private pair: CryptoKeyPair, readonly publicRaw: Uint8Array) {}
  static async create() {
    const pair = (await subtle().generateKey('Ed25519', true, ['sign', 'verify'])) as CryptoKeyPair;
    return new SigningKey(pair, new Uint8Array(await subtle().exportKey('raw', pair.publicKey)));
  }
  async sign(data: Uint8Array) { return new Uint8Array(await subtle().sign('Ed25519', this.pair.privateKey, ab(data))); }
}

export async function verifySignature(publicRaw: Uint8Array, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
  try {
    const key = await subtle().importKey('raw', ab(publicRaw), 'Ed25519', false, ['verify']);
    return await subtle().verify('Ed25519', key, ab(signature), ab(data));
  } catch { return false; }
}

export class SimServer {
  private issued = new Map<string, { message: Uint8Array; deviceId: string; expiresAt: number; used: boolean }>();
  private devices = new Map<string, Uint8Array>();
  private constructor(private keys: SigningKey) {}
  static async create() { return new SimServer(await SigningKey.create()); }
  get publicKey() { return this.keys.publicRaw; }
  enroll(deviceId: string, publicKey: Uint8Array) { this.devices.set(deviceId, publicKey); }

  async issue(deviceId: string, details: ChallengeDetails, now: number): Promise<Challenge> {
    if (!this.devices.has(deviceId)) throw new Error('device unavailable');
    const expiresAt = now + SERVER_WINDOW_MS;
    const payload: Record<string, string> = { schema_version: SCHEMA, challenge_id: `challenge_${randomHex(16)}`, device_id: deviceId, action: 'ACKNOWLEDGE_REVIEW', expires_at: new Date(expiresAt).toISOString(), nonce: randomHex(16), ...details };
    const message = canonical(payload);
    this.issued.set(payload.challenge_id, { message, deviceId, expiresAt, used: false });
    return { payload, message, signature: await this.keys.sign(message) };
  }

  async acknowledge(challengeId: string, signature: Uint8Array, now: number): Promise<AckResult> {
    const row = this.issued.get(challengeId);
    if (!row || row.used || now >= row.expiresAt) return { ok: false, reason: 'challenge unavailable' };
    const publicKey = this.devices.get(row.deviceId);
    if (!publicKey || !(await verifySignature(publicKey, signature, new Uint8Array([...row.message, ...encoder.encode(ACK_SUFFIX)])))) return { ok: false, reason: 'invalid acknowledgement' };
    row.used = true;
    return { ok: true, receipt: { challenge_id: challengeId, receipt_id: `SIM-${randomHex(6).toUpperCase()}`, effect: 'recorded_only', assurance: 'device_signature_not_proof_of_uncoerced_intent' } };
  }
}

export class SimDevice {
  phase: Phase = 'idle';
  reason = '';
  acknowledgement: { challenge_id: string; signature: Uint8Array } | null = null;
  details = { amount_bucket: '', payee: '' };
  private pending: { id: string; message: Uint8Array } | null = null;
  private released = false;
  private holdStarted: number | null = null;
  private receivedAt = 0;
  private signing = false;
  private constructor(readonly deviceId: string, private keys: SigningKey, readonly pinned: Uint8Array | null) {}
  static async create(pinned: Uint8Array | null) {
    const keys = await SigningKey.create();
    return new SimDevice(`device_${hex(keys.publicRaw.slice(0, 16))}`, keys, pinned);
  }
  get publicKey() { return this.keys.publicRaw; }

  private reject(reason: string) { this.pending = null; this.phase = 'rejected'; this.reason = reason; }

  async receive(packet: Pick<Challenge, 'message' | 'signature'>, now: number) {
    this.acknowledgement = null;
    this.pending = null;
    this.holdStarted = null;
    this.reason = '';
    if (!this.pinned) return this.reject('Pinned key required');
    if (packet.message.length > 1023) return this.reject('Invalid packet');
    if (!(await verifySignature(this.pinned, packet.signature, packet.message))) return this.reject('Signature rejected');
    let payload: Record<string, string>;
    try { payload = JSON.parse(decoder.decode(packet.message)); } catch { return this.reject('Invalid packet'); }
    if (payload.schema_version !== SCHEMA || payload.device_id !== this.deviceId || payload.action !== 'ACKNOWLEDGE_REVIEW') return this.reject('Binding rejected');
    const id = payload.challenge_id ?? '';
    if (id.length < 20 || id.length > 80) return this.reject('Challenge rejected');
    this.pending = { id, message: packet.message };
    this.details = { amount_bucket: payload.amount_bucket ?? 'bucketed', payee: payload.payee_pseudonym ?? '' };
    this.phase = 'awaiting_hold';
    this.released = false;
    this.receivedAt = now;
  }

  holdProgress(now: number) { return this.holdStarted === null ? 0 : Math.min(1, (now - this.holdStarted) / HOLD_MS); }

  // The button must be seen released once before a hold counts, as in loop() on the board.
  async tick(now: number, pressed: boolean): Promise<Phase> {
    if (!this.pending || this.signing) return this.phase;
    if (now - this.receivedAt > DEVICE_WINDOW_MS) { this.pending = null; this.holdStarted = null; this.phase = 'expired'; return this.phase; }
    if (!pressed) { this.released = true; this.holdStarted = null; this.phase = 'awaiting_hold'; return this.phase; }
    if (!this.released) return this.phase;
    this.holdStarted ??= now;
    this.phase = 'holding';
    if (now - this.holdStarted < HOLD_MS) return this.phase;
    this.signing = true;
    const { id, message } = this.pending;
    const signature = await this.keys.sign(new Uint8Array([...message, ...encoder.encode(ACK_SUFFIX)]));
    this.acknowledgement = { challenge_id: id, signature };
    this.pending = null;
    this.signing = false;
    this.phase = 'signed';
    return this.phase;
  }
}
