import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { HOLD_MS, DEVICE_WINDOW_MS, SERVER_WINDOW_MS, SigningKey, SimDevice, SimServer, supportsEd25519 } from './protocol.ts';

const details = { event_id: 'evt_sim_000001', amount_bucket: '50k_100k', payee_pseudonym: 'case_0123456789abcdef', risk_band: 'ELEVATED' };

async function setup(pinned = true) {
  const server = await SimServer.create();
  const device = await SimDevice.create(pinned ? server.publicKey : null);
  server.enroll(device.deviceId, device.publicKey);
  return { server, device };
}

async function holdToCompletion(device: SimDevice, start: number) {
  await device.tick(start, false);
  await device.tick(start + 10, true);
  return device.tick(start + 10 + HOLD_MS, true);
}

describe('simulated EarlyTrace Key protocol', async () => {
  assert.equal(await supportsEd25519(), true);

  it('records a one-time acknowledgement only after a physical hold', async () => {
    const { server, device } = await setup();
    const now = 1_000_000;
    const challenge = await server.issue(device.deviceId, details, now);
    await device.receive(challenge, now);
    assert.equal(device.phase, 'awaiting_hold');
    assert.equal(await holdToCompletion(device, now + 100), 'signed');
    const result = await server.acknowledge(device.acknowledgement!.challenge_id, device.acknowledgement!.signature, now + 4000);
    assert.equal(result.ok && result.receipt.effect, 'recorded_only');
    const replay = await server.acknowledge(device.acknowledgement!.challenge_id, device.acknowledgement!.signature, now + 5000);
    assert.deepEqual(replay, { ok: false, reason: 'challenge unavailable' });
  });

  it('restarts the hold when the button is released early', async () => {
    const { server, device } = await setup();
    const challenge = await server.issue(device.deviceId, details, 0);
    await device.receive(challenge, 0);
    await device.tick(10, false);
    await device.tick(20, true);
    assert.ok(device.holdProgress(1500) > 0.4);
    await device.tick(1500, false);
    assert.equal(device.holdProgress(1600), 0);
    assert.notEqual(await device.tick(20 + HOLD_MS, true), 'signed');
  });

  it('ignores a button that was already held when the challenge arrived', async () => {
    const { server, device } = await setup();
    const challenge = await server.issue(device.deviceId, details, 0);
    await device.receive(challenge, 0);
    assert.equal(await device.tick(10, true), 'awaiting_hold');
    assert.equal(await device.tick(10 + HOLD_MS + 50, true), 'awaiting_hold');
    assert.equal(device.acknowledgement, null);
  });

  it('rejects tampered content, forged servers, unpinned keys and foreign device IDs', async () => {
    const { server, device } = await setup();
    const challenge = await server.issue(device.deviceId, details, 0);
    const text = new TextDecoder().decode(challenge.message).replace('50k_100k', '500k_plus');
    await device.receive({ message: new TextEncoder().encode(text), signature: challenge.signature }, 0);
    assert.equal(device.reason, 'Signature rejected');

    const rogue = await SimServer.create();
    rogue.enroll(device.deviceId, device.publicKey);
    await device.receive(await rogue.issue(device.deviceId, details, 0), 0);
    assert.equal(device.reason, 'Signature rejected');

    const other = await SimDevice.create(server.publicKey);
    server.enroll(other.deviceId, other.publicKey);
    await device.receive(await server.issue(other.deviceId, details, 0), 0);
    assert.equal(device.reason, 'Binding rejected');

    const unpinned = await setup(false);
    await unpinned.device.receive(await unpinned.server.issue(unpinned.device.deviceId, details, 0), 0);
    assert.equal(unpinned.device.reason, 'Pinned key required');
  });

  it('rejects a forged acknowledgement from remote software', async () => {
    const { server, device } = await setup();
    const challenge = await server.issue(device.deviceId, details, 0);
    const attacker = await SigningKey.create();
    const forged = await attacker.sign(new Uint8Array([...challenge.message, ...new TextEncoder().encode('\nACKNOWLEDGE_REVIEW')]));
    assert.deepEqual(await server.acknowledge(challenge.payload.challenge_id, forged, 10), { ok: false, reason: 'invalid acknowledgement' });
  });

  it('expires on both the device and the server', async () => {
    const { server, device } = await setup();
    const challenge = await server.issue(device.deviceId, details, 0);
    await device.receive(challenge, 0);
    assert.equal(await device.tick(DEVICE_WINDOW_MS + 1, false), 'expired');
    const late = await server.acknowledge(challenge.payload.challenge_id, new Uint8Array(64), SERVER_WINDOW_MS + 1);
    assert.deepEqual(late, { ok: false, reason: 'challenge unavailable' });
  });
});
