import assert from 'node:assert/strict';
import { test } from 'node:test';
import { publicCommitment } from './protocol.mjs';

test('only a blinded commitment reaches the public payload', () => {
  const value = { network: 'solana-devnet', status: 'not_published', commitment: 'a'.repeat(64), tenant: 'BANK_A', event_id: 'evt_private', blinding: 'private' };
  assert.deepEqual(Object.keys(publicCommitment(value)), ['schema_version', 'commitment']);
  assert.throws(() => publicCommitment({ ...value, network: 'mainnet-beta' }));
  assert.throws(() => publicCommitment({ ...value, commitment: 'invalid' }));
});