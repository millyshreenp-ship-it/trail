import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fixture from '../data/workspace-replay.json' with { type: 'json' };
import { ApiError, decisionSchema, definitiveRejection, eligibleActions } from './workspace.ts';

describe('workspace safety contracts', () => {
  it('validates measured replay and forbids invented UNKNOWN scores', () => {
    for (const item of fixture.cases) assert.equal(decisionSchema.safeParse(item.decision).success, true);
    assert.equal(decisionSchema.safeParse({ ...fixture.cases[0].decision, action: 'UNKNOWN', score: 0.9 }).success, false);
  });
  it('preserves uncertain writes for timeouts and server failures', () => {
    assert.equal(definitiveRejection(new ApiError('timeout')), false);
    assert.equal(definitiveRejection(new ApiError('server', 503)), false);
    assert.equal(definitiveRejection(new ApiError('expired', 409)), true);
  });
  it('enforces permission and expiry guards', () => {
    const decision = decisionSchema.parse(fixture.cases[1].decision);
    assert.deepEqual(eligibleActions(decision, false, false), ['DISPLAY']);
    assert.deepEqual(eligibleActions({ ...decision, expires_at: '2000-01-01T00:00:00Z' }, true, true), []);
  });
});