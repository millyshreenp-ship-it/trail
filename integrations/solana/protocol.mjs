export function publicCommitment(value) {
  if (value?.network !== 'solana-devnet' || value?.status !== 'not_published' || !/^[a-f0-9]{64}$/.test(value?.commitment ?? '')) throw new Error('An unpublished Devnet commitment is required');
  return { schema_version: 'earlytrace.commitment.v1', commitment: value.commitment };
}