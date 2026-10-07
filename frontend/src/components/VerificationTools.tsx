import { useState } from 'react';
import { ArrowDownToLine, Fingerprint, GitBranch, ShieldCheck } from 'lucide-react';
import { z } from 'zod';
import { WorkspaceClient } from '../api/workspace';

const checkpointSchema = z.object({ checkpoint_id: z.string(), commitment: z.string().regex(/^[a-f0-9]{64}$/), network: z.literal('solana-devnet'), status: z.literal('not_published'), entries: z.number(), claim: z.string() }).passthrough();
const challengeSchema = z.object({ message_b64: z.string(), server_signature_b64: z.string(), server_public_key_b64: z.string(), effect: z.literal('recorded_only'), pinning_required: z.literal(true), payload: z.object({ challenge_id: z.string(), expires_at: z.string() }).passthrough() }).passthrough();

export default function VerificationTools({ client, eventId, enabled }: { client: WorkspaceClient | null; eventId?: string; enabled: boolean }) {
  const [checkpoint, setCheckpoint] = useState<z.infer<typeof checkpointSchema> | null>(null);
  const [challenge, setChallenge] = useState<z.infer<typeof challengeSchema> | null>(null);
  const [device, setDevice] = useState('');
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState('');
  function download(value: unknown, name: string) {
    const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a'); link.href = url; link.download = name; link.click(); URL.revokeObjectURL(url);
  }
  async function createCheckpoint() {
    if (!client) return;
    setBusy(true);
    try { const value = await client.request('/api/workspace/checkpoints', checkpointSchema, { method: 'POST' }); setCheckpoint(value); setStatus('Private checkpoint created. Not published on a blockchain.'); }
    catch (error) { setStatus(`Checkpoint unavailable: ${String(error)}`); }
    finally { setBusy(false); }
  }
  async function verify() {
    if (!client || !checkpoint) return;
    setBusy(true);
    try { const result = await client.request(`/api/workspace/checkpoints/${checkpoint.checkpoint_id}/verify`, z.object({ intact: z.boolean(), commitment: z.string() })); setStatus(result.intact ? 'Stored checkpoint matches the private audit evidence.' : 'Evidence no longer matches this checkpoint.'); }
    catch (error) { setStatus(`Verification unavailable: ${String(error)}`); }
    finally { setBusy(false); }
  }
  async function createChallenge() {
    if (!client || !eventId || !/^device_[a-z0-9_-]{8,64}$/.test(device)) { setStatus('Enter a registered device identifier.'); return; }
    setBusy(true);
    try { const value = await client.request(`/api/workspace/decisions/${eventId}/device-challenge`, challengeSchema, { method: 'POST', body: JSON.stringify({ device_id: device }) }); setChallenge(value); setStatus('Signed device challenge created. Device acknowledgement is not yet received.'); }
    catch (error) { setStatus(`Device challenge unavailable: ${String(error)}`); }
    finally { setBusy(false); }
  }
  return <section className="verification-tools"><div className="protocol-grid"><section><h3><GitBranch size={17}/>Private audit checkpoint</h3><div className="tool-actions"><button disabled={!enabled || busy} onClick={createCheckpoint}>Create checkpoint</button><button disabled={!checkpoint || busy} onClick={verify}><ShieldCheck size={15}/>Verify</button><button title="Download Devnet commitment" className="icon-button" disabled={!checkpoint} onClick={() => download(checkpoint, 'earlytrace-devnet-checkpoint.json')}><ArrowDownToLine size={17}/></button></div>{checkpoint && <div className="checkpoint-details"><code>{checkpoint.commitment}</code><small>{checkpoint.entries} entries · blinded commitment · not published</small></div>}</section><section><h3><Fingerprint size={17}/>Physical acknowledgement</h3><label className="device-input">Registered device<input aria-label="Registered device identifier" value={device} onChange={event => setDevice(event.target.value)} placeholder="device_..."/></label><div className="tool-actions"><button disabled={!enabled || !eventId || busy} onClick={createChallenge}>Create challenge</button><button className="icon-button" title="Download signed device challenge" disabled={!challenge} onClick={() => download(challenge, 'earlytrace-device-challenge.json')}><ArrowDownToLine size={17}/></button></div>{challenge && <small>Expires {new Date(challenge.payload.expires_at).toLocaleTimeString()} · recorded-only</small>}</section></div>{status && <p role="status" className="subtle">{status}</p>}</section>;
}