import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ArrowRight, Cpu, Eye, Fingerprint, Network, RotateCcw, ShieldAlert, ShieldCheck, Smartphone } from 'lucide-react';
import type { WorkspaceCase } from '../api/workspace';
import { HOLD_MS, SigningKey, SimDevice, SimServer, supportsEd25519, toB64, type Challenge, type Phase } from '../hardware/protocol';
import type { DeviceVisual, Led } from './HardwareScene';
import '../hardware.css';

const HardwareScene = lazy(() => import('./HardwareScene'));
const STEPS = [
  ['decision', 'Advisory recommendation', 'Engine returns verify or review; nothing is blocked.'],
  ['sign', 'Server signs a challenge', 'Ed25519, bound to one device and event, valid for 2 minutes.'],
  ['relay', 'Bridge relays over USB or BLE', 'The phone UI is not in the path and cannot edit the message.'],
  ['verify', 'Key verifies its pinned server', 'Signature, device ID and action are checked on the key.'],
  ['hold', 'Human holds the button for 3 s', 'Release first, then hold. Early release restarts the timer.'],
  ['device-sign', 'Key signs the acknowledgement', 'The private key never leaves the device.'],
  ['record', 'Server verifies once and records', 'One-time, expiring, recorded-only receipt. No payment effect.'],
] as const;
type StepId = (typeof STEPS)[number][0];
type StepState = 'idle' | 'done' | 'failed';
type Scenario = 'valid' | 'tampered' | 'forged_server' | 'wrong_device';
const ELIGIBLE = ['WARN_AND_VERIFY', 'STEP_UP', 'ANALYST_REVIEW'];
const blankSteps = (): Record<StepId, StepState> => ({ decision: 'idle', sign: 'idle', relay: 'idle', verify: 'idle', hold: 'idle', 'device-sign': 'idle', record: 'idle' });

interface Sim { server: SimServer; rogue: SimServer; attacker: SigningKey; device: SimDevice }

function visualFor(device: SimDevice | null, pinned: boolean, progress: number): DeviceVisual {
  if (!device) return { lines: ['EARLYTRACE KEY', 'Starting...'], progress: 0, led: 'blue' };
  const phase: Phase = device.phase;
  if (phase === 'rejected') return { lines: [device.reason, '', 'Challenge discarded'], progress: 0, led: 'red' };
  if (phase === 'expired') return { lines: ['Challenge expired'], progress: 0, led: 'red' };
  if (phase === 'signed') return { lines: ['Review acknowledged', 'Not a payment release'], progress: 0, led: 'green' };
  if (phase === 'awaiting_hold' || phase === 'holding') return { lines: ['EARLYTRACE / VERIFY', device.details.amount_bucket, device.details.payee.slice(5, 17), 'Release, then hold 3s'], progress, led: 'amber' };
  return { lines: ['EARLYTRACE KEY', pinned ? 'Await signed review' : 'Server key not pinned', 'Prototype / advisory'], progress: 0, led: 'blue' };
}

export default function HardwareLab({ cases, selectedId }: { cases: WorkspaceCase[]; selectedId: string }) {
  const subject = useMemo(() => {
    const eligible = cases.filter(item => ELIGIBLE.includes(item.decision.action));
    return eligible.find(item => item.id === selectedId) ?? eligible[0] ?? null;
  }, [cases, selectedId]);
  const [supported, setSupported] = useState<boolean | null>(null);
  const [webgl, setWebgl] = useState(true);
  const [pinned, setPinned] = useState(true);
  const [internals, setInternals] = useState(false);
  const [resetSignal, setResetSignal] = useState(0);
  const [steps, setSteps] = useState(blankSteps);
  const [transit, setTransit] = useState(false);
  const [pressed, setPressed] = useState(false);
  const [progress, setProgress] = useState(0);
  const [, rerender] = useState(0);
  const [log, setLog] = useState<{ id: number; text: string; bad: boolean }[]>([]);
  const [packet, setPacket] = useState<{ message_b64: string; server_signature_b64: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const sim = useRef<Sim | null>(null);
  const clockOffset = useRef(0);
  const pressedRef = useRef(false);
  const current = useRef<{ challenge: Challenge; acked: boolean } | null>(null);
  const counter = useRef(0);
  const now = () => Date.now() + clockOffset.current;

  const note = useCallback((text: string, bad = false) => setLog(previous => [{ id: ++counter.current, text, bad }, ...previous].slice(0, 9)), []);
  const mark = useCallback((id: StepId, state: StepState) => setSteps(previous => ({ ...previous, [id]: state })), []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!(await supportsEd25519())) { setSupported(false); return; }
      const existing = sim.current;
      const server = existing?.server ?? await SimServer.create();
      const rogue = existing?.rogue ?? await SimServer.create();
      const attacker = existing?.attacker ?? await SigningKey.create();
      const device = await SimDevice.create(pinned ? server.publicKey : null);
      server.enroll(device.deviceId, device.publicKey);
      rogue.enroll(device.deviceId, device.publicKey);
      if (cancelled) return;
      sim.current = { server, rogue, attacker, device };
      current.current = null;
      setSteps(blankSteps());
      setProgress(0);
      setSupported(true);
      note(pinned ? 'Key provisioned with the server public key pinned.' : 'Key provisioned WITHOUT a pinned server key.');
    })();
    return () => { cancelled = true; };
  }, [pinned, note]);

  const finishSigned = useCallback(async () => {
    const active = sim.current;
    const record = current.current;
    const ack = active?.device.acknowledgement;
    if (!active || !record || !ack || record.acked) return;
    record.acked = true;
    mark('hold', 'done');
    mark('device-sign', 'done');
    note('[key] Signed challenge + ACKNOWLEDGE_REVIEW.');
    const result = await active.server.acknowledge(ack.challenge_id, ack.signature, now());
    if (result.ok) { mark('record', 'done'); note(`[server] Verified once. Receipt ${result.receipt.receipt_id} · recorded_only. Simulated, not a PAUD entry.`); }
    else { mark('record', 'failed'); note(`[server] Rejected: ${result.reason}.`, true); }
  }, [mark, note]);

  useEffect(() => {
    const timer = window.setInterval(async () => {
      const active = sim.current;
      if (!active || !['awaiting_hold', 'holding'].includes(active.device.phase)) return;
      const before = active.device.phase;
      const phase = await active.device.tick(now(), pressedRef.current);
      setProgress(active.device.holdProgress(now()));
      if (phase === 'signed') { setProgress(0); void finishSigned(); }
      if (phase === 'expired') { mark('hold', 'failed'); note('[key] Challenge expired on the device.', true); }
      if (phase !== before) rerender(value => value + 1);
    }, 50);
    return () => window.clearInterval(timer);
  }, [finishSigned, mark, note]);

  const setButton = useCallback((down: boolean) => { pressedRef.current = down; setPressed(down); }, []);

  async function send(kind: Scenario) {
    const active = sim.current;
    if (!active || !subject || busy) return;
    setBusy(true);
    setSteps(blankSteps());
    setProgress(0);
    const details = { event_id: subject.decision.event_id, amount_bucket: subject.amount_bucket, payee_pseudonym: subject.nodes.find(node => node.subject)?.id ?? 'case_pending', risk_band: subject.decision.risk_band };
    try {
      mark('decision', 'done');
      let deviceId = active.device.deviceId;
      if (kind === 'wrong_device') { deviceId = `device_${'0'.repeat(32)}`; active.server.enroll(deviceId, active.device.publicKey); }
      const issuer = kind === 'forged_server' ? active.rogue : active.server;
      let challenge = await issuer.issue(deviceId, details, now());
      current.current = { challenge, acked: false };
      if (kind === 'tampered') {
        const altered = new TextEncoder().encode(new TextDecoder().decode(challenge.message).replace(details.amount_bucket, '500k_plus'));
        challenge = { ...challenge, message: altered };
        note('[attacker] Changed the amount in transit.', true);
      }
      if (kind === 'forged_server') note('[attacker] A different server signed this challenge.', true);
      if (kind === 'wrong_device') note('[attacker] Challenge was issued for a different key.', true);
      mark('sign', 'done');
      setPacket({ message_b64: toB64(challenge.message), server_signature_b64: toB64(challenge.signature) });
      note(`[server] Signed ${challenge.payload.challenge_id.slice(0, 20)}…`);
      setTransit(true);
      await new Promise(resolve => window.setTimeout(resolve, 900));
      setTransit(false);
      mark('relay', 'done');
      await active.device.receive(challenge, now());
      if (active.device.phase === 'awaiting_hold') { mark('verify', 'done'); note('[key] Signature, pin and device binding verified. Waiting for a physical hold.'); }
      else { mark('verify', 'failed'); note(`[key] ${active.device.reason}. Nothing can be approved.`, true); }
      rerender(value => value + 1);
    } finally { setBusy(false); }
  }

  async function forgeAcknowledgement() {
    const active = sim.current;
    const record = current.current;
    if (!active || !record) { note('Send a challenge first.', true); return; }
    const forged = await active.attacker.sign(new Uint8Array([...record.challenge.message, ...new TextEncoder().encode('\nACKNOWLEDGE_REVIEW')]));
    const result = await active.server.acknowledge(record.challenge.payload.challenge_id, forged, now());
    note(result.ok ? '[server] Accepted a forged signature (unexpected).' : `[attacker] Remote software signed with its own key → server: ${result.reason}.`, !result.ok);
  }

  async function replay() {
    const active = sim.current;
    const ack = active?.device.acknowledgement;
    if (!active || !ack) { note('Complete a physical hold first.', true); return; }
    const result = await active.server.acknowledge(ack.challenge_id, ack.signature, now());
    note(result.ok ? '[server] Replay accepted (unexpected).' : `[attacker] Replayed the signed acknowledgement → server: ${result.reason}.`, !result.ok);
  }

  function expire() {
    clockOffset.current += 121_000;
    note('Simulated clock advanced 2 minutes 1 second.');
  }

  const visual = visualFor(sim.current?.device ?? null, pinned, progress);
  const phoneLines = subject ? ['Pay new payee?', `Amount ${subject.amount_bucket.replaceAll('_', ' – ')}`, 'Tap to approve'] : ['No eligible event'];
  const phase = sim.current?.device.phase ?? 'idle';
  const holdLabel = phase === 'holding' ? `Holding… ${Math.round(progress * 100)}%` : `Hold to confirm (${HOLD_MS / 1000} s)`;

  if (supported === false) return <section className="hardware-lab"><div className="hardware-empty"><ShieldAlert size={26}/><strong>Ed25519 is unavailable in this browser.</strong><span>Use a current Chrome, Edge, Firefox or Safari to run the signed-challenge simulation.</span></div></section>;

  return <section className="hardware-lab">
    <div className="hardware-stage">
      <div className="hardware-flags"><span className="badge unknown"><Cpu size={12}/>SIMULATED DEVICE</span><span>No hardware connected · firmware builds, not yet flashed</span></div>
      {webgl ? <Suspense fallback={<div className="hardware-empty"><span>Loading 3D scene…</span></div>}><HardwareScene visual={visual} phoneLines={phoneLines} internals={internals} transit={transit} pressed={pressed} resetSignal={resetSignal} onButton={setButton} onUnavailable={() => setWebgl(false)}/></Suspense> : <div className="hardware-empty"><Cpu size={26}/><strong>3D view unavailable (WebGL is off).</strong><span>The protocol simulation below still runs.</span></div>}
      <div className="hardware-toolbar"><button aria-pressed={internals} onClick={() => setInternals(value => !value)}><Eye size={15}/>Internals</button><button onClick={() => setResetSignal(value => value + 1)}><RotateCcw size={15}/>Reset view</button><span>Drag to rotate · press the physical button on the device</span></div>
    </div>
    <div className="hardware-side">
      <h3><Fingerprint size={17}/>Physical acknowledgement</h3>
      <p className="subtle">{subject ? <>Challenge for <strong>{subject.title}</strong> ({subject.decision.action.replaceAll('_', ' ').toLowerCase()}).</> : 'Select a verify or review decision in the queue to issue a challenge.'}</p>
      <ol className="hardware-steps">{STEPS.map(([id, title, detail]) => <li key={id} className={steps[id]}><span aria-hidden="true"/><div><strong>{title}</strong><small>{detail}</small></div><em>{steps[id] === 'idle' ? '' : steps[id] === 'done' ? 'Done' : 'Stopped'}</em></li>)}</ol>
      <button className="primary" disabled={!subject || busy || !supported} onClick={() => send('valid')}><ArrowRight size={15}/>Send signed challenge</button>
      <button className={`hold-control ${phase === 'holding' ? 'active' : ''}`} disabled={phase !== 'awaiting_hold' && phase !== 'holding'} onPointerDown={event => { try { event.currentTarget.setPointerCapture(event.pointerId); } catch { /* released pointer */ } setButton(true); }} onPointerUp={() => setButton(false)} onPointerCancel={() => setButton(false)} onKeyDown={event => { if ((event.code === 'Space' || event.code === 'Enter') && !event.repeat) { event.preventDefault(); setButton(true); } }} onKeyUp={event => { if (event.code === 'Space' || event.code === 'Enter') setButton(false); }} onBlur={() => setButton(false)}><span style={{ transform: `scaleX(${progress})` }} aria-hidden="true"/>{holdLabel}</button>
      <div className="hardware-attacks"><h4><ShieldAlert size={15}/>Try to break it</h4>
        <button disabled={!subject || busy} onClick={() => send('tampered')}>Tamper with the amount</button>
        <button disabled={!subject || busy} onClick={() => send('forged_server')}>Forged server signature</button>
        <button disabled={!subject || busy} onClick={() => send('wrong_device')}>Challenge for another key</button>
        <button onClick={forgeAcknowledgement}>Remote malware forges approval</button>
        <button onClick={replay}>Replay a used approval</button>
        <button onClick={expire}>Let the challenge expire</button>
        <label className="pin-toggle"><input type="checkbox" checked={pinned} onChange={event => setPinned(event.target.checked)}/>Pin server key at provisioning</label>
      </div>
    </div>
    <div className="hardware-bottom">
      <section><h3><Network size={16}/>How it integrates</h3>
        <div className="flow" aria-label="Integration path"><div><strong>EarlyTrace API</strong><small>Decision, signed challenge, receipt</small></div><ArrowRight size={16}/><div><strong>Analyst bridge</strong><small>integrations/hardware/bridge.py · USB serial or BLE</small></div><ArrowRight size={16}/><div><strong>EarlyTrace Key</strong><small>ESP32-C3 · 128×64 OLED · button</small></div><ArrowRight size={16}/><div><strong>Signed acknowledgement</strong><small>Back to the API, recorded only</small></div></div>
        <p className="subtle">Same wire format as the real device: the simulator signs and verifies with Ed25519 exactly as the firmware and backend do. A customer-facing version would relay the challenge through a bank app SDK; that path is not built or claimed.</p>
      </section>
      <section><h3><ShieldCheck size={16}/>What this proves, and what it does not</h3>
        <ul className="hardware-limits"><li>Remote software cannot create the key's signature or edit its screen.</li><li>A coerced person can still press the button; the receipt says so.</li><li>It records a review acknowledgement. It never authorizes, releases or blocks a payment.</li><li>The device key is a prototype software key, not a certified secure element.</li><li>Firmware compiles for ESP32-C3 (587,712 bytes). It has not been flashed or tested on a board.</li></ul>
      </section>
      <section><h3><Smartphone size={16}/>Event log</h3>
        <ul className="hardware-log" aria-live="polite">{log.length ? log.map(entry => <li key={entry.id} className={entry.bad ? 'bad' : ''}>{entry.text}</li>) : <li>Send a challenge to begin.</li>}</ul>
        {packet && <details><summary>Wire packet</summary><code>message_b64: {packet.message_b64.slice(0, 96)}…</code><code>server_signature_b64: {packet.server_signature_b64}</code></details>}
      </section>
    </div>
  </section>;
}
