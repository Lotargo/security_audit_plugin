import { SandboxBridge } from './src/mcp/bridge.js';

const b = new SandboxBridge({ workspaceRoot: process.cwd(), hostPort: 19301 });
await b.ensureRuntime();
console.log('RUNTIME OK');
await b.setScope({ mode: 'local', arm_canaries: false });
await b.setEvolveEnabled(true);

const d1 = await b.exec('whoami');
console.log('whoami:', JSON.stringify(d1));
const d2 = await b.exec('curl -fsS --connect-timeout 1 --max-time 2 https://example.com >/dev/null');
console.log('curl example:', JSON.stringify(d2));

const status = await b.getEvolveStatus();
console.log('STATUS:', JSON.stringify(status, null, 1).slice(0, 1500));

const sessions: any = await b.getEvolveSessions();
const active = sessions.sessions.find(
  (s: any) => s.session_id !== 'runtime-default' && s.event_refs.length > 0
);
console.log('ACTIVE SESSION:', active?.session_id, 'events:', active?.event_refs.length);

const trace: any = await b.getEvolveTrace(active.session_id);
console.log('TRACE risk:', trace.risk_level, trace.risk_score, JSON.stringify(trace.tags));

try {
  const prep: any = await b.prepareDeception(active.session_id);
  console.log('PREPARE OK:', JSON.stringify(prep, null, 1).slice(0, 2000));
} catch (e: any) {
  console.log('PREPARE FAILED:', e.message);
}
