export const DEFAULT_POSITIONS = Object.freeze({ agent: [145, 300], proxy: [420, 300], weather: [735, 205], tickets: [735, 410], vault: [420, 95], ledger: [735, 510] });
export const NODE_DETAILS = Object.freeze({
  agent: { type: 'agent', typeLabel: 'SOURCE', title: 'Agent context', what: 'This is the AI request. It carries an opaque capability reference, not a provider password or API key.', security: 'The model can request an action, but it cannot read the vault or widen its own permissions.' },
  proxy: { type: 'proxy', typeLabel: 'BOUNDARY', title: 'CanaryNorth policy proxy', what: 'This is the checkpoint. It checks identity, expiry, action, resource, and content before anything could be forwarded.', security: 'Default deny: a request needs every check to pass. Failed input is quarantined here.' },
  weather: { type: 'tool', typeLabel: 'TOOL', title: 'weather.get_forecast', what: 'A synthetic weather tool that could receive an approved forecast request. It never sees a blocked request.', security: 'Allowlisted only for weather://nyc through the forecast capability.' },
  tickets: { type: 'tool', typeLabel: 'TOOL', title: 'tickets.update', what: 'A separate synthetic tool with a different capability. It demonstrates that one permission does not unlock every tool.', security: 'Scoped to one demo ticket and write:ticket; the weather capability cannot reach it.' },
  vault: { type: 'vault', typeLabel: 'CREDENTIAL BOUNDARY', title: 'Server-side credential boundary', what: 'A production adapter can resolve a provider credential after policy passes. The demo uses no provider credential.', security: 'Credential material stays outside model context and decision receipts.' },
  ledger: { type: 'ledger', typeLabel: 'EVIDENCE', title: 'Signed receipt ledger', what: 'Each decision leaves a small receipt with a hash and a link to the previous receipt.', security: 'A tamper-evident chain makes silent edits detectable. This demo ledger is in memory and resets on restart.' }
});
export const EDGE_DETAILS = Object.freeze({
  'agent->proxy': { title: 'Capability handoff', explanation: 'The agent presents an opaque capability reference. No provider credential crosses this boundary.' },
  'proxy->weather': { title: 'Would-forward path', explanation: 'Only an approved forecast request could be forwarded to the synthetic weather tool.' },
  'proxy->tickets': { title: 'Separate scope', explanation: 'A weather capability does not grant access to the separate ticket update tool.' },
  'vault->proxy': { title: 'Server-side resolution', explanation: 'A production adapter can resolve credential material after policy passes without returning it to the agent.' },
  'proxy->ledger': { title: 'Receipt chain', explanation: 'The policy decision is recorded with a hash and a link to the previous receipt.' }
});
export const SCENARIOS = Object.freeze({
  safe: Object.freeze({
    label: 'Safe request',
    tone: 'allow',
    summary: 'A scoped synthetic request reaches the boundary and would-forward to the allowlisted tool.',
    steps: Object.freeze([
      Object.freeze({ label: 'Request arrives', detail: 'Agent presents an opaque capability reference.', path: ['agent', 'proxy'] }),
      Object.freeze({ label: 'Policy passes', detail: 'Scope and content checks pass for the synthetic forecast request.', path: ['proxy', 'weather'] }),
      Object.freeze({ label: 'Receipt chained', detail: 'The decision is recorded before anything could run.', path: ['proxy', 'ledger'] })
    ])
  }),
  injection: Object.freeze({
    label: 'Prompt injection',
    tone: 'deny',
    summary: 'Bounded input screening holds the request at the policy boundary.',
    steps: Object.freeze([
      Object.freeze({ label: 'Request arrives', detail: 'The agent presents a capability and untrusted input to the boundary.', path: ['agent', 'proxy'] }),
      Object.freeze({ label: 'Input quarantined', detail: 'Prompt-injection content stops at CanaryNorth. No tool receives it.', path: ['proxy'] }),
      Object.freeze({ label: 'Denial recorded', detail: 'A receipt preserves the reason without exposing the raw prompt.', path: ['proxy', 'ledger'] })
    ])
  }),
  dlp: Object.freeze({
    label: 'Sensitive input',
    tone: 'deny',
    summary: 'Credential-shaped input is quarantined before it can reach a tool.',
    steps: Object.freeze([
      Object.freeze({ label: 'Request arrives', detail: 'The agent presents a capability and content for inspection.', path: ['agent', 'proxy'] }),
      Object.freeze({ label: 'Sensitive input stopped', detail: 'The DLP check quarantines credential-shaped content at the boundary.', path: ['proxy'] }),
      Object.freeze({ label: 'Denial recorded', detail: 'A receipt preserves the stop reason without storing the sensitive value.', path: ['proxy', 'ledger'] })
    ])
  })
});
export function clampPosition([x, y]) { return [Math.max(52, Math.min(948, Number(x))), Math.max(52, Math.min(508, Number(y)))]; }
export function demoPath(step, allowed = true) {
  const allowedSteps = [['agent', 'proxy'], ['proxy', 'weather'], ['proxy', 'ledger']];
  const deniedSteps = [['agent', 'proxy'], ['proxy'], ['proxy', 'ledger']];
  return (allowed ? allowedSteps : deniedSteps)[step] || [];
}
export function scenarioPath(scenario = 'safe', step = -1) { return SCENARIOS[scenario]?.steps[step]?.path || []; }
