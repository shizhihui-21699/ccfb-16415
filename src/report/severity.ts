/**
 * Turning a probe result into a graded finding.
 *
 * The severity ladder mirrors how the bug actually behaves in a browser:
 *
 *   critical  attacker-origin message caused script execution or navigation to
 *             an attacker-controlled URL in the target's origin
 *   high      attacker-origin message reached a dangerous sink with
 *             attacker-controlled content but did not execute (e.g. inert HTML),
 *             or the handler is unguarded and every probe was invoked
 *   medium    a validation exists but is bypassable, and the handler demonstrably
 *             acts on attacker messages
 *   low       a validation weakness with no demonstrated action, or a
 *             data/source-based check on an otherwise inert handler
 *   info      informational: correct allow-list, relay-only handler
 */
import type { ListenerProbeResult, EffectRecord } from '../probe/types.js';
import type { Finding, Severity, FindingVerdict, summarizedEffect } from './types.js';
import type { PageModel } from '../browser/page-model.js';

const DANGEROUS_SINKS = new Set([
  'eval',
  'Function',
  'timer-string',
  'html:innerHTML',
  'html:outerHTML',
  'html:insertAdjacentHTML',
  'html:document.write',
  'html:document.writeln',
  'attr:srcdoc',
  'attr:setAttribute',
  'attr:src',
  'attr:href',
  'location',
  'location.href',
  'location.assign',
  'location.replace',
  'window.open',
]);

const SCRIPT_EXEC_SINKS = new Set(['eval', 'Function', 'timer-string']);

export function recordToFinding(result: ListenerProbeResult, model: PageModel): Finding {
  const t = result.target;
  const sem = t.semantics;
  const executed = result.evidence.effects.some((e) => e.kind === 'canary' && e.attackerControlled);
  const navPayload = result.evidence.effects.some(
    (e) => e.kind === 'navigation' && e.attackerControlled
  );
  const sinkEffects = result.evidence.effects.filter((e) => e.kind === 'sink');
  const scriptSink = sinkEffects.some((e) => {
    const kind = String((e.detail && e.detail.kind) || '');
    return SCRIPT_EXEC_SINKS.has(kind) || /^attr:(on|src|srcdoc)/.test(kind);
  });
  const dangerousSinkHit = sinkEffects.some((e) => DANGEROUS_SINKS.has(String(e.detail?.kind || '')));
  const outboundEffects = result.evidence.effects.filter((e) => e.kind === 'outbound' && e.attackerControlled);
  // A request that leaves the page (fetch/beacon/websocket) with the payload is
  // data exfiltration; a localStorage write is persistence/data poisoning. They
  // are not equivalent, so they grade differently.
  const exfilLeak = outboundEffects.some((e) => {
    const ch = String(e.detail?.channel || '');
    return ch === 'fetch' || ch === 'sendBeacon' || ch === 'WebSocket.send' || ch === 'xhr.send' || ch === 'window.postMessage';
  });
  const storagePoison = outboundEffects.some((e) => /localStorage|sessionStorage/.test(String(e.detail?.channel || '')));
  const dangerousSinkWithData = sinkEffects.some(
    (e) => DANGEROUS_SINKS.has(String(e.detail?.kind || '')) && e.attackerControlled
  );
  const invokedByAttacker = result.attempts.some((a) => a.invoked.length > 0);

  const verdict: FindingVerdict = (() => {
    if (result.outcome === 'exploited') return 'exploited';
    // A navigation to an attacker-controlled URL, a script-capable sink hit, or
    // an outbound request carrying the payload is an exploit even without a
    // canary: the canary only proves *script* execution, not that the action
    // happened at all.
    if (
      result.outcome === 'acted' &&
      (navPayload || dangerousSinkWithData || exfilLeak)
    ) {
      return 'exploited';
    }
    if (result.outcome === 'acted' && storagePoison) return 'weak-validation';
    if (sem.guardVerdict === 'strong' || sem.guardVerdict === 'same-origin') {
      return sem.hasStaticSink && (invokedByAttacker === false) ? 'not-a-finding' : 'information';
    }
    if (invokedByAttacker && sem.guardVerdict === 'none') return 'vulnerable-unconfirmed';
    if (invokedByAttacker) return 'weak-validation';
    if (['none', 'weak', 'deny-list', 'data-based', 'source-based', 'post-check'].includes(sem.guardVerdict) &&
        (sem.hasStaticSink || sem.wildcardOutbound)) return 'vulnerable-unconfirmed';
    return 'information';
  })();

  const severity: Severity = (() => {
    if (verdict === 'not-a-finding') return 'info';
    if (executed) return 'critical';
    if (navPayload) return 'high';
    if (verdict === 'exploited' && (scriptSink || exfilLeak)) return 'critical';
    if (verdict === 'exploited') return dangerousSinkHit ? 'high' : 'medium';
    if (verdict === 'vulnerable-unconfirmed') {
      if (sem.guardVerdict === 'none' && (sem.sinks.includes('eval') || sem.sinks.some((s) => s.startsWith('html:')))) return 'high';
      if (sem.guardVerdict === 'none') return 'medium';
      return 'low';
    }
    if (verdict === 'weak-validation') {
      return dangerousSinkHit ? 'medium' : 'low';
    }
    return 'info';
  })();

  const confidence: Finding['confidence'] = executed
    ? 'high'
    : verdict === 'exploited'
      ? 'high'
      : verdict === 'vulnerable-unconfirmed'
        ? invokedByAttacker
          ? 'medium'
          : 'low'
        : verdict === 'weak-validation'
          ? 'medium'
          : 'high';

  const title = buildTitle(t, verdict, severity, executed, sem.guardVerdict);
  const summary = buildSummary(result, executed, verdict);

  // The origin that actually produced the decisive effect is the one worth
  // reporting; a finding proved from a synthesised bypass origin must not be
  // labelled with the generic baseline origin.
  const decisive = result.attempts.find((a) => a.effects.some((e) => e.attackerControlled)) ||
    result.attempts.find((a) => a.invoked.length) || result.attempts.find((a) => a.delivered);
  const effectiveOrigin = decisive?.senderOrigin || '';

  const attempts = result.attempts
    .filter((a) => a.delivered)
    .slice(0, 6)
    .map((a) => ({
      message: a.message,
      delivered: a.delivered,
      invoked: a.invoked.length,
      senderOrigin: a.senderOrigin,
      effects: a.effects.slice(0, 6).map(summarizeEffect),
    }));

  return {
    id: 'WMA-' + t.id.replace(/^t/, '') + '-' + t.lid,
    targetId: t.id,
    title,
    severity,
    verdict,
    outcome: result.outcome,
    summary,
    delivery: {
      channel: (decisive?.channel || result.attempts.find((a) => a.delivered)?.channel || 'none') as 'iframe' | 'popup' | 'none',
      attackerOrigin: effectiveOrigin,
      messagesSent: result.attempts.length,
      invoked: invokedByAttacker,
    },
    handler: {
      name: t.handlerName,
      registration: t.registration,
      target: t.target,
      frameUrl: t.frameUrl,
      isTop: t.isTop,
      location: t.location,
      original: t.original,
      sourceSnippet: clip(t.source, 3000),
      sourceLines: extractSourceWindow(t.source),
    },
    validation: {
      verdict: sem.guardVerdict,
      evidence: sem.evidence,
      allowedOrigins: sem.allowedOrigins,
      weaknesses: sem.weaknesses,
      readsOrigin: sem.readsOrigin,
      readsSource: sem.readsSource,
      readsData: sem.readsData,
    },
    impact: {
      sinks: sem.sinks,
      observedEffects: result.evidence.effects.slice(0, 20),
      canaryExecuted: executed,
      attackerControlled: result.evidence.effects.some((e) => e.attackerControlled),
      narrative: buildNarrative(result, executed, navPayload, dangerousSinkHit),
    },
    proof: {
      attempts,
      snippets: result.evidence.snippets.slice(0, 8),
      screenshot: result.evidence.screenshots?.[0],
      consoleLines: result.evidence.consoleLines?.slice(-12),
      network: result.evidence.network?.slice(0, 8),
    },
    remediation: buildRemediation(sem.guardVerdict, sem.allowedOrigins, sem.sinks),
    notes: result.notes,
    confidence,
  };
}

function buildTitle(
  t: ListenerProbeResult['target'],
  verdict: FindingVerdict,
  severity: Severity,
  executed: boolean,
  guard: string
): string {
  const named = !!(t.handlerName && t.handlerName !== '(anonymous)' && t.handlerName !== 'message handler');
  const name = named ? t.handlerName : 'a message handler';
  if (executed) return `Cross-origin script execution via ${name} (${t.frameUrl})`;
  if (verdict === 'exploited') return `Attacker-origin message reaches a dangerous sink in ${name}`;
  if (guard === 'none') return `${named ? 'Message handler ' + name : 'A message handler'} accepts any origin`;
  if (guard === 'weak') return `Bypassable origin check in ${name}`;
  if (guard === 'data-based') return `${named ? 'Message handler ' + name : 'A message handler'} authenticates data instead of origin`;
  if (guard === 'source-based') return `${named ? 'Message handler ' + name : 'A message handler'} trusts window identity instead of origin`;
  if (guard === 'deny-list') return `Deny-list origin check in ${name} allows unknown origins`;
  if (guard === 'post-check') return `Origin checked after the action in ${name}`;
  if (verdict === 'weak-validation') return `Weak validation observed in ${name}`;
  return `${name} — ${guard} validation`;
}

function buildSummary(result: ListenerProbeResult, executed: boolean, verdict: FindingVerdict): string {
  const t = result.target;
  const sem = t.semantics;
  const parts: string[] = [];
  const loc = t.original ? `${t.original.url}:${t.original.line}` : `${t.location.url}:${t.location.line ?? '?'}`;
  parts.push(
    `A 'message' listener (${t.registration} on ${t.target}) is registered at ${loc}.`
  );
  switch (sem.guardVerdict) {
    case 'none':
      parts.push('The handler does not gate its behaviour on event.origin, so any page that can frame or open it can drive it.');
      break;
    case 'weak':
      parts.push(`The origin check is bypassable: ${sem.weaknesses[0] || 'substring/prefix comparison'}.`);
      break;
    case 'deny-list':
      parts.push('The handler only rejects one known-bad origin and accepts every other origin.');
      break;
    case 'data-based':
      parts.push('The handler validates a field inside the message data, which the sender controls.');
      break;
    case 'source-based':
      parts.push('The handler compares event.source, which only checks window identity, not origin: an attacker-framed copy passes.');
      break;
    case 'post-check':
      parts.push('The origin is checked only after the sensitive action has already run.');
      break;
    case 'unknown':
      parts.push('Origin validation is delegated in a way that could not be verified statically.');
      break;
    case 'strong':
    case 'same-origin':
      parts.push('The handler enforces an exact origin check; it is listed for completeness, not as a vulnerability.');
      break;
  }
  if (sem.sinks.length) parts.push(`Static sinks present: ${sem.sinks.join(', ')}.`);
  if (executed) parts.push('A message from the attacker origin executed injected script in the page.');
  else if (verdict === 'exploited') parts.push('A message from the attacker origin produced an attacker-controlled effect.');
  else if (verdict === 'vulnerable-unconfirmed') {
    parts.push(
      result.attempts.some((a) => a.invoked.length)
        ? 'The handler ran for attacker-origin messages; no single payload produced a conclusive effect.'
        : 'No candidate message reached the handler in this run; treat the missing check as a defect to confirm manually.'
    );
  }
  return parts.join(' ');
}

function buildNarrative(
  result: ListenerProbeResult,
  executed: boolean,
  navPayload: boolean,
  dangerousSink: boolean
): string {
  if (executed) {
    return 'Attacker hosts a page that frames or opens the target and posts a crafted message. The browser sets event.origin to the attacker origin; the handler processes it anyway and writes attacker markup into a script-capable sink, so an injected handler runs in the target page — from there it can read authenticated state and perform actions as the victim.';
  }
  if (navPayload) {
    return 'An attacker-origin message drives a navigation to a URL taken from the message, enabling phishing or token exfiltration through the trusted origin.';
  }
  if (result.outcome === 'acted' || dangerousSink) {
    return 'An attacker-origin message reaches a risky operation (DOM write, script load, or outbound request) with attacker-supplied content. Even where immediate execution was not observed, the same path is exploitable with a payload suited to the specific sink.';
  }
  if (result.target.semantics.guardVerdict === 'none') {
    return 'Any site that can embed or open the target can send messages the handler will process. Whether that is exploitable depends on what the handler does; it acts on the message without knowing the sender.';
  }
  return 'The message-handling path does not establish the sender reliably.';
}

function summarizeEffect(e: EffectRecord): summarizedEffect {
  const d = e.detail || {};
  let detail = '';
  if (e.kind === 'sink') {
    const inner = d.detail || {};
    detail = `${d.kind || 'sink'}: ${String(inner.html || inner.code || inner.url || inner.value || '').slice(0, 160)}`;
  } else if (e.kind === 'canary') {
    detail = `canary token executed: ${String(d.token).slice(0, 60)}`;
  } else if (e.kind === 'outbound') {
    detail = `${d.channel} ${String(d.url || d.targetOrigin || '').slice(0, 120)} ${String(d.body || '').slice(0, 80)}`;
  } else if (e.kind === 'navigation') {
    detail = `navigated ${String(d.from || '').slice(0, 60)} -> ${String(d.to || '').slice(0, 100)}`;
  } else if (e.kind === 'dom') {
    detail = `DOM changed (${JSON.stringify(d).slice(0, 100)})`;
  } else {
    detail = JSON.stringify(d).slice(0, 160);
  }
  return { kind: e.kind, attackerControlled: !!e.attackerControlled, detail };
}

function extractSourceWindow(source: string): { line: number; text: string }[] | undefined {
  if (!source) return undefined;
  const lines = source.split('\n');
  if (lines.length <= 60) return lines.map((text, i) => ({ line: i + 1, text }));
  return undefined;
}

function clip(s: string, n: number): string {
  if (!s) return '';
  return s.length <= n ? s : s.slice(0, n) + '\n…[' + (s.length - n) + ' chars]';
}

function buildRemediation(
  guard: string,
  allowed: string[],
  sinks: string[]
): Finding['remediation'] {
  const list = allowed.length ? allowed : ['https://your-trusted.example'];
  const code = [
    '// Exact, whole-origin comparison against a fixed allow-list.',
    `const ALLOWED = new Set(${JSON.stringify(list)});`,
    "window.addEventListener('message', (event) => {",
    '  if (!ALLOWED.has(event.origin)) return;   // never use startsWith/indexOf/regex',
    '  // ... handle event.data ...',
    '});',
  ].join('\n');

  const refs = [
    'https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns',
    'https://html.spec.whatwg.org/multipage/web-messaging.html#dom-window-postmessage',
  ];

  const bits: string[] = [];
  if (guard === 'none') bits.push('Add an exact origin allow-list before doing anything with the message.');
  if (guard === 'weak') bits.push('Replace the substring/prefix/regex test with an exact Set membership check on event.origin.');
  if (guard === 'deny-list') bits.push('Invert the check to an allow-list; a deny-list cannot enumerate every attacker origin.');
  if (guard === 'data-based') bits.push('Do not use fields inside event.data as an authenticity signal; check event.origin instead.');
  if (guard === 'source-based') bits.push('event.source is not an origin check; validate event.origin explicitly.');
  if (guard === 'post-check') bits.push('Move the origin check ahead of all effects.');
  if (sinks.some((s) => s.startsWith('html') || s === 'eval')) {
    bits.push('Render untrusted content with textContent / DOM APIs, never innerHTML/eval, even after validating the origin.');
  }
  if (allowed.length === 1) bits.push(`The only accepted origin should be ${allowed[0]}.`);
  return { summary: bits.join(' '), codeFix: code, references: refs };
}
