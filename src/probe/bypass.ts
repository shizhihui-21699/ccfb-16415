/**
 * Origin bypass synthesis.
 *
 * A weak check is only *proven* exploitable by a message that actually passes
 * it, which needs an attacker-controlled origin satisfying the check. This
 * module reads the check's expression and constructs such origins:
 *
 *   origin.startsWith('https://pay.example.com')
 *     → https://pay.example.com.attacker.tld   (prefix holds, origin differs)
 *   origin.indexOf('example.com') !== -1
 *     → https://attacker.tld/?example.com      (substring holds)
 *   /^https:\/\/example.com/.test(origin)     (unescaped dot, no $)
 *     → https://exampleXcom.attacker.tld
 *   list.includes(origin) with a non-origin entry
 *     → https://<that entry>.attacker.tld or a URL embedding it
 *
 * The harness then serves the attacker page on that origin, so delivery is a
 * genuine cross-origin postMessage whose event.origin really passes the check.
 * Origins are constrained to hostnames that resolve to the loopback mapping the
 * harness already relies on, so any .test / .invalid / .example host works.
 */
import type { OriginPredicate, GuardVerdict } from '../analysis/origin-check.js';

export interface BypassOrigin {
  origin: string;
  /** How it defeats the check, for the report. */
  technique: string;
  /** The expression it targets. */
  against: string;
  confidence: 'high' | 'medium' | 'low';
}

/** Registrable-ish suffix the harness can serve on. */
const ATTACKER_SUFFIX = 'wma-attacker.test';

/**
 * Synthesise attacker origins that satisfy a weak predicate.
 */
export function synthesizeBypassOrigins(predicate: OriginPredicate | null, verdict: GuardVerdict): BypassOrigin[] {
  if (!predicate) return [];
  const out: BypassOrigin[] = [];
  const push = (origin: string, technique: string, confidence: BypassOrigin['confidence'] = 'high') => {
    if (!isUsableOrigin(origin)) return;
    if (out.some((o) => o.origin === origin)) return;
    out.push({ origin, technique, against: predicate.evidence, confidence });
  };

  const ev = predicate.evidence || '';
  const ops = predicate.operands || [];
  const method = predicate.method || '';

  // Structured path first: the analyser already resolved constants like
  // `origin.indexOf(WIDGET_ORIGIN)` to their literal value.
  if (method === 'startsWith' && ops[0]) {
    const crafted = appendToPrefix(ops[0]);
    if (crafted) push(crafted, `origin.startsWith(${JSON.stringify(ops[0])}) is satisfied by ${crafted}, a different origin`);
    const alt = altFromPrefix(ops[0]);
    if (alt) push(alt, `a look-alike host under the same prefix: ${alt}`, 'medium');
  }
  if (method === 'endsWith' && ops[0]) {
    const suffix = ops[0];
    if (!suffix.startsWith('.')) {
      push(`https://attacker${suffix.replace(/^\//, '')}`, `origin.endsWith(${JSON.stringify(suffix)}) is satisfied by attacker${suffix}`);
    }
  }
  if ((method === 'indexOf' || method === 'includes' || method === 'lastIndexOf') && ops[0]) {
    const needle = ops[0];
    const hostish = needle.replace(/^https?:\/\//, '').replace(/[^a-zA-Z0-9.-]/g, '-').replace(/^-+|-+$/g, '');
    if (hostish) push(`https://${hostish}.${ATTACKER_SUFFIX}`, `origin.${method}(${JSON.stringify(needle)}) matches the host label of ${hostish}.${ATTACKER_SUFFIX}`);
    push(`https://${ATTACKER_SUFFIX}/?${encodeURIComponent(needle)}`, `origin.${method}(${JSON.stringify(needle)}) matches inside the query string`);
    push(`https://x${encodeURIComponent(needle)}.${ATTACKER_SUFFIX}`, `the needle is embedded in the hostname`);
  }

  // ---- startsWith('PREFIX') : PREFIX + attacker suffix passes a prefix test
  const sw = /\.startsWith\(\s*(['"`])([^'"`]+)\1\s*\)/.exec(ev);
  if (sw) {
    const prefix = sw[2]!;
    const crafted = appendToPrefix(prefix);
    if (crafted) push(crafted, `origin.startsWith(${JSON.stringify(prefix)}) is satisfied by ${crafted}, a different origin`);
    // also the "prefix + distinct port / sibling label" forms
    const alt = altFromPrefix(prefix);
    if (alt) push(alt, `a look-alike host under the same prefix: ${alt}`, 'medium');
  }

  // ---- endsWith('SUFFIX')
  const ew = /\.endsWith\(\s*(['"`])([^'"`]+)\1\s*\)/.exec(ev);
  if (ew) {
    const suffix = ew[2]!;
    if (suffix.startsWith('.')) {
      // ".example.com" — cannot be satisfied by an unrelated domain; a sibling
      // under a longer label cannot pass. Skip: genuinely not bypassable here.
    } else {
      // 'example.com' with no dot prefix: "attackerexample.com" passes.
      push(`https://attacker${suffix.replace(/^\//, '')}`, `origin.endsWith(${JSON.stringify(suffix)}) is satisfied by attacker${suffix}`);
    }
  }

  // ---- indexOf / includes / substring
  const idx = /\.(indexOf|includes|search|lastIndexOf)\(\s*(['"`])([^'"`]+)\2/.exec(ev);
  if (idx) {
    const needle = idx[3]!;
    // put the needle in the host label, then in the path, then the query
    const hostish = needle.replace(/^https?:\/\//, '').replace(/[^a-zA-Z0-9.-]/g, '-').replace(/^-+|-+$/g, '');
    if (hostish) push(`https://${hostish}.${ATTACKER_SUFFIX}`, `origin.${idx[1]}(${JSON.stringify(needle)}) matches the host label of ${hostish}.${ATTACKER_SUFFIX}`);
    push(`https://${ATTACKER_SUFFIX}/?${encodeURIComponent(needle)}`, `origin.${idx[1]}(${JSON.stringify(needle)}) matches inside the path/query`);
    push(`https://x${encodeURIComponent(needle)}.${ATTACKER_SUFFIX}`, `needle embedded in the hostname`);
  }

  // ---- regex tests (unanchored, unescaped dots, .*)
  // The analyser records the resolved pattern as an operand when it came from a
  // constant (e.g. `RE.test(e.origin)` with `var RE = /.../`).
  const regexPatterns: string[] = [];
  if (method === 'regex' && ops.length) regexPatterns.push(ops[0]!);
  if (/test\(|match\(|search\(|exec\(/.test(ev)) {
    const literalRegex = /\/((?:\\.|[^/\n])+)\/([a-z]*)/.exec(ev);
    if (literalRegex) regexPatterns.push(literalRegex[1]!);
  }
  for (const pattern of Array.from(new Set(regexPatterns))) {
    for (const o of originsForRegex(pattern)) push(o.origin, o.technique, o.confidence);
  }

  // ---- literal host strings compared loosely (no scheme)
  for (const lit of predicate.allowedOrigins) {
    const host = lit.replace(/^https?:\/\//, '');
    push(`https://${host}.${ATTACKER_SUFFIX}`, `the checked value ${lit} has no scheme terminator, so ${host}.${ATTACKER_SUFFIX} also matches`, 'medium');
  }

  // ---- deny-list: any origin that is not the blocked one
  if (verdict === 'deny-list') {
    push(`https://${ATTACKER_SUFFIX}`, 'a deny-list only excludes specific origins; any other origin is accepted');
  }

  // ---- data / source based: plain attacker origin is enough
  if (verdict === 'data-based' || verdict === 'source-based') {
    push(`https://${ATTACKER_SUFFIX}`, 'the check does not depend on the real origin, so any attacker origin is accepted');
  }

  // Cap and order by confidence.
  const rank = { high: 0, medium: 1, low: 2 } as const;
  out.sort((a, b) => rank[a.confidence] - rank[b.confidence]);
  return out.slice(0, 6);
}

function isUsableOrigin(origin: string): boolean {
  try {
    const u = new URL(origin);
    if (!/^https?:$/.test(u.protocol)) return false;
    // Only hostnames the harness can serve on (loopback-mapped wildcard).
    if (!/^[a-zA-Z0-9.-]+$/.test(u.hostname)) return false;
    if (u.hostname.length > 120) return false;
    return true;
  } catch {
    return false;
  }
}

/** Given a prefix like https://pay.example.com, produce a longer origin. */
function appendToPrefix(prefix: string): string | null {
  if (!/^https?:\/\//.test(prefix)) return null;
  const trailingSlash = prefix.endsWith('/');
  const base = prefix.replace(/\/+$/, '');
  if (trailingSlash) {
    // https://pay.example.com/ + attacker host path
    return `${base}.${ATTACKER_SUFFIX}/`;
  }
  // origin has no trailing slash; prefix must match a *string prefix* of it, so
  // extend the hostname: https://pay.example.com.attacker
  try {
    const u = new URL(base);
    if (u.port) return `${u.protocol}//${u.hostname}.${ATTACKER_SUFFIX}:${u.port}`;
    return `${u.protocol}//${u.hostname}.${ATTACKER_SUFFIX}`;
  } catch {
    return null;
  }
}

function altFromPrefix(prefix: string): string | null {
  try {
    const u = new URL(prefix.replace(/\/+$/, ''));
    const labels = u.hostname.split('.');
    if (labels.length < 2) return null;
    const sibling = ['evil', ...labels].join('.');
    return `${u.protocol}//${sibling}`;
  } catch {
    return null;
  }
}

/** Build origins that an anchored-or-not regex accepts but which are hostile. */
function originsForRegex(pattern: string): BypassOrigin[] {
  const out: BypassOrigin[] = [];
  const unescapedDot = /(?<!\\)\./.test(pattern.replace(/\\\./g, '\u0000'));
  const anchoredEnd = /\$$/.test(pattern) || /\\\$$/.test(pattern);

  // Extract the literal host the pattern is trying to match, if any.
  const hostMatch = /https?:\\?\/\\?\/\\?([a-zA-Z0-9.-]+)/.exec(pattern.replace(/\\\//g, '/'));
  const host = hostMatch ? hostMatch[1]!.replace(/\\\./g, '.') : null;

  if (host && unescapedDot) {
    // Replace a dot with a valid DNS character; X passes /example.com/.
    const dotted = host.replace(/(?<!\\)\./g, 'x');
    if (!anchoredEnd) {
      out.push({
        origin: `https://${dotted}.${ATTACKER_SUFFIX}`,
        technique: `unescaped dots in /${pattern}/ match any character, and the pattern is not end-anchored`,
        against: `/${pattern}/`,
        confidence: 'high',
      });
    }
    out.push({
      origin: `https://${dotted}`,
      technique: `the unescaped dot in /${pattern}/ matches a letter, so ${dotted} satisfies it`,
      against: `/${pattern}/`,
      confidence: 'high',
    });
  }
  if (host && !anchoredEnd) {
    out.push({
      origin: `https://${host}.${ATTACKER_SUFFIX}`,
      technique: `the pattern /${pattern}/ is not end-anchored, so a longer host starting with ${host} matches`,
      against: `/${pattern}/`,
      confidence: 'high',
    });
  }
  if (!/^\^/.test(pattern)) {
    out.push({
      origin: `https://${ATTACKER_SUFFIX}/?x=${host || 'x'}`,
      technique: `the pattern /${pattern}/ is not start-anchored, so the match can occur anywhere in the URL`,
      against: `/${pattern}/`,
      confidence: 'medium',
    });
  }
  return out;
}

/**
 * A default attacker origin plus any per-predicate bypass origin. Always returns
 * at least one usable origin.
 */
export function attackerOriginsFor(predicate: OriginPredicate | null, verdict: GuardVerdict): BypassOrigin[] {
  const synth = synthesizeBypassOrigins(predicate, verdict);
  if (synth.length) return synth;
  return [
    {
      origin: `https://${ATTACKER_SUFFIX}`,
      technique: 'baseline attacker origin (no bypass synthesis needed)',
      against: predicate?.evidence || '(none)',
      confidence: 'high',
    },
  ];
}

/** Map of origin -> why it is being used, for the report. */
export function describeBypass(bypass: BypassOrigin[]): string {
  return bypass.map((b) => `${b.origin} — ${b.technique}`).join('; ');
}
