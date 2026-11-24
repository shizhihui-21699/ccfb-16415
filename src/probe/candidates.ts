/**
 * Candidate assembly: merges runtime-captured listeners with static scan hits,
 * attaches semantics and schemas, and records source-map-resolved positions.
 */
import type { PageModel, CapturedListener } from '../browser/page-model.js';
import { analyzeHandler, type HandlerSemantics } from '../analysis/origin-check.js';
import { inferStaticSchema, buildSchema, type MessageSchema } from '../analysis/message-schema.js';
import { scanUnit } from '../analysis/static-scan.js';
import type { SourceMapRegistry } from '../analysis/source-maps.js';
import type { CandidateTarget, ListenerSemantics } from './types.js';

export interface AssembleOptions {
  maps?: SourceMapRegistry;
  /** Trusted origins to fold into schema defaults (helps protocol reconstruction). */
  trustedOrigins?: string[];
  debug?: (...a: any[]) => void;
}

/** Build a resolver that finds a helper function's source by name in any script. */
function makeHelperResolver(model: PageModel): (name: string) => string | null {
  const cache = new Map<string, string | null>();
  return (name: string) => {
    if (cache.has(name)) return cache.get(name)!;
    let found: string | null = null;
    for (const script of model.scripts) {
      const re = new RegExp(
        '(?:function\\s+' + escapeRe(name) + '\\s*\\(|(?:var|let|const)\\s+' + escapeRe(name) + '\\s*=\\s*(?:async\\s*)?(?:function\\b|\\())'
      );
      const m = re.exec(script.code);
      if (!m) continue;
      const start = m.index;
      const snippet = script.code.slice(start, start + 4000);
      // take a plausible balanced function slice
      const fnSrc = sliceFunctionText(snippet);
      if (fnSrc) {
        found = fnSrc;
        break;
      }
    }
    cache.set(name, found);
    return found;
  };
}

function sliceFunctionText(snippet: string): string | null {
  // Find first '{' and match braces to its close.
  const open = snippet.indexOf('{');
  if (open === -1) return null;
  let depth = 0;
  let inStr: string | null = null;
  let esc = false;
  for (let i = open; i < snippet.length; i++) {
    const ch = snippet[i]!;
    if (inStr) {
      if (esc) esc = false;
      else if (ch === '\\') esc = true;
      else if (ch === inStr) inStr = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      inStr = ch;
      continue;
    }
    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) {
        // include the prefix before the brace (`function name(...)`)
        return snippet.slice(0, i + 1);
      }
    }
  }
  return null;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Derive the handler's name from its captured stack, if any. */
function handlerNameOf(l: CapturedListener): string {
  for (const f of l.stack) {
    if (f.fn && !/^(anonymous|\(anonymous\)|Object\.|Array\.)/.test(f.fn) && !f.url.includes('wma-inject')) {
      return f.fn.replace(/^Object\./, '');
    }
  }
  // try the source text
  const m = /function\s+([A-Za-z_$][\w$]*)/.exec(l.source);
  if (m) return m[1]!;
  const assigned = /^(?:var|let|const)?\s*([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function|\(|\w+\s*=>)/.exec(l.source);
  if (assigned) return assigned[1]!;
  return '(anonymous)';
}

function locationOf(l: CapturedListener): { url: string; line: number | null; column: number | null } {
  for (const f of l.stack) {
    if (!f.url || f.url.includes('wma-inject')) continue;
    if (/UtilityScript|pptr/.test(f.url)) continue;
    return { url: f.url, line: f.line, column: f.col };
  }
  return { url: l.frameUrl, line: null, column: null };
}

export function semanticsToSummary(sem: HandlerSemantics): ListenerSemantics {
  return {
    guardVerdict: sem.guard?.verdict || 'none',
    allowedOrigins: sem.guard?.allowedOrigins || [],
    weaknesses: sem.guard?.weaknesses || [],
    evidence: sem.guard?.evidence || '',
    readsOrigin: sem.readsOrigin,
    readsSource: sem.readsSource,
    readsData: sem.readsData,
    sinks: Array.from(new Set(sem.staticSinks.map((s) => s.kind))),
    postCheck: sem.postCheck,
    wildcardOutbound: sem.wildcardOutbound,
    dataFields: sem.dataFields,
    hasStaticSink: sem.staticSinks.length > 0,
  };
}

/**
 * Collect script-level string constants (`var WIDGET_ORIGIN = 'https://…'`).
 * Handlers are usually nested inside an IIFE that holds the allow-list, so the
 * handler source alone cannot resolve the identifier; the enclosing script can.
 */
function collectScriptArrays(code: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  // var ALLOWED = ['a','b']  /  new Set(['a','b'])  /  new Set('a','b'.split(','))
  const re = /\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:new\s+(?:Set|Array)\s*\(\s*)?(\[[^\]]{0,800}\]|(['"`])[^'"`]{0,400}\3\s*\.split\s*\([^)]*\))/g;
  let m: RegExpExecArray | null;
  let n = 0;
  while ((m = re.exec(code)) && n < 200) {
    const name = m[1]!;
    const expr = m[2]!;
    const vals: string[] = [];
    const litRe = /(['"`])((?:\\.|(?!\1).)*)\1/g;
    let lm: RegExpExecArray | null;
    while ((lm = litRe.exec(expr))) vals.push(lm[2]!);
    if (vals.length && vals.every((v) => v.length <= 300)) {
      out[name] = vals;
      n++;
    }
  }
  return out;
}

function collectScriptRegexes(code: string): Record<string, { pattern: string; flags: string }> {
  const out: Record<string, { pattern: string; flags: string }> = {};
  const re = /\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*\/((?:\\.|\[(?:\\.|[^\]])*\]|[^\/\n])+)\/([a-z]*)/g;
  let m: RegExpExecArray | null;
  let n = 0;
  while ((m = re.exec(code)) && n < 200) {
    out[m[1]!] = { pattern: m[2]!, flags: m[3] || '' };
    n++;
  }
  return out;
}

function collectScriptConsts(code: string): Record<string, string> {
  const out: Record<string, string> = {};
  const re = /\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(['"`])((?:\\.|(?!\2).)*)\2/g;
  let m: RegExpExecArray | null;
  let n = 0;
  while ((m = re.exec(code)) && n < 400) {
    const val = m[3]!;
    // Backreferences in the tempered pattern can include escape sequences; only
    // keep values that look like plain strings/origins.
    if (val.length <= 300 && !/\\[^u]/.test(val)) {
      out[m[1]!] = val;
      n++;
    }
  }
  return out;
}

function harvestDataValues(model: PageModel): Record<string, string[]> {
  const out: Record<string, Set<string>> = {};
  const add = (k: string, v: string) => {
    (out[k] || (out[k] = new Set())).add(v);
  };
  for (const script of model.scripts) {
    const code = script.code;
    // x.cmd === 'value' / x.action === 'value' / cmd !== 'value'
    const cmp = /\b([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\s*(?:===|==|!==|!=)\s*(['"`])((?:\\.|(?!\3).)*)\3/g;
    let m: RegExpExecArray | null;
    while ((m = cmp.exec(code))) if (m[4]!.length <= 80) add(m[2]!, m[4]!);
    // switch (x.cmd) { case 'value': }
    const sw = /switch\s*\(\s*[\w$.]+\.([A-Za-z_$][\w$]*)\s*\)\s*\{([\s\S]{0,1200}?)\}/g;
    while ((m = sw.exec(code))) {
      const field = m[1]!;
      const body = m[2]!;
      const caseRe = /case\s*(['"`])((?:\\.|(?!\1).)*)\1/g;
      let cm: RegExpExecArray | null;
      while ((cm = caseRe.exec(body))) if (cm[2]!.length <= 80) add(field, cm[2]!);
    }
    // bare parameter comparisons: `function (cmd) { if (cmd === 'setHtml') }`
    const bare = /\b([A-Za-z_$][\w$]*)\s*(?:===|==|!==|!=)\s*(['"`])((?:\\.|(?!\2).)*)\2/g;
    while ((m = bare.exec(code))) {
      const name = m[1]!;
      // exclude obvious non-message identifiers
      if (/^(this|window|document|typeof|undefined|null|true|false|self|location)$/.test(name)) continue;
      // Map a bare param to the field name it most likely corresponds to. The
      // caller often forwards `d.cmd` into this parameter; key on the param name
      // AND on common message field names it shadows.
      if (m[3]!.length <= 80) {
        add(name, m[3]!);
        // Also attribute to common discriminator fields so the message schema for
        // the *receiving* handler picks the value up.
        for (const hint of ['cmd', 'action', 'type', 'command', 'event', 'kind', 'method']) {
          if (hint.toLowerCase() === name.toLowerCase()) add(hint, m[3]!);
        }
      }
    }

    // callback invocations that pass a message field: onCommand(d.cmd, ...)
    const call = /\.(\w+)\s*\(\s*([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\s*[,)]/g;
    while ((m = call.exec(code))) {
      // remember that the field is dispatched; values come from other sites
    }
  }
  const res: Record<string, string[]> = {};
  for (const [k, set] of Object.entries(out)) res[k] = Array.from(set);
  return res;
}

export function assembleCandidates(model: PageModel, opts: AssembleOptions = {}): CandidateTarget[] {
  const resolveHelper = makeHelperResolver(model);
  const harvested = harvestDataValues(model);
  const out: CandidateTarget[] = [];
  const seen = new Set<string>();

  // Index static listeners by (unitUrl, start-line proximity) for cross-linking.
  const staticByUnit = new Map<string, ReturnType<typeof scanUnit>['listeners']>();
  for (const scan of model.staticScan) staticByUnit.set(scan.unitUrl, scan.listeners);

  // Protocol samples: messages the page sends during its own bootstrapping
  // reveal the real message shape.
  const protocolSamples: any[] = [];
  for (const s of model.scripts) {
    // cheap scan for postMessage(<object literal>, '*')
    const re = /postMessage\s*\(\s*(\{[\s\S]{0,600}?\})\s*,\s*(['"])([^'"]*)\2/g;
    let m: RegExpExecArray | null;
    let count = 0;
    while ((m = re.exec(s.code)) && count < 12) {
      const literal = m[1]!;
      const parsed = tryParseObjectLiteral(literal);
      if (parsed) {
        protocolSamples.push(parsed);
        count++;
      }
    }
  }

  for (const l of model.listeners) {
    if (l.removed) continue;
    const key = l.frameId + ':' + (l.stack[0]?.fn || '') + ':' + l.stack[0]?.url + ':' + l.stack[0]?.line;
    if (seen.has(key)) continue;
    seen.add(key);

    // Locate the script that contains this handler, for script-level constants.
    const ownerScript = model.scripts.find(
      (sc) => l.source && sc.code.includes(l.source.slice(0, Math.min(80, l.source.length)))
    );
    const consts = ownerScript ? collectScriptConsts(ownerScript.code) : {};
    const constArrays = ownerScript ? collectScriptArrays(ownerScript.code) : {};
    const constRegexes = ownerScript ? collectScriptRegexes(ownerScript.code) : {};
    const sem = analyzeHandler(l.source, { resolveHelper, maxDepth: 3, consts, constArrays, constRegexes });
    const staticSchema = inferStaticSchema(l.source);
    const schema: MessageSchema = staticSchema;
    // Values the rest of the page compares these fields against may not appear in
    // this handler (an SDK dispatcher forwards to a host callback that switches
    // on the value). Fold them in as disciminator candidates.
    for (const f of schema.fields) {
      const vals = harvested[f.path];
      if (!vals || !vals.length) continue;
      let d = schema.discriminators.find((x) => x.path === f.path);
      if (!d) {
        d = { path: f.path, values: [] };
        schema.discriminators.push(d);
      }
      for (const v of vals) if (!d.values.includes(v)) d.values.push(v);
    }
    if (protocolSamples.length) {
      schema.protocolSamples = protocolSamples.slice(0, 8);
    }

    // Attach the corresponding static listener id when we can find it by url.
    const loc = locationOf(l);
    let staticId: string | undefined;
    for (const [unitUrl, list] of staticByUnit) {
      const candidate = list.find(
        (s) => s.unitUrl === loc.url && loc.line != null && Math.abs(s.line - loc.line) <= 2
      );
      if (candidate) {
        staticId = candidate.id;
        break;
      }
    }

    // A static listener whose source contains the runtime source (or vice versa)
    // links even when positions differ due to bundling.
    if (!staticId && l.source.length > 40) {
      outer: for (const list of staticByUnit.values()) {
        for (const s of list) {
          if (s.handlerSource && s.handlerSource.length > 60 && l.source.length > 60) {
            const a = normalizeWs(l.source).slice(0, 120);
            const b = normalizeWs(s.handlerSource).slice(0, 120);
            if (a && b && (a.includes(b.slice(0, 80)) || b.includes(a.slice(0, 80)))) {
              staticId = s.id;
              break outer;
            }
          }
        }
      }
    }

    let original: CandidateTarget['original'];
    const orig = opts.maps?.resolve(loc.url, loc.line, loc.column) || null;
    if (orig) original = { url: orig.url, line: orig.line, column: orig.column, name: orig.name };

    const target: CandidateTarget = {
      id: `t${out.length + 1}`,
      frameId: l.frameId,
      lid: l.lid,
      frameUrl: l.frameUrl,
      frameOrigin: l.frameOrigin,
      isTop: l.isTop,
      registration: l.origin,
      target: l.target,
      handlerName: handlerNameOf(l),
      location: loc,
      source: l.source,
      staticId,
      original,
      schema,
      semantics: semanticsToSummary(sem),
      predicate: sem.guard || null,
    };
    out.push(target);
  }

  return out;
}

function normalizeWs(s: string): string {
  return s.replace(/\s+/g, ' ').trim();
}

function tryParseObjectLiteral(literal: string): any | null {
  try {
    const fn = new Function('return (' + literal + ');');
    const v = fn();
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      // Only keep serialisable samples.
      return JSON.parse(JSON.stringify(v));
    }
  } catch {
    /* literal may reference variables */
  }
  return null;
}
